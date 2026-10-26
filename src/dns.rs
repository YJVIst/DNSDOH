use crate::{
    model::{Credential, Snapshot, now},
    security,
    state::{ApiError, App},
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, OriginalUri, Path, RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA, SOA},
    },
};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

pub fn answer(
    snapshot: &Snapshot,
    credential: &Credential,
    bytes: &[u8],
) -> Result<(Vec<u8>, bool), ApiError> {
    if bytes.len() > 65535 || bytes.len() < 12 {
        return Err(ApiError::bad("Invalid DNS message"));
    }
    let query = Message::from_vec(bytes).map_err(|_| ApiError::bad("Invalid DNS message"))?;
    if query.metadata.message_type != MessageType::Query
        || query.queries.len() != 1
        || !query.answers.is_empty()
        || !query.authorities.is_empty()
    {
        return Err(ApiError::bad("Exactly one DNS question is required"));
    }
    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.queries = query.queries.clone();
    if let Some(edns) = &query.edns {
        let mut response_edns = Edns::new();
        response_edns.set_version(0).set_max_payload(1232);
        reply.edns = Some(response_edns);
        if edns.version() != 0 {
            reply.metadata.response_code = ResponseCode::BADVERS;
            return Ok((
                reply
                    .to_vec()
                    .map_err(|_| ApiError::bad("DNS encoding failed"))?,
                false,
            ));
        }
    }
    if query.metadata.op_code != OpCode::Query {
        reply.metadata.response_code = ResponseCode::NotImp;
        return Ok((
            reply
                .to_vec()
                .map_err(|_| ApiError::bad("DNS encoding failed"))?,
            false,
        ));
    }
    let q = &query.queries[0];
    let name = q.name().to_ascii().trim_end_matches('.').to_lowercase();
    let zone = snapshot
        .zones
        .iter()
        .find(|z| security::inside(&name, &z.name));
    let allowed = zone.is_some_and(|z| credential.zones.contains(&z.id));
    if !allowed
        || q.query_class() != DNSClass::IN
        || matches!(
            q.query_type(),
            RecordType::AXFR | RecordType::IXFR | RecordType::ANY
        )
    {
        reply.metadata.response_code = ResponseCode::Refused;
    } else if let Some(zone) = zone {
        reply.metadata.authoritative = true;
        let records: Vec<_> = snapshot
            .records
            .iter()
            .filter(|r| r.zone_id == zone.id && r.name == name)
            .collect();
        // Empty non-terminals exist when an enabled descendant record exists.
        let exists = name == zone.name
            || !records.is_empty()
            || snapshot
                .records
                .iter()
                .any(|r| r.zone_id == zone.id && security::inside(&r.name, &name));
        if !exists {
            reply.metadata.response_code = ResponseCode::NXDomain;
        }
        // RFC 2181: every address in an RRset uses the lowest configured TTL.
        let rr_type = q.query_type().to_string();
        let rr_ttl = records
            .iter()
            .filter(|r| r.record_type == rr_type)
            .map(|r| r.ttl)
            .min()
            .unwrap_or(60);
        for r in records {
            let data = match (q.query_type(), r.record_type.as_str()) {
                (RecordType::A, "A") => r.value.parse().ok().map(|v| RData::A(A(v))),
                (RecordType::AAAA, "AAAA") => r.value.parse().ok().map(|v| RData::AAAA(AAAA(v))),
                _ => None,
            };
            if let Some(data) = data {
                reply
                    .answers
                    .push(Record::from_rdata(q.name().clone(), rr_ttl, data));
            }
        }
        if reply.answers.is_empty() {
            let origin = Name::from_utf8(&zone.name).map_err(|_| ApiError::bad("Invalid zone"))?;
            let soa = SOA::new(
                origin.clone(),
                Name::from_utf8(format!("hostmaster.{}", zone.name))
                    .map_err(|_| ApiError::bad("Invalid zone"))?,
                snapshot.revision as u32,
                60,
                30,
                3600,
                15,
            );
            let record = Record::from_rdata(origin, 15, RData::SOA(soa));
            if q.query_type() == RecordType::SOA && name == zone.name {
                reply.answers.push(record);
            } else {
                reply.authorities.push(record);
            }
        }
    }
    let success = matches!(
        reply.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    );
    Ok((
        reply
            .to_vec()
            .map_err(|_| ApiError::bad("DNS encoding failed"))?,
        success,
    ))
}

pub fn prepare(
    app: &App,
    token: &str,
    bytes: &[u8],
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<(i64, Vec<u8>, bool), ApiError> {
    prepare_mode(app, token, bytes, peer, headers, false)
        .map(|(revision, wire, success, _)| (revision, wire, success))
}

fn prepare_mode(
    app: &App,
    token: &str,
    bytes: &[u8],
    peer: SocketAddr,
    headers: &HeaderMap,
    compatible: bool,
) -> Result<(i64, Vec<u8>, bool, Option<Vec<u8>>), ApiError> {
    let client = crate::auth::client_ip(app, peer, headers);
    if !app.allow(format!("dns-ip:{client}"), 600, Duration::from_secs(1)) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
        ));
    }
    if token.len() != 43
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Access denied"));
    }
    let snapshot = app.view().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Configuration lease unavailable",
        )
    })?;
    let hash = security::digest(token);
    let credential = snapshot
        .credentials
        .get(&hash)
        .filter(|c| c.expires_at.is_none_or(|at| at > now()))
        .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "Access denied"))?;
    if !app.allow(
        format!("token:{}", credential.id),
        snapshot.token_qps,
        Duration::from_secs(1),
    ) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
        ));
    }
    let result = answer(&snapshot, credential, bytes)?;
    let forward = if compatible {
        public_query(&snapshot, bytes)?
    } else {
        None
    };
    Ok((snapshot.revision, result.0, result.1, forward))
}
async fn process(
    app: &App,
    token: &str,
    bytes: &[u8],
    peer: SocketAddr,
    headers: &HeaderMap,
    compatible: bool,
) -> Response {
    let started = Instant::now();
    let result = match prepare_mode(app, token, bytes, peer, headers, compatible) {
        Ok((_, wire, success, None)) => Ok((wire, success)),
        Ok((_, _, _, Some(query))) => forward_public(app, &query).await.map(|wire| {
            let success = matches!(wire[3] & 15, 0 | 3);
            (wire, success)
        }),
        Err(error) => Err(error),
    };
    match result {
        Ok((wire, success)) => {
            app.count(
                if success {
                    "success"
                } else if wire[3] & 15 == 2 {
                    "error"
                } else {
                    "denied"
                },
                started.elapsed(),
            );
            (
                [
                    (header::CONTENT_TYPE, "application/dns-message"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                wire,
            )
                .into_response()
        }
        Err(error) => {
            app.count(
                if matches!(
                    error.status,
                    StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
                ) {
                    "denied"
                } else {
                    "error"
                },
                started.elapsed(),
            );
            let mut response = error.into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            response
        }
    }
}
pub async fn get(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    RawQuery(query): RawQuery,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let raw = query.unwrap_or_default();
    if raw.len() > 8192 {
        return ApiError::new(StatusCode::URI_TOO_LONG, "DNS query too large").into_response();
    }
    let params: Vec<_> = url::form_urlencoded::parse(raw.as_bytes()).collect();
    let values: Vec<_> = params
        .iter()
        .filter(|(k, _)| k == "dns")
        .map(|(_, v)| v.as_ref())
        .collect();
    if values.len() != 1 {
        return ApiError::bad("A single dns query parameter is required").into_response();
    }
    match URL_SAFE_NO_PAD.decode(values[0]) {
        Ok(bytes) => {
            process(
                &app,
                &token,
                &bytes,
                peer,
                &headers,
                uri.path().starts_with("/dns-query/compat/"),
            )
            .await
        }
        Err(_) => ApiError::bad("Invalid DNS query encoding").into_response(),
    }
}
pub async fn post(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.split(';').next())
        != Some("application/dns-message")
    {
        return ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected application/dns-message",
        )
        .into_response();
    }
    process(
        &app,
        &token,
        &body,
        peer,
        &headers,
        uri.path().starts_with("/dns-query/compat/"),
    )
    .await
}

// Called only after token validation and the normal strict DNS parser. Never fall
// back for a known private zone, including a disabled or unauthorized zone.
fn public_query(snapshot: &Snapshot, wire: &[u8]) -> Result<Option<Vec<u8>>, ApiError> {
    let Some(zones) = &snapshot.private_zones else {
        return Ok(None);
    };
    let query = Message::from_vec(wire).map_err(|_| ApiError::bad("Invalid DNS message"))?;
    if query.queries.len() != 1
        || query.metadata.op_code != OpCode::Query
        || query.metadata.message_type != MessageType::Query
        || query.edns.as_ref().is_some_and(|e| e.version() != 0)
    {
        return Ok(None);
    }
    let q = &query.queries[0];
    let name = q.name().to_ascii().trim_end_matches('.').to_lowercase();
    if q.query_class() != DNSClass::IN
        || matches!(
            q.query_type(),
            RecordType::AXFR | RecordType::IXFR | RecordType::ANY
        )
        || zones.iter().any(|z| security::inside(&name, z))
        || snapshot
            .zones
            .iter()
            .any(|z| security::inside(&name, &z.name))
    {
        return Ok(None);
    }
    // Rebuild the query: no ECS, cookies, extra records, or client-supplied headers.
    let mut clean = Message::query();
    clean.metadata.id = query.metadata.id;
    clean.metadata.recursion_desired = true;
    clean.queries = query.queries;
    clean
        .to_vec()
        .map(Some)
        .map_err(|_| ApiError::bad("DNS encoding failed"))
}

async fn forward_public(app: &App, query: &[u8]) -> Result<Vec<u8>, ApiError> {
    let request = Message::from_vec(query).map_err(|_| ApiError::bad("Invalid DNS message"))?;
    // Fixed HTTPS upstreams; tokens and client IP headers are never forwarded.
    for upstream in ["https://1.1.1.1/dns-query", "https://223.5.5.5/dns-query"] {
        let Ok(mut response) = app
            .0
            .http
            .post(upstream)
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header(header::ACCEPT, "application/dns-message")
            .body(query.to_vec())
            .send()
            .await
        else {
            continue;
        };
        if !response.status().is_success()
            || response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.split(';').next())
                != Some("application/dns-message")
        {
            continue;
        }
        let mut wire = Vec::new();
        let mut complete = true;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if wire.len() + chunk.len() <= 65535 => {
                    wire.extend_from_slice(&chunk)
                }
                Ok(None) => break,
                _ => {
                    complete = false;
                    break;
                }
            }
        }
        if !complete {
            continue;
        }
        let Ok(answer) = Message::from_vec(&wire) else {
            continue;
        };
        if answer.metadata.message_type == MessageType::Response
            && answer.metadata.id == request.metadata.id
            && answer.metadata.op_code == OpCode::Query
            && answer.queries == request.queries
            && matches!(
                answer.metadata.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            return Ok(wire);
        }
    }
    // Fail closed; do not ask the client's public DNS as a fallback.
    let mut failure = Message::response(request.metadata.id, OpCode::Query);
    failure.queries = request.queries;
    failure.metadata.recursion_desired = true;
    failure.metadata.recursion_available = true;
    failure.metadata.response_code = ResponseCode::ServFail;
    failure
        .to_vec()
        .map_err(|_| ApiError::bad("DNS encoding failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsRecord, Zone};
    use hickory_proto::op::Query;
    use std::collections::HashMap;
    fn fixture() -> (Snapshot, Credential) {
        (
            Snapshot {
                private_zones: Some(vec![
                    "nodes.example.com".into(),
                    "disabled.example.com".into(),
                ]),
                revision: 1,
                token_qps: 30,
                zones: vec![Zone {
                    id: "z".into(),
                    name: "nodes.example.com".into(),
                }],
                records: vec![DnsRecord {
                    zone_id: "z".into(),
                    name: "hk.nodes.example.com".into(),
                    record_type: "A".into(),
                    value: "203.0.113.8".into(),
                    ttl: 60,
                }],
                credentials: HashMap::new(),
            },
            Credential {
                id: "t".into(),
                user_id: "u".into(),
                expires_at: None,
                zones: vec!["z".into()],
            },
        )
    }
    fn request(name: &str, kind: RecordType) -> Vec<u8> {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), kind));
        m.to_vec().unwrap()
    }
    #[test]
    fn compatibility_never_forwards_private_or_unsafe_questions() {
        let (mut s, _) = fixture();
        for domain in [
            "hk.nodes.example.com",
            "missing.nodes.example.com",
            "disabled.example.com",
            "x.disabled.example.com",
        ] {
            assert!(
                public_query(&s, &request(domain, RecordType::A))
                    .unwrap()
                    .is_none()
            );
        }
        for kind in [RecordType::AXFR, RecordType::IXFR, RecordType::ANY] {
            assert!(
                public_query(&s, &request("example.org", kind))
                    .unwrap()
                    .is_none()
            );
        }
        let q = request("example.org", RecordType::A);
        assert!(public_query(&s, &q).unwrap().is_some());
        s.private_zones = None;
        assert!(public_query(&s, &q).unwrap().is_none());
    }
    #[test]
    fn resolution_and_negative_answers() {
        let (s, c) = fixture();
        for (name, kind, code, count) in [
            (
                "hk.nodes.example.com",
                RecordType::A,
                ResponseCode::NoError,
                1,
            ),
            (
                "hk.nodes.example.com",
                RecordType::AAAA,
                ResponseCode::NoError,
                0,
            ),
            (
                "missing.nodes.example.com",
                RecordType::A,
                ResponseCode::NXDomain,
                0,
            ),
            (
                "outside.example.com",
                RecordType::A,
                ResponseCode::Refused,
                0,
            ),
            (
                "hk.nodes.example.com",
                RecordType::AXFR,
                ResponseCode::Refused,
                0,
            ),
        ] {
            let wire = request(name, kind);
            let (bytes, _) = answer(&s, &c, &wire).unwrap();
            let response = Message::from_vec(&bytes).unwrap();
            assert_eq!(response.metadata.response_code, code);
            assert_eq!(response.answers.len(), count);
            assert_eq!(
                response.metadata.id,
                Message::from_vec(&wire).unwrap().metadata.id
            );
        }
    }
    #[test]
    fn grants_and_malformed_queries() {
        let (s, mut c) = fixture();
        c.zones.clear();
        let (bytes, _) = answer(&s, &c, &request("hk.nodes.example.com", RecordType::A)).unwrap();
        assert_eq!(
            Message::from_vec(&bytes).unwrap().metadata.response_code,
            ResponseCode::Refused
        );
        assert!(answer(&s, &c, b"garbage").is_err());
    }
    #[test]
    fn edns_rrset_and_empty_nonterminal() {
        let (mut s, c) = fixture();
        s.records.push(DnsRecord {
            zone_id: "z".into(),
            name: "hk.nodes.example.com".into(),
            record_type: "A".into(),
            value: "203.0.113.9".into(),
            ttl: 30,
        });
        s.records.push(DnsRecord {
            zone_id: "z".into(),
            name: "a.branch.nodes.example.com".into(),
            record_type: "A".into(),
            value: "203.0.113.10".into(),
            ttl: 60,
        });
        let (wire, _) = answer(&s, &c, &request("hk.nodes.example.com", RecordType::A)).unwrap();
        let m = Message::from_vec(&wire).unwrap();
        assert_eq!(m.answers.len(), 2);
        assert!(m.answers.iter().all(|r| r.ttl == 30));
        let (wire, success) =
            answer(&s, &c, &request("branch.nodes.example.com", RecordType::A)).unwrap();
        let m = Message::from_vec(&wire).unwrap();
        assert!(success);
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert!(m.answers.is_empty());
        let mut q = Message::from_vec(&request("hk.nodes.example.com", RecordType::A)).unwrap();
        let mut e = Edns::new();
        e.set_version(1);
        q.edns = Some(e);
        let (wire, _) = answer(&s, &c, &q.to_vec().unwrap()).unwrap();
        // BADVERS and BADSIG share wire code 16; the decoder uses the BADSIG alias.
        let reply = Message::from_vec(&wire).unwrap();
        assert_eq!(u16::from(reply.metadata.response_code), 16);
        assert_eq!(reply.edns.unwrap().version(), 0);
        q.metadata.message_type = MessageType::Response;
        assert!(answer(&s, &c, &q.to_vec().unwrap()).is_err());
    }
}
