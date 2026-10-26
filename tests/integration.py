#!/usr/bin/env python3
"""Real MariaDB + controller + two node processes. Python cryptography is used for independent signature verification fixtures.

Requires DNSDOH_TEST_ENV and an isolated database whose name ends in _test.
This suite clears that test database, never the acceptance/production database.
Secrets are read from a mode-0600 env file and are never printed.
"""
import base64
import contextlib
import hashlib
import http.cookiejar
import http.server
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(os.environ.get('DNSDOH_TEST_RUNTIME', '/mnt/youlin-data/runtime/integration'))
RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
CONFIG = Path(os.environ.get('DNSDOH_TEST_ENV', '/mnt/youlin-data/runtime/test.env'))
ENV = os.environ.copy()
ENV.update(dict(line.split('=', 1) for line in CONFIG.read_text().splitlines() if line and not line.startswith('#')))
ENV["DNSDOH_TEST_MODE"]="true"
ENV["DNSDOH_MASTER_KEY"]=secrets.token_urlsafe(32)
BIN = os.environ.get('DNSDOH_BIN', str(ROOT / 'target/debug/dnsdoh'))
BASE = 'http://127.0.0.1:19080'
NODE1 = 'http://127.0.0.1:19081'
NODE2 = 'http://127.0.0.1:19082'
DB = urllib.parse.urlsplit(ENV['DATABASE_URL'])
assert DB.path[1:].endswith('_test'), 'Integration tests require an isolated *_test database'
PROCESSES = []
SECRETS = [ENV['DNSDOH_ADMIN_PASSWORD'], DB.password]
RESULTS = []


def sql(query):
    env = ENV.copy()
    env['MYSQL_PWD'] = urllib.parse.unquote(DB.password)
    result = subprocess.run([ENV.get('DNSDOH_MARIADB_BIN', 'mariadb'), '--no-defaults',
        '--host=' + DB.hostname, '--port=' + str(DB.port or 3306),
        '--user=' + urllib.parse.unquote(DB.username), '--batch', '--skip-column-names', DB.path[1:]],
        input=query, text=True, capture_output=True, env=env)
    assert result.returncode == 0, 'MariaDB test statement failed'
    return result.stdout.strip()


def check(condition, label):
    assert condition, label
    RESULTS.append(label)
    print('PASS', label, flush=True)


def wait_for(predicate, timeout=12):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if predicate():
                return True
        except (OSError, urllib.error.URLError, TimeoutError):
            pass
        time.sleep(.15)
    return False


class Client:
    def __init__(self, base=BASE):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ''

    def request(self, path, method='GET', body=None, headers=None):
        h = {'X-CSRF-Token': self.csrf}
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
            h['Content-Type'] = 'application/json'
        if headers:
            h.update(headers)
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=h)
        try:
            result = self.opener.open(req, timeout=4)
        except urllib.error.HTTPError as error:
            result = error
        return result.code, result.read(), {k.lower(): v for k, v in result.headers.items()}

    def api(self, path, method='GET', body=None, expected=200, headers=None):
        status, wire, response_headers = self.request('/api' + path, method, body, headers)
        assert status == expected, f'API {method} {path} expected {expected}, got {status}'
        return json.loads(wire)

    def login(self):
        data = self.api('/login', 'POST', {'username': ENV['DNSDOH_ADMIN_USERNAME'], 'password': ENV['DNSDOH_ADMIN_PASSWORD']})
        self.csrf = data['csrf']
        SECRETS.extend([self.csrf] + [c.value for c in self.jar])


def start(name, overrides):
    env = ENV.copy()
    env.update(overrides)
    log = open(RUNTIME / (name + '.log'), 'ab')
    process = subprocess.Popen([BIN, 'serve'], env=env, stdout=log, stderr=log)
    PROCESSES.append(process)
    log.close()
    return process


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def question(name, kind=1, ident=0x3A12, edns_version=None):
    q = b''.join(bytes([len(s)]) + s.encode() for s in name.split('.')) + b'\0' + struct.pack('!HH', kind, 1)
    header = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, int(edns_version is not None))
    return header + q + (b'\0' + struct.pack('!HHIH', 41, 1232, edns_version << 16, 0) if edns_version is not None else b'')


def dns_name(wire, pos):
    while wire[pos]:
        if wire[pos] & 0xC0 == 0xC0:
            return pos + 2
        pos += wire[pos] + 1
    return pos + 1


def decode(wire):
    ident, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', wire[:12])
    pos = 12
    for _ in range(qd):
        pos = dns_name(wire, pos) + 4
    records = []
    for _ in range(an + ns + ar):
        pos = dns_name(wire, pos)
        kind, cls, ttl, length = struct.unpack('!HHIH', wire[pos:pos + 10])
        pos += 10
        value = str(ipaddress.ip_address(wire[pos:pos + length])) if kind in (1, 28) else None
        records.append({'type': kind, 'ttl': ttl, 'value': value})
        pos += length
    return {'id': ident, 'flags': flags, 'rcode': flags & 15, 'answers': an, 'authority': ns, 'records': records}


def doh(base, token, name='hk01.nodes.example.test', kind=1, method='POST', wire=None):
    wire = question(name, kind) if wire is None else wire
    path = '/dns-query/' + token
    if method == 'GET':
        path += '?dns=' + base64.urlsafe_b64encode(wire).decode().rstrip('=')
        body = None
    else:
        body = wire
    status, data, headers = Client(base).request(path, method, body, {'Content-Type': 'application/dns-message'})
    return status, decode(data) if status == 200 else None, headers


PROXY_ENABLED = threading.Event()
PROXY_ENABLED.set()
PROXY_REJECT_REPORT = threading.Event()
PROXY_DROPPED_REPORT = threading.Event()
PROXY_RECOVERED_REPORT = threading.Event()
class SyncProxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        if not PROXY_ENABLED.is_set():
            self.send_response(503); self.end_headers(); return
        payload = json.loads(body)
        if PROXY_REJECT_REPORT.is_set() and payload.get('report'):
            PROXY_REJECT_REPORT.clear(); PROXY_DROPPED_REPORT.set()
            self.send_response(400); self.end_headers(); return
        if PROXY_DROPPED_REPORT.is_set() and payload.get('report') is None:
            PROXY_RECOVERED_REPORT.set()
        try:
            status, data, headers = Client().request('/internal/node/sync', 'POST', body,
                {'Authorization': self.headers.get('Authorization', ''), 'Content-Type': 'application/json'})
            self.send_response(status)
            self.send_header('Content-Type', headers.get('content-type', 'application/json'))
            self.end_headers(); self.wfile.write(data)
        except Exception:
            self.send_response(503); self.end_headers()


def main():
    tables = sql('SHOW TABLES').splitlines()
    if tables:
        sql('SET FOREIGN_KEY_CHECKS=0;' + ''.join('DROP TABLE `' + t.replace('`', '``') + '`;' for t in tables) + 'SET FOREIGN_KEY_CHECKS=1;')
    controller = start('controller', {'DNSDOH_MODE': 'controller', 'DNSDOH_PUBLIC_URL': BASE, 'DNSDOH_DOH_URL': BASE, 'DNSDOH_BIND': '127.0.0.1:19080'})
    check(wait_for(lambda: Client().request('/readyz')[0] == 200), 'controller starts with MariaDB migrations')
    anonymous = Client()
    check(anonymous.request('/api/state')[0] == 401, 'anonymous administrator access rejected')
    anonymous.api('/login', 'POST', {'username': 'admin', 'password': 'wrong'}, expected=401)
    c = Client(); c.login()
    cookies = list(c.jar)
    check('HttpOnly' in cookies[0]._rest and cookies[0]._rest.get('SameSite') == 'Strict', 'session uses HttpOnly and SameSite=Strict')
    c.api('/zones', 'POST', {'name': 'nodes.example.test'}, expected=403, headers={'X-CSRF-Token': ''})
    c.api('/zones', 'POST', {'name': 'nodes.example.test'}, expected=403, headers={'Origin': 'https://untrusted.example'})
    check(not c.api('/state')['zones'], 'CSRF and cross-origin writes cannot mutate data')
    z = c.api('/zones', 'POST', {'name': 'nodes.example.test'})['id']
    z2 = c.api('/zones', 'POST', {'name': 'restricted.example.test'})['id']
    c.api('/zones', 'POST', {'name': 'sub.nodes.example.test'}, expected=400)
    c.api('/zones', 'POST', {'name': 'example.test'}, expected=400)
    check(True, 'overlapping private zones rejected to preserve permission boundaries')
    r = c.api('/records', 'POST', {'zone_id': z, 'name': 'HK01.nodes.example.test.', 'record_type': 'A', 'value': '203.0.113.10', 'ttl': 60})['id']
    c.api('/records', 'POST', {'zone_id': z, 'name': 'hk01.nodes.example.test', 'record_type': 'AAAA', 'value': '2001:db8::10', 'ttl': 60})
    c.api('/records', 'POST', {'zone_id': z, 'name': 'v4.nodes.example.test', 'record_type': 'A', 'value': '192.0.2.8', 'ttl': 60})
    c.api('/records', 'POST', {'zone_id': z2, 'name': 'a.restricted.example.test', 'record_type': 'A', 'value': '192.0.2.99'})
    c.api('/records', 'POST', {'zone_id': z, 'name': 'evilnodes.example.test', 'record_type': 'A', 'value': '192.0.2.1'}, expected=400)
    c.api('/records', 'POST', {'zone_id': z, 'name': 'a.nodes.example.test', 'record_type': 'AAAA', 'value': '192.0.2.1'}, expected=400)
    c.api('/records', 'POST', {'zone_id': z, 'name': 'a.nodes.example.test', 'record_type': 'A', 'value': '192.0.2.1', 'ttl': 0}, expected=400)
    check(True, 'record normalization, zone boundary, address family and TTL validation')
    u = c.api('/users', 'POST', {'name': 'Integration user', 'zone_ids': [z]})['id']
    t = c.api('/tokens', 'POST', {'user_id': u, 'name': 'Integration token'})
    token = t['token']; SECRETS.append(token)
    check(len(token) == 43 and '=' not in token, '256-bit URL-safe access tokens')
    for method in ['GET', 'POST']:
        status, data, headers = doh(BASE, token, method=method)
        check(status == 200 and data['id'] == 0x3A12 and data['rcode'] == 0 and data['records'][0]['value'] == '203.0.113.10', 'RFC8484 ' + method + ' returns private IPv4')
        check(data['flags'] & 0x0400 and not data['flags'] & 0x0080 and not data['flags'] & 0x0020 and headers.get('cache-control') == 'no-store', method + ' DNS flags and HTTP cache isolation')
    check(doh(BASE, token, kind=28)[1]['records'][0]['value'] == '2001:db8::10', 'private IPv6 resolution')
    check(doh(BASE, token, 'v4.nodes.example.test', 28)[1]['answers'] == 0 and doh(BASE, token, 'v4.nodes.example.test', 28)[1]['rcode'] == 0, 'NODATA for existing name without requested type')
    negative = doh(BASE, token, 'missing.nodes.example.test')[1]
    check(negative['rcode'] == 3 and negative['authority'] == 1, 'NXDOMAIN includes negative-cache SOA')
    for name, kind in [('a.restricted.example.test', 1), ('example.com', 1), ('evilnodes.example.test', 1), ('nodes.example.test', 252), ('nodes.example.test', 255)]:
        check(doh(BASE, token, name, kind)[1]['rcode'] == 5, f'query refused: {name} type={kind}')
    check(doh(BASE, 'A' * 43)[0] == 403 and doh(BASE, 'bad')[0] == 403, 'invalid tokens reveal no IP')
    check(doh(BASE, token, wire=b'bad')[0] == 400, 'malformed DNS wire rejected')
    path = '/dns-query/' + token
    check(c.request(path, 'POST', question('hk01.nodes.example.test'), {'Content-Type': 'application/json'})[0] == 415, 'wrong media type rejected')
    check(c.request(path + '?dns=bad&dns=bad')[0] == 400, 'duplicate DNS query parameters rejected')
    check(c.request(path, 'POST', b'A' * 70000, {'Content-Type': 'application/dns-message'})[0] == 413, 'oversized wire rejected')
    raw = c.api('/state')
    check(token not in json.dumps(raw) and 'token_hash' not in json.dumps(raw) and 'secret_hash' not in json.dumps(raw), 'dashboard never exposes stored credential hashes or raw tokens')
    check(sql('SELECT token_hash FROM tokens WHERE id="' + t['id'] + '"') == hashlib.sha256(token.encode()).hexdigest(), 'MariaDB stores token SHA-256 instead of plaintext')
    # Rejected grant replacement must roll back the entire transaction.
    c.api('/users/' + u, 'PUT', {'name': 'Should roll back', 'zone_ids': [str(uuid.uuid4())]}, expected=400)
    check(next(x for x in c.api('/state')['users'] if x['id'] == u)['name'] == 'Integration user', 'invalid grant update rolls back atomically')
    c.api('/users/' + u, 'PUT', {'name': 'Integration user', 'zone_ids': [], 'enabled': True})
    check(doh(BASE, token)[1]['rcode'] == 5, 'removing a zone grant denies subsequent queries')
    c.api('/users/' + u, 'PUT', {'name': 'Integration user', 'zone_ids': [z], 'enabled': False})
    check(doh(BASE, token)[0] == 403, 'disabled user invalidates all user tokens')
    c.api('/users/' + u, 'PUT', {'name': 'Integration user', 'zone_ids': [z], 'enabled': True})
    expiring = c.api('/tokens', 'POST', {'user_id': u, 'name': 'Short lived', 'expires_at': int(time.time()) + 2})['token']
    SECRETS.append(expiring)
    check(wait_for(lambda: doh(BASE, expiring)[0] == 403, 5), 'token expiration enforced at query time')
    c.api('/settings', 'PUT', {'token_qps': 2, 'retention_days': 14})
    time.sleep(1.1)
    codes = [doh(BASE, token)[0] for _ in range(4)]
    check(codes == [200, 200, 429, 429], 'per-token query rate limit enforced')
    c.api('/settings', 'PUT', {'token_qps': 1000, 'retention_days': 14})
    n1 = c.api('/nodes', 'POST', {'name': 'Test node A', 'endpoint': NODE1, 'region': 'local'})
    n2 = c.api('/nodes', 'POST', {'name': 'Test node B', 'endpoint': NODE2, 'region': 'local'})
    SECRETS.extend([n1['secret'], n2['secret']])
    proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 19090), SyncProxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    def start_node(node, endpoint, controller_url):
        return start('node-' + node['id'], {'DNSDOH_MODE': 'node', 'DNSDOH_NODE_ID': node['id'], 'DNSDOH_NODE_SECRET': node['secret'], 'DNSDOH_BIND': endpoint.removeprefix('http://'), 'DNSDOH_PUBLIC_URL': endpoint, 'DNSDOH_DOH_URL': endpoint, 'DNSDOH_CONTROLLER_URL': controller_url})
    p1 = start_node(n1, NODE1, BASE)
    p2 = start_node(n2, NODE2, 'http://127.0.0.1:19090')
    check(wait_for(lambda: doh(NODE1, token)[0] == 200 and doh(NODE2, token)[0] == 200), 'two independent node processes synchronize and answer')
    # One-time enrollment, body-bound signatures and replay protection.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    b64=lambda b:base64.urlsafe_b64encode(b).decode().rstrip('=')
    key=Ed25519PrivateKey.generate()
    public=b64(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
    private=b64(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
    SECRETS.extend([private,n1['install_ticket']])
    check('sha256sum --check' in n1['install_command'] and n1['secret'] not in n1['install_command'], 'create node returns hash-pinned installer with only a one-time ticket')
    grant=c.api('/nodes/'+n1['id']+'/install','POST');SECRETS.append(grant['install_ticket'])
    body={'ticket':n1['install_ticket'],'node_id':n1['id'],'endpoint':NODE1,'public_key':public}
    check(c.request('/internal/node/enroll','POST',body)[0]==403,'reissuing installer invalidates previous unused ticket')
    body['ticket']=grant['install_ticket'];body['node_id']=n2['id']
    check(c.request('/internal/node/enroll','POST',body)[0]==403,'ticket is bound to its registered node')
    body['node_id']=n1['id'];body['endpoint']=NODE2
    check(c.request('/internal/node/enroll','POST',body)[0]==403,'ticket is bound to its configured endpoint')
    body['endpoint']=NODE1
    check(c.request('/internal/node/enroll','POST',body)[0]==200,'one-time ticket accepts locally generated Ed25519 public key')
    check(c.request('/internal/node/enroll','POST',body)[0]==403,'redeemed installation ticket cannot be replayed')
    sync={'node_id':n1['id'],'applied_revision':0,'version':'signature-test','report':None}
    check(c.request('/internal/node/sync','POST',sync,{'Authorization':'Bearer '+n1['secret']})[0]==403,'enrolled node rejects its previous bearer secret')
    wire=json.dumps(sync).encode()
    def signed(payload,timestamp=None,context=None):
        timestamp=str(timestamp if timestamp is not None else int(time.time()));nonce=secrets.token_urlsafe(32)
        message=f'DNSDOH-SYNC-V1\n{context or n1["id"]}\n{timestamp}\n{nonce}\n{hashlib.sha256(payload).hexdigest()}'.encode()
        return {'Content-Type':'application/json','x-dnsdoh-time':timestamp,'x-dnsdoh-nonce':nonce,'x-dnsdoh-signature':b64(key.sign(message))}
    headers=signed(wire)
    check(c.request('/internal/node/sync','POST',wire,headers)[0]==200,'valid signed synchronization accepted')
    check(c.request('/internal/node/sync','POST',wire,headers)[0]==403,'replayed signed synchronization rejected')
    check(c.request('/internal/node/sync','POST',wire+b' ',signed(wire))[0]==403,'signature binds exact request body')
    check(c.request('/internal/node/sync','POST',wire,signed(wire,int(time.time())-60))[0]==403,'stale signed request rejected')
    control=json.dumps({'node_id':n1['id'],'applied_revision':0}).encode()
    check(c.request('/internal/node/control','POST',control,signed(control))[0]==403,'sync-context signature cannot authorize certificate control API')
    control_headers=signed(control,context=n1['id']+'/control')
    check(c.request('/internal/node/control','POST',control,control_headers)[0]==200,'independently signed control request accepted')
    check(c.request('/internal/node/control','POST',control,control_headers)[0]==403,'certificate control API rejects replayed nonce')
    check(c.request('/internal/node/control','POST',control+b' ',signed(control,context=n1['id']+'/control'))[0]==403,'certificate control signature binds exact body')
    check(c.request('/internal/node/control','POST',control,signed(control,int(time.time())-60,context=n1['id']+'/control'))[0]==403,'certificate control API rejects expired signature')
    grant=c.api('/nodes/'+n2['id']+'/install','POST');SECRETS.append(grant['install_ticket'])
    sql('UPDATE node_enrollments SET expires_at=0 WHERE node_id="'+n2['id']+'"')
    check(c.request('/internal/node/enroll','POST',{'ticket':grant['install_ticket'],'node_id':n2['id'],'endpoint':NODE2,'public_key':public})[0]==403,'expired installation ticket rejected')
    stop(p1)
    def start_signed():
        return start('signed-node-A',{'DNSDOH_MODE':'node','DNSDOH_NODE_ID':n1['id'],'DNSDOH_NODE_PRIVATE_KEY':private,'DNSDOH_NODE_SECRET':'','DNSDOH_BIND':'127.0.0.1:19081','DNSDOH_PUBLIC_URL':NODE1,'DNSDOH_DOH_URL':NODE1,'DNSDOH_CONTROLLER_URL':BASE})
    p1=start_signed()
    check(wait_for(lambda:doh(NODE1,token)[0]==200),'signed node process synchronizes and serves real DNS')
    gateway=BASE+'/gateway'
    check(wait_for(lambda:doh(gateway,token)[2].get('x-dnsdoh-route')=='forwarded'),'unified gateway routes to a healthy current-revision node')
    check(doh(gateway,'A'*43)[0]==403,'unified gateway authenticates before forwarding')
    stop(p1);stop(p2)
    check(doh(gateway,token)[2].get('x-dnsdoh-route')=='local-fallback','unified gateway falls back locally when all nodes fail')
    p1=start_signed();p2=start_node(n2,NODE2,'http://127.0.0.1:19090')
    check(wait_for(lambda:doh(gateway,token)[2].get('x-dnsdoh-route')=='forwarded'),'gateway automatically restores healthy backend routing')
    check(Client(NODE1).request('/api/state')[0] == 404 and Client(NODE1).request('/')[0] == 404, 'DNS nodes expose no administrative dashboard or API')
    c.api('/records/' + r, 'PUT', {'zone_id': z, 'name': 'hk01.nodes.example.test', 'record_type': 'A', 'value': '203.0.113.11', 'ttl': 45})
    check(wait_for(lambda: doh(NODE1, token)[1]['records'][0]['value'] == '203.0.113.11' and doh(NODE2, token)[1]['records'][0]['value'] == '203.0.113.11'), 'record edits propagate to both nodes')
    # Deduplication is verified on a separately registered reporting identity.
    nr = c.api('/nodes', 'POST', {'name': 'Metrics fixture', 'endpoint': 'http://127.0.0.1:19999'})
    SECRETS.append(nr['secret'])
    report = {'node_id': nr['id'], 'applied_revision': 1, 'version': 'test', 'report': {'id': str(uuid.uuid4()), 'metrics': [{'bucket': int(time.time()) // 60 * 60, 'total': 7, 'success': 5, 'denied': 1, 'errors': 1, 'latency_us': 123}]}}
    for _ in range(2):
        status, _, _ = c.request('/internal/node/sync', 'POST', report, {'Authorization': 'Bearer ' + nr['secret']})
        assert status == 200, 'metrics sync failed'
    check(sql('SELECT SUM(total) FROM metrics WHERE node_id="' + nr['id'] + '"') == '7', 'retried metrics reports are counted exactly once')
    report['report']['metrics'][0]['success'] = 9223372036854775807
    check(c.request('/internal/node/sync', 'POST', report, {'Authorization': 'Bearer ' + nr['secret']})[0] == 400, 'hostile metric integers cannot overflow or crash control plane')
    PROXY_ENABLED.clear()
    start_revoke = time.monotonic()
    c.api('/tokens/' + t['id'] + '/revoke', 'POST')
    check(wait_for(lambda: doh(NODE1, token)[0] == 403, 6), 'online node rejects revoked token after synchronization')
    check(wait_for(lambda: doh(NODE2, token)[0] == 503, 16), 'disconnected node fails closed when its configuration lease expires')
    check(time.monotonic() - start_revoke < 16, 'revocation remains bounded by the 15-second node lease')
    PROXY_ENABLED.set()
    check(wait_for(lambda: doh(NODE2, token)[0] == 403), 'reconnected node does not resurrect revoked credentials')
    token2 = c.api('/tokens', 'POST', {'user_id': u, 'name': 'After revoke'})['token']; SECRETS.append(token2)
    check(wait_for(lambda: doh(NODE1, token2)[0] == 200 and doh(NODE2, token2)[0] == 200), 'fresh token works on all restored nodes')
    rotated = c.api('/nodes/' + n1['id'] + '/rotate', 'POST'); SECRETS.append(rotated['secret'])
    check(wait_for(lambda: Client(NODE1).request('/readyz')[0] == 503), 'node key rotation stops the old node credential')
    stop(p1)
    n1['secret'] = rotated['secret']
    p1 = start_node(n1, NODE1, BASE)
    check(wait_for(lambda: doh(NODE1, token2)[0] == 200), 'rotated node credential restores synchronization')
    PROXY_REJECT_REPORT.set()
    doh(NODE2, token2)
    check(wait_for(lambda: PROXY_DROPPED_REPORT.is_set()), 'invalid metrics batch can be rejected independently')
    check(wait_for(lambda: PROXY_RECOVERED_REPORT.is_set()), 'rejected metrics do not permanently block node configuration recovery')
    # Simulate database read failure without stopping other MariaDB databases.
    sql('RENAME TABLE tokens TO tokens_unavailable')
    try:
        check(wait_for(lambda: doh(BASE, token2)[0] == 503, 6), 'controller fails closed on a MariaDB configuration-read failure')
        check(wait_for(lambda: doh(NODE1, token2)[0] == 503 and doh(NODE2, token2)[0] == 503, 19), 'both nodes stop answering after controller configuration failure')
    finally:
        sql('RENAME TABLE tokens_unavailable TO tokens')
    check(wait_for(lambda: doh(BASE, token2)[0] == 200 and doh(NODE1, token2)[0] == 200 and doh(NODE2, token2)[0] == 200), 'MariaDB recovery automatically restores controller and nodes')
    c.api('/nodes/' + nr['id'], 'DELETE')
    c.api('/zones/' + z2, 'DELETE')
    c.api('/users/' + u, 'DELETE')
    check(doh(BASE, token2)[0] == 403 and sql('SELECT COUNT(*) FROM tokens') == '0', 'user deletion cascades tokens and grants')
    c2 = Client(); c2.login()
    new_password = secrets.token_urlsafe(24); SECRETS.append(new_password)
    c.api('/password', 'POST', {'current_password': ENV['DNSDOH_ADMIN_PASSWORD'], 'new_password': new_password})
    check(c2.request('/api/state')[0] == 401 and c.request('/api/state')[0] == 200, 'password change revokes other sessions and preserves the current one')
    c.api('/logout', 'POST')
    check(c.request('/api/state')[0] == 401, 'logout invalidates the server-side session')
    for process in PROCESSES:
        stop(process)
    proxy.shutdown(); proxy.server_close()
    logs = '\n'.join(p.read_text(errors='replace') for p in RUNTIME.glob('*.log'))
    check(all(secret not in logs for secret in SECRETS if secret), 'application logs contain no passwords, session values or bearer secrets')
    report = {'passed': len(RESULTS), 'checks': RESULTS, 'database': 'MariaDB', 'topology': 'one controller, unified gateway and two independent nodes (signed and legacy) on one host', 'completed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    (RUNTIME / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(f'ALL {len(RESULTS)} INTEGRATION CHECKS PASSED', flush=True)


if __name__ == '__main__':
    try:
        main()
    finally:
        for process in PROCESSES:
            stop(process)
