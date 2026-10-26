#!/usr/bin/env python3
"""Query a private DoH endpoint without putting its bearer token in argv or logs."""
import argparse
import base64
import getpass
import ipaddress
import json
import os
import secrets
import ssl
import struct
import urllib.error
import urllib.request

p = argparse.ArgumentParser()
p.add_argument('--endpoint', required=True, help='HTTPS origin, without /dns-query or a token')
p.add_argument('--name', required=True)
p.add_argument('--type', choices=['A', 'AAAA'], default='A')
p.add_argument('--method', choices=['GET', 'POST'], default='POST')
p.add_argument('--ca-cert', help='Optional local test CA certificate')
a = p.parse_args()
token = os.environ.get('DNSDOH_TOKEN') or getpass.getpass('DoH access token (hidden): ')
name = a.name.rstrip('.').encode('idna').decode('ascii')
identifier = secrets.randbelow(65536)
wire = struct.pack('!HHHHHH', identifier, 0x100, 1, 0, 0, 0)
wire += b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'
wire += struct.pack('!HH', 1 if a.type == 'A' else 28, 1)
url = a.endpoint.rstrip('/') + '/dns-query/' + token
if a.method == 'GET':
    url += '?dns=' + base64.urlsafe_b64encode(wire).decode().rstrip('=')
request = urllib.request.Request(url, method=a.method, data=wire if a.method == 'POST' else None,
    headers={'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'})
try:
    with urllib.request.urlopen(request, context=ssl.create_default_context(cafile=a.ca_cert), timeout=10) as response:
        body = response.read()
except urllib.error.HTTPError as error:
    p.exit(1, f'DoH request rejected with HTTP {error.code}\n')
except Exception:
    p.exit(1, 'DoH connection or TLS validation failed\n')
def skip_name(pos):
    while body[pos]:
        if body[pos] & 0xc0 == 0xc0:
            return pos + 2
        pos += body[pos] + 1
    return pos + 1
try:
    response_id, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', body[:12])
    assert response_id == identifier and flags & 0x8000
    pos = 12
    for _ in range(questions):
        pos = skip_name(pos) + 4
    values = []
    for _ in range(answers):
        pos = skip_name(pos)
        kind, cls, ttl, length = struct.unpack('!HHIH', body[pos:pos+10]); pos += 10
        if kind in (1, 28):
            values.append({'address': str(ipaddress.ip_address(body[pos:pos+length])), 'ttl': ttl})
        pos += length
    print(json.dumps({'domain': name, 'rcode': flags & 15, 'answers': values}, ensure_ascii=False, indent=2))
except Exception:
    p.exit(1, 'Malformed DNS response\n')
