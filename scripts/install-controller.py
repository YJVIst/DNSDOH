#!/usr/bin/env python3
"""Install an isolated DNSDOH controller using only a pre-pointed management domain."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

DATA = Path('/opt/dnsdoh')
PROJECT = DATA / 'DNSDOH'
RUNTIME = DATA / 'runtime'
HOSTING = DATA / 'hosting'
INSTALL = DATA / 'installer'
STATE = RUNTIME / 'install-controller.json'
ENV = RUNTIME / 'controller.env'
NGINX = Path('/etc/nginx/conf.d/dnsdoh-admin.conf')
MARKER = '# Managed by DNSDOH controller installer\n'
LOG = None


def configure_paths(value):
    global DATA, PROJECT, RUNTIME, HOSTING, INSTALL, STATE, ENV
    if (not re.fullmatch(r'/[a-zA-Z0-9_./-]+', value) or
            any(part in ('.', '..') for part in value.split('/')) or
            '//' in value or value.endswith('/') or
            value in ('/opt', '/usr', '/var', '/etc', '/mnt', '/srv', '/tmp', '/var/tmp', '/home') or
            value.startswith(('/root/', '/home/', '/tmp/', '/var/tmp/')) or value == '/root'):
        raise ValueError('安装目录须为独立绝对路径，仅含字母、数字、下划线、点、斜线和短横线；不要使用 /root、/home 或临时目录（服务隔离不允许访问）')
    path = Path(value)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('安装目录及父目录不能是符号链接')
    DATA = path
    PROJECT, RUNTIME, HOSTING, INSTALL = (DATA / p for p in ('DNSDOH', 'runtime', 'hosting', 'installer'))
    STATE, ENV = RUNTIME / 'install-controller.json', RUNTIME / 'controller.env'


def render_template(source, name):
    return (source / 'deploy' / name).read_text().replace('/opt/dnsdoh', str(DATA))


def domain_name(value):
    value = value.strip().rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('请输入管理域名，不能填写 IP 地址')
    if len(value) > 253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
        raise ValueError('管理域名格式错误，请勿包含 https://、端口或路径')
    if value.endswith(('.localhost', '.local', '.invalid', '.test')):
        raise ValueError('必须使用可公开验证的真实域名')
    return value


def supported_os(release):
    return (release.get('ID') == 'debian' and release.get('VERSION_ID') in ('12', '13')) or (release.get('ID') == 'ubuntu' and release.get('VERSION_ID') in ('22.04', '24.04'))


def parse_env(path):
    return dict(l.split('=', 1) for l in path.read_text().splitlines() if l and not l.startswith('#'))


def atomic(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError('拒绝替换符号链接：' + str(path))
    tmp = path.with_name(path.name + '.dnsdoh-new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(content.encode() if isinstance(content, str) else content)
    tmp.chmod(mode)
    tmp.replace(path)


def managed(path, content):
    path = Path(path)
    if path.exists() and not path.read_text().startswith(MARKER):
        raise RuntimeError('同名配置不属于本安装器，拒绝覆盖：' + str(path))
    atomic(path, MARKER + content, 0o644)


def run(*args, **kwargs):
    subprocess.run(args, check=True, stdout=LOG, stderr=LOG, **kwargs)


def stage(state, name):
    state['stage'] = name
    atomic(STATE, json.dumps(state, ensure_ascii=False, indent=2))
    print('▶ ' + name, flush=True)


def user(name):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        run('useradd', '--system', '--no-create-home', '--home-dir', str(DATA), '--shell', '/usr/sbin/nologin', name)
        return pwd.getpwnam(name)


def owned_dir(path, who, mode=0o750):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    os.chown(path, who.pw_uid, who.pw_gid)


def free_port(port):
    with socket.socket() as s:
        try:
            s.bind(('127.0.0.1', port))
        except OSError:
            raise RuntimeError(f'回环端口 {port} 已被其他服务使用；未改动已有服务')


def controller_env(domain):
    password = secrets.token_urlsafe(32)
    return {
        'DATABASE_URL': f'mysql://dnsdoh:{password}@127.0.0.1:13306/dnsdoh',
        'DNSDOH_MODE': 'controller', 'DNSDOH_BIND': '127.0.0.1:18080',
        'DNSDOH_PUBLIC_URL': 'https://' + domain, 'DNSDOH_DOH_URL': 'https://' + domain,
        'DNSDOH_ADMIN_USERNAME': 'admin_' + secrets.token_hex(3),
        'DNSDOH_ADMIN_PASSWORD': secrets.token_urlsafe(24),
        'DNSDOH_MASTER_KEY': secrets.token_urlsafe(32),
        'DNSDOH_TRUST_PROXY': 'true', 'RUST_LOG': 'dnsdoh=info',
    }


def ipv6_listener(port, ssl=False):
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(('::1', 0))
    except OSError:
        return ''
    return f" listen [::]:{port}{' ssl' if ssl else ''};\n"


def http_config(domain, tls=False):
    text = f'''server {{
 listen 80;
{ipv6_listener(80)} server_name {domain};
 access_log off;
 error_log /dev/null crit;
 location ^~ /.well-known/acme-challenge/ {{ root {HOSTING}/acme; default_type text/plain; try_files $uri =404; }}
 location /dns-query/ {{ return 400; }}
 location / {{ {'return 308 https://$host$request_uri;' if tls else 'return 503;'} }}
}}
'''
    if tls:
        text += f'''server {{
 listen 443 ssl;
{ipv6_listener(443, True)} server_name {domain};
 ssl_certificate {RUNTIME}/letsencrypt/live/dnsdoh-admin/fullchain.pem;
 ssl_certificate_key {RUNTIME}/letsencrypt/live/dnsdoh-admin/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 ssl_session_tickets off;
 access_log off;
 error_log /dev/null crit;
 client_max_body_size 64k;
 client_body_buffer_size 64k;
 client_body_timeout 10s;
 add_header Strict-Transport-Security "max-age=31536000" always;
 location /downloads/ {{ alias {HOSTING}/downloads/; autoindex off; default_type application/octet-stream; add_header Cache-Control "no-store"; }}
 location / {{
  proxy_pass http://127.0.0.1:18080;
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-Proto https;
  proxy_read_timeout 30s;
  proxy_buffering off;
  proxy_cache off;
 }}
}}
'''
    return text


def apply_nginx(domain, tls):
    old = NGINX.read_bytes() if NGINX.exists() else None
    managed(NGINX, http_config(domain, tls))
    try:
        run('nginx', '-t')
        run('systemctl', 'enable', '--now', 'nginx')
        run('systemctl', 'reload', 'nginx')
    except Exception:
        if old is None: NGINX.unlink(missing_ok=True)
        else: atomic(NGINX, old, 0o644)
        raise


def wait_http(url, expected=None, timeout=60):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with opener.open(url, timeout=8) as response:
                body = response.read(1024 * 1024)
            if expected is None or body == expected:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise RuntimeError('域名验证未通过：请检查域名 A/AAAA 是否指向本机、80/443 是否开放，然后使用同一域名重试')


def sql(query):
    # SQL may contain generated passwords: never copy its stderr into logs.
    result = subprocess.run(['mariadb', '--no-defaults', '--socket=' + str(RUNTIME / 'mariadb-run/mariadb.sock'), '-u', 'root'], input=query, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError('独立 MariaDB 初始化失败；已隐藏包含凭据的 SQL 诊断')


def unit(name, body):
    managed(Path('/etc/systemd/system') / name, body)


def install_units(source):
    unit('dnsdoh-mariadb.service', f'''[Unit]
Description=DNSDOH isolated MariaDB
After=network.target
RequiresMountsFor={DATA}
[Service]
Type=simple
User=dnsdoh-db
Group=dnsdoh-db
ExecStart={shutil.which('mariadbd')} --defaults-file={RUNTIME}/mariadb.cnf
Restart=on-failure
RestartSec=3
TimeoutStopSec=120
UMask=0077
[Install]
WantedBy=multi-user.target
''')
    controller = render_template(source, 'dnsdoh@.service').replace('After=network-online.target', 'After=network-online.target dnsdoh-mariadb.service').replace('Wants=network-online.target', 'Wants=network-online.target dnsdoh-mariadb.service')
    unit('dnsdoh@.service', controller)
    for name in ('dnsdoh-domain-maintain.service', 'dnsdoh-domain-maintain.timer'):
        unit(name, render_template(source, name))
    hook = PROJECT / 'scripts/reload-nginx.sh'
    atomic(hook, '#!/bin/sh\nset -eu\n/usr/sbin/nginx -t\n/bin/systemctl reload nginx\n', 0o755)
    unit('dnsdoh-admin-cert.service', f'''[Unit]
Description=Renew DNSDOH management HTTPS certificate
After=network-online.target nginx.service
RequiresMountsFor={DATA}
[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --cert-name dnsdoh-admin --config-dir {RUNTIME}/letsencrypt --work-dir {RUNTIME}/certbot-work --logs-dir {RUNTIME}/certbot-logs --deploy-hook {hook}
UMask=0077
''')
    unit('dnsdoh-admin-cert.timer', '''[Unit]
Description=Check DNSDOH management certificate twice daily
[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
''')
    unit('dnsdoh-backup.service', f'''[Unit]
Description=Back up DNSDOH MariaDB and matching encryption configuration
RequiresMountsFor={DATA}
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {PROJECT}/scripts/backup.py --env {ENV} --output {RUNTIME}/backups --dump {shutil.which('mariadb-dump')}
UMask=0077
''')
    unit('dnsdoh-backup.timer', '''[Unit]
Description=Daily DNSDOH backup
[Timer]
OnCalendar=daily
RandomizedDelaySec=300
Persistent=true
[Install]
WantedBy=timers.target
''')
    run('systemctl', 'daemon-reload')


def install(args):
    global LOG
    if os.geteuid() != 0 or platform.machine() != 'x86_64':
        raise RuntimeError('请在 Linux x86_64 服务器使用 root 执行')
    release = dict((k, v.strip('"')) for k, v in (l.split('=', 1) for l in Path('/etc/os-release').read_text().splitlines() if '=' in l))
    if not supported_os(release) or not Path('/run/systemd/system').exists():
        raise RuntimeError('主控一键安装支持运行 systemd 的 Debian 12/13、Ubuntu 22.04/24.04')
    if not args.domain:
        with open('/dev/tty', 'r+') as tty:
            tty.write('请输入管理域名（已解析到本机，例如 admin.example.com）：'); tty.flush()
            args.domain = tty.readline().strip()
    domain = domain_name(args.domain)
    source = Path(args.bundle or Path(__file__).resolve().parents[1]).resolve()
    binary = source / 'agent/dnsdoh'
    if not binary.is_file():
        raise RuntimeError('缺少静态发布包；请使用根目录 install.sh，或传入 --bundle 已解压的发布目录')
    if not STATE.exists():
        if ENV.exists():
            raise RuntimeError('发现既有主控配置，拒绝覆盖；本脚本用于新装或恢复本安装器的安装')
        for port in (18080, 13306): free_port(port)
        if NGINX.exists(): raise RuntimeError('已有同名 Nginx 配置，拒绝覆盖')
        for name in ('dnsdoh-mariadb.service', 'dnsdoh@.service', 'dnsdoh-domain-maintain.service', 'dnsdoh-domain-maintain.timer', 'dnsdoh-backup.service', 'dnsdoh-backup.timer', 'dnsdoh-admin-cert.service', 'dnsdoh-admin-cert.timer'):
            if (Path('/etc/systemd/system') / name).exists(): raise RuntimeError('发现既有 DNSDOH 服务，拒绝覆盖：' + name + '；重试旧安装时请通过 --data-dir 指定原安装目录，本脚本不会自动迁移数据')
    else:
        state = json.loads(STATE.read_text())
        if state['domain'] != domain:
            raise RuntimeError('该主控已绑定另一管理域名；重试须使用原域名，域名迁移请另行处理')
        if not ENV.exists(): raise RuntimeError('原加密配置丢失，请恢复 controller.env 后再试')
    if shutil.which('nginx'):
        result = subprocess.run(['nginx', '-T'], text=True, capture_output=True, check=True)
        # Exclude only the block from our own generated file, not other virtual hosts.
        config = re.sub(r'# configuration file ' + re.escape(str(NGINX)) + r':\n.*?(?=\n# configuration file |\Z)', '', result.stdout, flags=re.S)
        if re.search(r'\bserver_name\s+[^;]*?(?<![a-z0-9.-])' + re.escape(domain) + r'(?![a-z0-9.-])', config):
            raise RuntimeError('该域名已经属于其他 Nginx 配置，拒绝覆盖')
    elif not STATE.exists():
        for port in (80, 443): free_port(port)
    if args.preflight:
        print(json.dumps({'domain': domain, 'platform': release['ID'] + ' ' + release['VERSION_ID'], 'data': str(DATA), 'existing_installation': STATE.exists()}, ensure_ascii=False)); return
    new_data_root = not DATA.exists()
    DATA.mkdir(parents=True, exist_ok=True)
    if new_data_root: DATA.chmod(0o755)
    if not DATA.stat().st_mode & 0o001: raise RuntimeError('数据目录须允许服务用户穿越（目录执行权限）')
    RUNTIME.mkdir(exist_ok=True); RUNTIME.chmod(0o711)
    INSTALL.mkdir(exist_ok=True); INSTALL.chmod(0o700)
    for folder in ('tmp', 'apt-cache', 'apt-lists/partial'): (INSTALL / folder).mkdir(parents=True, exist_ok=True)
    os.environ.update(TMPDIR=str(INSTALL / 'tmp'), DEBIAN_FRONTEND='noninteractive')
    LOG = open(INSTALL / 'controller-install.log', 'a'); os.chmod(INSTALL / 'controller-install.log', 0o600)
    lock = open(INSTALL / 'controller.lock', 'a')
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: raise RuntimeError('已有主控安装任务正在执行')
    if STATE.exists(): state = json.loads(STATE.read_text()); env = parse_env(ENV)
    else:
        state = {'schema': 1, 'domain': domain, 'data_dir': str(DATA), 'stage': '初始化'}
        env = controller_env(domain)
        atomic(ENV, ''.join(k + '=' + v + '\n' for k, v in env.items()))
        atomic(STATE, json.dumps(state))
    atomic(RUNTIME / '管理员登录信息.txt', 'DNSDOH 管理员初始登录信息\n\n后台地址：https://' + domain + '\n管理员账号：' + env['DNSDOH_ADMIN_USERNAME'] + '\n管理员初始密码：' + env['DNSDOH_ADMIN_PASSWORD'] + '\n\n若已在后台修改密码，请使用修改后的密码。首次登录请完成 DNS 供应商向导。\n')
    stage(state, '安装 Nginx、MariaDB 核心和 Certbot')
    apt = ['apt-get', '-o', f'Dir::Cache={INSTALL}/apt-cache', '-o', f'Dir::State::lists={INSTALL}/apt-lists']
    run(*apt, 'update', '-qq')
    run(*apt, 'install', '-y', '--no-install-recommends', 'nginx', 'ca-certificates', 'curl', 'python3', 'certbot', 'mariadb-server-core', 'mariadb-client')
    app_user = user('dnsdoh'); db_user = user('dnsdoh-db')
    for directory in ('mariadb', 'mariadb-run', 'mariadb-tmp'): owned_dir(RUNTIME / directory, db_user)
    owned_dir(RUNTIME / 'tmp', app_user)
    for folder in (PROJECT, PROJECT / 'target', PROJECT / 'target/release', PROJECT / 'scripts', HOSTING, HOSTING / 'downloads', HOSTING / 'acme', HOSTING / 'acme/.well-known', HOSTING / 'acme/.well-known/acme-challenge'):
        folder.mkdir(parents=True, exist_ok=True); folder.chmod(0o755)
    stage(state, '安装静态主控及节点发布文件')
    run(str(binary), '--version')
    version = subprocess.check_output([binary, '--version'], text=True).strip().split()[-1]
    if not re.fullmatch(r'\d+\.\d+\.\d+', version): raise RuntimeError('发布版本不合法')
    state['version'] = version
    atomic(PROJECT / 'target/release/dnsdoh', binary.read_bytes(), 0o755)
    atomic(PROJECT / 'scripts/backup.py', (source / 'scripts/backup.py').read_bytes(), 0o755)
    artifact = 'dnsdoh-' + version + '-linux-x86_64-musl'
    atomic(HOSTING / 'downloads' / artifact, binary.read_bytes(), 0o644)
    atomic(HOSTING / 'downloads/latest.json', json.dumps({'version': version, 'platform': 'linux-x86_64', 'libc': 'musl', 'file': artifact, 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}), 0o644)
    atomic(RUNTIME / 'mariadb.cnf', f'''[mariadbd]
basedir=/usr
datadir={RUNTIME}/mariadb
socket={RUNTIME}/mariadb-run/mariadb.sock
pid-file={RUNTIME}/mariadb-run/mariadb.pid
log-error={RUNTIME}/mariadb-run/error.log
tmpdir={RUNTIME}/mariadb-tmp
bind-address=127.0.0.1
port=13306
skip-name-resolve
character-set-server=utf8mb4
collation-server=utf8mb4_unicode_ci
innodb-buffer-pool-size=128M
''', 0o640)
    os.chown(RUNTIME / 'mariadb.cnf', 0, db_user.pw_gid)
    stage(state, '初始化独立 MariaDB 与受保护服务')
    if not (RUNTIME / 'mariadb/.dnsdoh-initialized').exists():
        run('mariadb-install-db', '--no-defaults', '--basedir=/usr', '--datadir=' + str(RUNTIME / 'mariadb'), '--user=dnsdoh-db', '--auth-root-authentication-method=socket', '--skip-test-db', env={**os.environ, 'TMPDIR': str(RUNTIME / 'mariadb-tmp')})
        atomic(RUNTIME / 'mariadb/.dnsdoh-initialized', 'initialized\n')
    install_units(source)
    run('systemctl', 'enable', '--now', 'dnsdoh-mariadb.service')
    for attempt in range(60):
        try: sql('SELECT 1'); break
        except RuntimeError:
            if attempt == 59: raise
            time.sleep(1)
    from urllib.parse import urlsplit
    password = urlsplit(env['DATABASE_URL']).password
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', password or ''): raise RuntimeError('保存的数据库凭据格式错误')
    sql("CREATE DATABASE IF NOT EXISTS dnsdoh CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS 'dnsdoh'@'127.0.0.1' IDENTIFIED BY '" + password + "'; ALTER USER 'dnsdoh'@'127.0.0.1' IDENTIFIED BY '" + password + "'; GRANT ALL PRIVILEGES ON dnsdoh.* TO 'dnsdoh'@'127.0.0.1';")
    run('systemctl', 'enable', 'dnsdoh@controller.service')
    run('systemctl', 'restart', 'dnsdoh@controller.service')
    wait_http('http://127.0.0.1:18080/readyz')
    stage(state, '验证管理域名并申请 HTTPS 证书')
    cert_exists = (RUNTIME / 'letsencrypt/live/dnsdoh-admin/fullchain.pem').exists()
    apply_nginx(domain, cert_exists)
    probe = secrets.token_urlsafe(24)
    proof = HOSTING / 'acme/.well-known/acme-challenge' / ('dnsdoh-preflight-' + probe)
    atomic(proof, probe, 0o644)
    try: wait_http('http://' + domain + '/.well-known/acme-challenge/' + proof.name, probe.encode())
    finally: proof.unlink(missing_ok=True)
    valid = cert_exists and subprocess.run(['openssl', 'x509', '-checkend', '2592000', '-noout', '-in', str(RUNTIME / 'letsencrypt/live/dnsdoh-admin/fullchain.pem')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if not valid:
        run('certbot', 'certonly', '--non-interactive', '--agree-tos', '--register-unsafely-without-email', '--webroot', '-w', str(HOSTING / 'acme'), '--cert-name', 'dnsdoh-admin', '-d', domain, '--keep-until-expiring', '--config-dir', str(RUNTIME / 'letsencrypt'), '--work-dir', str(RUNTIME / 'certbot-work'), '--logs-dir', str(RUNTIME / 'certbot-logs'))
    apply_nginx(domain, True)
    wait_http('https://' + domain + '/readyz')
    stage(state, '启用证书维护、备份和开机启动')
    run('systemctl', 'enable', '--now', 'dnsdoh-admin-cert.timer', 'dnsdoh-domain-maintain.timer', 'dnsdoh-backup.timer')
    run('systemctl', 'start', 'dnsdoh-backup.service')
    stage(state, '安装完成')
    print('\n后台：https://' + domain + '\n管理员账号和随机密码已保存：' + str(RUNTIME / '管理员登录信息.txt') + '\n查看命令：cat ' + str(RUNTIME / '管理员登录信息.txt') + '\n首次登录后完成 DNS 供应商向导，即可配置统一 DoH 域名和节点。', flush=True)
    lock.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data-dir', default=os.environ.get('DNSDOH_DATA_ROOT', '/opt/dnsdoh'), help='Installation and data directory (default: /opt/dnsdoh)')
    p.add_argument('--domain', help='Management hostname already pointing to this server')
    p.add_argument('--bundle', help='Extracted release directory for offline-artifact installation')
    p.add_argument('--preflight', action='store_true', help='Read-only validation; no installation')
    args = p.parse_args()
    try:
        configure_paths(args.data_dir)
        install(args)
    except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as exc:
        # subprocess diagnostics can contain credentials: show only our fixed stage/error.
        message = str(exc) if isinstance(exc, (RuntimeError, ValueError)) else '系统步骤失败，请检查受保护的安装日志'
        print('安装未完成：' + message + '\n修复后可使用同一管理域名重新运行，已有密码和数据库会保留。日志：' + str(INSTALL / 'controller-install.log'), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__': main()
