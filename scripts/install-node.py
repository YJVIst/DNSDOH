#!/usr/bin/env python3
"""DNSDOH unified-domain agent installer (systemd/OpenRC, static Linux agent)."""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path('/opt/dnsdoh-node')
MARKER = '# Managed by DNSDOH node installer\n'
LOG = None

def os_family(release):
    ids = (release.get('ID', '') + ' ' + release.get('ID_LIKE', '')).split()
    if any(x in ids for x in ('debian', 'ubuntu')):
        return 'apt', 'systemd'
    if any(x in ids for x in ('rhel', 'centos', 'fedora', 'rocky', 'almalinux', 'ol', 'amzn')):
        return 'rpm', 'systemd'
    if any(x in ids for x in ('suse', 'opensuse', 'opensuse-leap', 'opensuse-tumbleweed', 'sles')):
        return 'zypper', 'systemd'
    if 'alpine' in ids:
        return 'apk', 'openrc'
    if any(x in ids for x in ('arch', 'manjaro')):
        return 'pacman', 'systemd'
    raise RuntimeError('Unsupported distribution; Debian/Ubuntu, RHEL family, SUSE, Alpine and Arch are supported')

def release_info():
    return dict((k, v.strip().strip('"')) for k, v in (line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line))

def stage(name):
    print('DNSDOH_STAGE ' + name, flush=True)

def run(*args, **kwargs):
    subprocess.run(args, check=True, stdout=LOG, stderr=LOG, **kwargs)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def fetch(url, limit=64 * 1024 * 1024):
    with urllib.request.build_opener(NoRedirect).open(url, timeout=90) as response:
        data = response.read(limit + 1)
        if len(data) > limit:
            raise RuntimeError('Download exceeded limit')
        return data

def managed(path, content, mode=0o644):
    path = Path(path)
    if path.exists() and not path.read_text().startswith(('# Managed by DNSDOH', '#!/sbin/openrc-run\n# Managed by DNSDOH', '#!/bin/sh\n# Managed by DNSDOH')):
        raise RuntimeError('Refusing to replace unmanaged file: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.startswith('#!') else MARKER + content)
    path.chmod(mode)

def install_packages(family):
    packages = ['nginx', 'ca-certificates', 'curl']
    if family == 'apt':
        apt = ['apt-get', '-o', f'Dir::Cache={ROOT}/apt-cache', '-o', f'Dir::State::lists={ROOT}/apt-lists']
        run(*apt, 'update', '-qq')
        run(*apt, 'install', '-y', '--no-install-recommends', *packages)
    elif family == 'rpm':
        manager = shutil.which('dnf') or shutil.which('yum')
        run(manager, '-y', f'--setopt=cachedir={ROOT}/package-cache', 'install', *packages, 'shadow-utils', 'policycoreutils-python-utils')
    elif family == 'zypper':
        run('zypper', '--non-interactive', 'install', '--no-recommends', *packages, 'shadow')
    elif family == 'apk':
        run('apk', '--cache-dir', str(ROOT / 'package-cache'), 'add', *packages, 'openrc')
    else:
        run('pacman', '--noconfirm', '--needed', '--cachedir', str(ROOT / 'package-cache'), '-S', *packages)

def main():
    global LOG, ROOT
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', default=os.environ.get('DNSDOH_NODE_ROOT', '/opt/dnsdoh-node'), help='Node directory (default: /opt/dnsdoh-node)')
    p.add_argument('--controller')
    p.add_argument('--ticket')
    p.add_argument('--node-id')
    p.add_argument('--endpoint')
    p.add_argument('--platform-plan', action='store_true')
    args = p.parse_args()
    if (not re.fullmatch(r'/[a-zA-Z0-9_./-]+', args.root) or
            any(part in ('.', '..') for part in args.root.split('/')) or
            '//' in args.root or args.root.endswith('/') or
            args.root in ('/opt', '/usr', '/var', '/etc', '/mnt', '/srv', '/tmp', '/var/tmp', '/root', '/home') or
            args.root.startswith(('/root/', '/home/', '/tmp/', '/var/tmp/'))):
        raise RuntimeError('Use a dedicated absolute node directory outside /root and /home, without shell metacharacters')
    ROOT = Path(args.root)
    if any(p.is_symlink() for p in (ROOT, *ROOT.parents)):
        raise RuntimeError('Node directory and parents must not be symbolic links')
    family, init = os_family(release_info())
    if args.platform_plan:
        print(json.dumps({'family': family, 'init': init, 'architecture': platform.machine()}))
        return
    if not all((args.controller, args.ticket, args.node_id, args.endpoint)):
        raise RuntimeError('Installation binding is incomplete')
    if os.geteuid() != 0 or platform.machine() != 'x86_64':
        raise RuntimeError('Run as root on Linux x86_64; other architectures require a separately published agent')
    if init == 'systemd' and not Path('/run/systemd/system').exists():
        raise RuntimeError('systemd must be running')
    for value in (args.controller, args.endpoint):
        u = urllib.parse.urlsplit(value)
        if u.scheme != 'https' or u.username or u.password or u.query or u.fragment or u.path or u.port not in (None, 443) or not re.fullmatch(r'[a-zA-Z0-9.-]+', u.hostname or ''):
            raise RuntimeError('Controller and unified endpoint must be HTTPS origins on port 443')
    host = urllib.parse.urlsplit(args.endpoint).hostname
    if len(args.ticket) != 43:
        raise RuntimeError('Invalid installation ticket')
    # Refuse accidental relocation of an existing node and its signed identity.
    for service in (Path('/etc/systemd/system/dnsdoh-node.service'), Path('/etc/init.d/dnsdoh-node')):
        if service.exists() and str(ROOT / 'bin/dnsdoh') not in service.read_text():
            raise RuntimeError('An existing node uses another directory; set DNSDOH_NODE_ROOT to its original path before retrying')
    ROOT.mkdir(parents=True, exist_ok=True)
    ROOT.chmod(0o755)
    if not ROOT.parent.stat().st_mode & 0o001:
        raise RuntimeError(str(ROOT.parent) + ' must allow directory traversal')
    for folder in ('bin', 'run', 'tmp', 'tls', 'package-cache', 'apt-cache', 'apt-lists/partial'):
        path = ROOT / folder
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700 if folder in ('run', 'tmp', 'tls') else 0o755)
    LOG = open(ROOT / 'run/install.log', 'a', buffering=1)
    os.chmod(ROOT / 'run/install.log', 0o600)
    os.environ['TMPDIR'] = str(ROOT / 'tmp')
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    env = ROOT / 'run/node.env'
    if env.exists():
        old = dict(line.split('=', 1) for line in env.read_text().splitlines() if '=' in line)
        if old.get('DNSDOH_NODE_ID') != args.node_id:
            raise RuntimeError('This machine already has a different DNSDOH identity; remove that managed installation first')
        port = int(old['DNSDOH_BIND'].rsplit(':', 1)[1])
    else:
        port = None
        for candidate in range(18081, 18111):
            with socket.socket() as sock:
                try:
                    sock.bind(('127.0.0.1', candidate))
                    port = candidate
                    break
                except OSError:
                    continue
        if port is None:
            raise RuntimeError('No free loopback port in 18081..18110')
    if not shutil.which('nginx'):
        for used_port in (80, 443):
            with socket.socket() as sock:
                try:
                    sock.bind(('0.0.0.0', used_port))
                except OSError:
                    raise RuntimeError(f'Port {used_port} belongs to another HTTPS service; configure an nginx integration before installing')
    stage('packages')
    install_packages(family)
    # Alpine's default nginx config includes http.d; add only our dedicated include.
    if family == 'apk':
        managed('/etc/nginx/http.d/dnsdoh-include.conf', 'include /etc/nginx/conf.d/dnsdoh-node.conf;\n')
        Path('/etc/nginx/conf.d').mkdir(parents=True, exist_ok=True)
        if not Path('/etc/nginx/conf.d/dnsdoh-node.conf').exists():
            managed('/etc/nginx/conf.d/dnsdoh-node.conf', '')
    configuration = Path('/etc/nginx/conf.d/dnsdoh-node.conf')
    if configuration.exists() and not configuration.read_text().startswith(MARKER):
        raise RuntimeError('DNSDOH nginx filename belongs to another application')
    dump = subprocess.run(['nginx', '-T'], capture_output=True, text=True, check=True).stdout
    if re.search(r'\bserver_name\s+[^;]*\b' + re.escape(host) + r'\b', dump) and (not configuration.exists() or host not in configuration.read_text()):
        raise RuntimeError('Unified hostname already belongs to another nginx virtual host')
    stage('binary')
    manifest = json.loads(fetch(args.controller + '/downloads/latest.json', 16384))
    artifact = manifest['file']
    if not re.fullmatch(r'dnsdoh-[a-zA-Z0-9._-]+', artifact) or manifest['platform'] != 'linux-x86_64' or manifest.get('libc') != 'musl':
        raise RuntimeError('A static musl x86_64 agent artifact must be published by the controller')
    binary = fetch(args.controller + '/downloads/' + artifact)
    if hashlib.sha256(binary).hexdigest() != manifest['sha256']:
        raise RuntimeError('Binary SHA256 mismatch')
    candidate = ROOT / 'bin/dnsdoh.new'
    candidate.write_bytes(binary)
    candidate.chmod(0o755)
    run(str(candidate), '--version')
    if subprocess.run(['id', '-u', 'dnsdoh-node'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        if family == 'apk':
            run('addgroup', '-S', 'dnsdoh-node')
            run('adduser', '-S', '-D', '-H', '-G', 'dnsdoh-node', '-s', '/sbin/nologin', 'dnsdoh-node')
        else:
            run('useradd', '--system', '--home-dir', str(ROOT), '--shell', '/usr/sbin/nologin', 'dnsdoh-node')
    if shutil.which('getenforce') and subprocess.check_output(['getenforce'], text=True).strip() != 'Disabled':
        run('setsebool', '-P', 'httpd_can_network_connect', '1')
        for label, pattern in [('cert_t', str(ROOT) + '/tls(/.*)?'), ('bin_t', str(ROOT) + '/bin(/.*)?')]:
            result = subprocess.run(['semanage', 'fcontext', '-a', '-t', label, pattern], stdout=LOG, stderr=LOG)
            if result.returncode:
                run('semanage', 'fcontext', '-m', '-t', label, pattern)
        run('restorecon', '-RF', str(ROOT / 'bin'), str(ROOT / 'tls'))
    stage('enrollment')
    temp_env = ROOT / 'run/node.env.new'
    temp_env.unlink(missing_ok=True)
    run(str(candidate), 'enroll', '--controller', args.controller, '--node-id', args.node_id, '--endpoint', args.endpoint, '--bind', f'127.0.0.1:{port}', '--output', str(temp_env), input=args.ticket, text=True)
    args.ticket = ''
    candidate.replace(ROOT / 'bin/dnsdoh')
    temp_env.replace(env)
    maintain = ROOT / 'bin/maintain.sh'
    managed(maintain, f'''#!/bin/sh
+# Managed by DNSDOH node installer
+set -eu
+set -a
+. {env}
+set +a
+exec {ROOT}/bin/dnsdoh node-maintain --root {ROOT}
+'''.replace('\n+', '\n'), 0o700)
    if init == 'systemd':
        managed('/etc/systemd/system/dnsdoh-node.service', f'''[Unit]
+Description=DNSDOH signed direct resolver
+After=network-online.target
+Wants=network-online.target
+RequiresMountsFor={ROOT}
+[Service]
+User=dnsdoh-node
+Group=dnsdoh-node
+EnvironmentFile={env}
+ExecStart={ROOT}/bin/dnsdoh serve
+Restart=always
+RestartSec=3
+NoNewPrivileges=true
+ProtectSystem=strict
+ProtectHome=true
+UMask=0077
+StandardOutput=append:{ROOT}/run/node.log
+StandardError=append:{ROOT}/run/node.log
+[Install]
+WantedBy=multi-user.target
+'''.replace('\n+', '\n'))
        managed('/etc/systemd/system/dnsdoh-node-maintain.service', f'''[Unit]
+Description=Apply DNSDOH unified HTTPS domains
+After=network-online.target nginx.service
+RequiresMountsFor={ROOT}
+[Service]
+Type=oneshot
+EnvironmentFile={env}
+ExecStart={ROOT}/bin/dnsdoh node-maintain --root {ROOT}
+UMask=0077
+StandardOutput=append:{ROOT}/run/maintain.log
+StandardError=append:{ROOT}/run/maintain.log
+'''.replace('\n+', '\n'))
        managed('/etc/systemd/system/dnsdoh-node-maintain.timer', '''[Unit]
+Description=Refresh DNSDOH domain certificates
+[Timer]
+OnBootSec=10s
+OnUnitActiveSec=20s
+AccuracySec=1s
+[Install]
+WantedBy=timers.target
+'''.replace('\n+', '\n'))
        run('systemctl', 'daemon-reload')
        if Path('/etc/systemd/system/dnsdoh-node-cert.timer').exists():
            run('systemctl', 'disable', '--now', 'dnsdoh-node-cert.timer')
        run('systemctl', 'enable', '--now', 'nginx')
        run('systemctl', 'enable', 'dnsdoh-node.service')
        run('systemctl', 'restart', 'dnsdoh-node.service')
        run('systemctl', 'enable', '--now', 'dnsdoh-node-maintain.timer')
    else:
        managed('/etc/init.d/dnsdoh-node', f'''#!/sbin/openrc-run
+# Managed by DNSDOH node installer
+description="DNSDOH signed direct resolver"
+supervisor="supervise-daemon"
+command="{ROOT}/bin/dnsdoh"
+command_args="serve"
+command_user="dnsdoh-node:dnsdoh-node"
+output_log="{ROOT}/run/node.log"
+error_log="{ROOT}/run/node.log"
+respawn_delay=3
+depend() {{ need net; }}
+start_pre() {{ set -a; . {env}; set +a; }}
+'''.replace('\n+', '\n'), 0o755)
        run('rc-update', 'add', 'nginx', 'default')
        run('rc-service', 'nginx', 'start')
        run('rc-update', 'add', 'dnsdoh-node', 'default')
        run('rc-service', 'dnsdoh-node', 'restart')
        cron = Path('/etc/crontabs/root')
        line = f'* * * * * {maintain} >>{ROOT}/run/maintain.log 2>&1 # DNSDOH certificate refresh\n'
        previous = cron.read_text() if cron.exists() else ''
        if line not in previous:
            cron.write_text(previous.rstrip() + '\n' + line)
            cron.chmod(0o600)
        run('rc-update', 'add', 'crond', 'default')
        run('rc-service', 'crond', 'start')
    if shutil.which('firewall-cmd') and subprocess.run(['firewall-cmd', '--state'], stdout=LOG, stderr=LOG).returncode == 0:
        run('firewall-cmd', '--add-service=https')
        run('firewall-cmd', '--permanent', '--add-service=https')
    stage('tls')
    for _ in range(15):
        result = subprocess.run([str(maintain)], stdout=LOG, stderr=LOG)
        if result.returncode == 0:
            break
        time.sleep(4)
    else:
        raise RuntimeError('Unified certificate could not be applied; inspect install.log and domain setup')
    for _ in range(20):
        try:
            value = json.loads(fetch(f'http://127.0.0.1:{port}/readyz', 4096))
            if value.get('status') == 'ready' and value.get('node_id') == args.node_id:
                run(str(maintain))
                stage('ready')
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError('Installed node did not become ready')

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('DNSDOH installation failed; check ' + str(ROOT / 'run/install.log'), file=sys.stderr)
        if LOG:
            LOG.write('Failure category: ' + type(error).__name__ + '\n')
            if isinstance(error, RuntimeError):
                LOG.write(str(error) + '\n')
        sys.exit(1)
