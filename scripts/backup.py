#!/usr/bin/env python3
"""Create a private, atomic MariaDB logical backup without passwords in argv."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
from urllib.parse import urlsplit, unquote

data = Path(os.environ.get('DNSDOH_DATA_ROOT', '/opt/dnsdoh'))
p = argparse.ArgumentParser()
p.add_argument('--env', type=Path, default=data / 'runtime/controller.env')
p.add_argument('--output', type=Path, default=data / 'runtime/backups')
p.add_argument('--dump', default=shutil.which('mariadb-dump') or 'mariadb-dump')
a = p.parse_args()
os.umask(0o077)
config = dict(line.split('=', 1) for line in a.env.read_text().splitlines() if line and not line.startswith('#'))
db = urlsplit(config['DATABASE_URL'])
if db.scheme != 'mysql' or not db.path.strip('/'):
    p.error('A MariaDB mysql:// database URL is required')
a.output.mkdir(parents=True, exist_ok=True, mode=0o700)
env = os.environ.copy()
env['MYSQL_PWD'] = unquote(db.password or '')
name = 'dnsdoh-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.sql.gz'
destination = a.output / name
command = [a.dump, '--no-defaults', '--host=' + (db.hostname or '127.0.0.1'),
           '--port=' + str(db.port or 3306), '--user=' + unquote(db.username or ''),
           '--single-transaction', '--skip-lock-tables', '--hex-blob', '--default-character-set=utf8mb4',
           unquote(db.path.strip('/'))]
with tempfile.NamedTemporaryFile(dir=a.output, prefix='.pending-', delete=False) as raw:
    temporary = Path(raw.name)
try:
    with tempfile.TemporaryFile(dir=a.output) as errors:
        child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=errors)
        with gzip.open(temporary, 'wb') as target:
            while chunk := child.stdout.read(1024 * 1024):
                target.write(chunk)
        if child.wait() != 0:
            raise RuntimeError('MariaDB backup failed; no completed archive was published')
    # Pair every database snapshot with the original AES key and configuration.
    config_backup = destination.with_suffix(destination.suffix + '.env')
    config_backup.write_bytes(a.env.read_bytes())
    config_backup.chmod(0o600)
    temporary.replace(destination)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(destination.suffix + '.sha256').write_text(digest + '  ' + name + '\n')
    # Keep the most recent 14 completed snapshots; never touch unrelated files.
    for old in sorted(a.output.glob('dnsdoh-*.sql.gz'), reverse=True)[14:]:
        old.unlink()
        old.with_suffix(old.suffix + '.sha256').unlink(missing_ok=True)
        old.with_suffix(old.suffix + '.env').unlink(missing_ok=True)
    print('Backup completed:', destination.name)
finally:
    temporary.unlink(missing_ok=True)
