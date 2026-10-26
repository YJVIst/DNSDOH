#!/usr/bin/env python3
"""Manage installed systemd units, or prepared manual processes when not installed.
Does not recreate credentials. MariaDB has its own systemd unit.
"""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

p = argparse.ArgumentParser()
p.add_argument('action', choices=['start', 'stop', 'restart', 'status'])
p.add_argument('--runtime', type=Path, default=Path('/mnt/youlin-data/runtime'))
p.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'target/release/dnsdoh')
a = p.parse_args()
names = ['controller', 'node-a', 'node-b']
if a.runtime.resolve() == Path('/mnt/youlin-data/runtime') and Path('/etc/systemd/system/dnsdoh@.service').exists():
    units = ['dnsdoh@' + name + '.service' for name in names]
    if a.action != 'status':
        subprocess.run(['systemctl', a.action, *units], check=True)
    for name, unit in zip(names, units):
        state = subprocess.check_output(['systemctl', 'show', unit, '-p', 'ActiveState', '--value'], text=True).strip()
        pid = subprocess.check_output(['systemctl', 'show', unit, '-p', 'MainPID', '--value'], text=True).strip()
        print(f'{name}: {state} (systemd pid {pid})')
    sys.exit(0)
def running(name):
    try:
        pid = int((a.runtime / (name + '.pid')).read_text())
        cmdline = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        if cmdline and Path(os.fsdecode(cmdline[0])).name == 'dnsdoh' and b'serve' in cmdline:
            return pid
    except (OSError, ValueError):
        pass
    return None
if a.action in ('stop', 'restart'):
    for name in reversed(names):
        pid = running(name)
        if pid:
            os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and any(running(n) for n in names):
        time.sleep(.1)
    if any(running(n) for n in names):
        p.exit(1, 'A process has not stopped; inspect it before restarting.\n')
if a.action in ('start', 'restart'):
    for name in names:
        if running(name):
            continue
        source = a.runtime / (name + '.env')
        if source.stat().st_mode & 0o077:
            p.error('Environment files must be mode 600')
        env = os.environ.copy()
        env.update(dict(line.split('=', 1) for line in source.read_text().splitlines() if line and not line.startswith('#')))
        with (a.runtime / (name + '.log')).open('ab') as log:
            child = subprocess.Popen([str(a.binary.resolve()), 'serve'], env=env, stdout=log, stderr=log, start_new_session=True)
        (a.runtime / (name + '.pid')).write_text(str(child.pid))
    time.sleep(.5)
for name in names:
    pid = running(name)
    print(f'{name}: ' + (f'running (pid {pid})' if pid else 'stopped'))
