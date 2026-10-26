#!/usr/bin/env python3
"""Load a literal KEY=VALUE environment file, then replace this process with DNSDOH."""
import argparse
import os
from pathlib import Path
import stat

p = argparse.ArgumentParser()
p.add_argument('--env', required=True, type=Path)
p.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'target/release/dnsdoh')
p.add_argument('command', nargs='?', default='serve', choices=['serve', 'migrate', 'reset-admin'])
args = p.parse_args()
if stat.S_IMODE(args.env.stat().st_mode) & 0o077:
    p.error('The environment file must be private: chmod 600 <env-file>')
env = os.environ.copy()
for number, line in enumerate(args.env.read_text().splitlines(), 1):
    if not line or line.lstrip().startswith('#'):
        continue
    key, sep, value = line.partition('=')
    if not sep or not key.replace('_', '').isalnum():
        p.error(f'Invalid environment entry on line {number}')
    env[key] = value
os.execve(str(args.binary.resolve()), [str(args.binary.resolve()), args.command], env)
