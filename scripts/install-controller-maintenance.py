#!/usr/bin/env python3
"""Install root-only certificate application timer for the prepared controller."""
from pathlib import Path
import os,secrets,shutil,subprocess
root=Path(__file__).resolve().parents[1]
p=Path('/mnt/youlin-data/runtime/controller.env')
if os.geteuid()!=0:raise SystemExit('Run as root')
s=p.read_text()
if not any(line.startswith('DNSDOH_MASTER_KEY=') and 'REPLACE_' not in line for line in s.splitlines()):
 s='\n'.join(line for line in s.splitlines() if not line.startswith('DNSDOH_MASTER_KEY='))+'\n'
 s+='\nDNSDOH_MASTER_KEY='+secrets.token_urlsafe(32)+'\n';p.write_text(s);p.chmod(0o600)
for name in ['dnsdoh-domain-maintain.service','dnsdoh-domain-maintain.timer']:
 shutil.copy2(root/'deploy'/name,Path('/etc/systemd/system')/name)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','dnsdoh-domain-maintain.timer'],check=True)
print('Controller encryption key and certificate maintenance are configured; restart controller to load its key')
