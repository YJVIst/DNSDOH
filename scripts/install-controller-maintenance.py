#!/usr/bin/env python3
"""Install root-only certificate application timer for the prepared controller."""
from pathlib import Path
import os,secrets,subprocess,importlib.util,argparse
root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--data-dir', default=os.environ.get('DNSDOH_DATA_ROOT', '/opt/dnsdoh'))
args=parser.parse_args()
spec=importlib.util.spec_from_file_location('installer',root/'scripts/install-controller.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
installer.configure_paths(args.data_dir)
p=installer.ENV
if os.geteuid()!=0:raise SystemExit('Run as root')
s=p.read_text()
if not any(line.startswith('DNSDOH_MASTER_KEY=') and 'REPLACE_' not in line for line in s.splitlines()):
 s='\n'.join(line for line in s.splitlines() if not line.startswith('DNSDOH_MASTER_KEY='))+'\n'
 s+='\nDNSDOH_MASTER_KEY='+secrets.token_urlsafe(32)+'\n';p.write_text(s);p.chmod(0o600)
for name in ['dnsdoh-domain-maintain.service','dnsdoh-domain-maintain.timer']:
 installer.managed(Path('/etc/systemd/system')/name,installer.render_template(root,name))
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','dnsdoh-domain-maintain.timer'],check=True)
print('Controller encryption key and certificate maintenance are configured; restart controller to load its key')
