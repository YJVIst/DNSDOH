#!/usr/bin/env python3
"""Package tracked/untracked nonignored project sources; never include runtime data."""
import hashlib
import subprocess
import shutil
import tarfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
out=Path('/mnt/youlin-data/artifacts');out.mkdir(parents=True,exist_ok=True)
files=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).split(b'\0')
with tarfile.open(out/'DNSDOH-source.tar.gz','w:gz') as archive:
    for item in sorted(set(files)):
        if item:
            rel=Path(item.decode());archive.add(root/rel,arcname=Path('DNSDOH')/rel,recursive=False)
with tarfile.open(out/'DNSDOH-linux-amd64.tar.gz','w:gz',dereference=True) as archive:
    archive.add(root/'target-musl/x86_64-unknown-linux-musl/release/dnsdoh',arcname='DNSDOH/target/release/dnsdoh')
    archive.add(root/'target-musl/x86_64-unknown-linux-musl/release/dnsdoh',arcname='DNSDOH/agent/dnsdoh')
    for name in ['README.md','LICENSE','docs/DEPLOYMENT.md','docs/NODES.md','docs/API.md','deploy/controller.env.example','deploy/node.env.example','deploy/nginx.conf','deploy/dnsdoh@.service','deploy/dnsdoh-domain-maintain.service','deploy/dnsdoh-domain-maintain.timer','scripts/install-controller-maintenance.py','scripts/install-node.py','scripts/build-agent.sh','scripts/backup.py','scripts/install-controller.py','install.sh']:
        archive.add(root/name,arcname='DNSDOH/'+name)
shutil.copy2(root/'install.sh',out/'DNSDOH-install.sh')
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256((out/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in ['DNSDOH-source.tar.gz','DNSDOH-linux-amd64.tar.gz','DNSDOH-install.sh']))
print('Source and Linux x86_64 archives created with SHA256SUMS')
