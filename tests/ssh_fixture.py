"""Independent OpenSSH fixture: public-key login, pinning and host reinstall handling."""
import json,os,subprocess,time
from pathlib import Path

def exercise(m,c,check):
 root=Path('/mnt/youlin-data/runtime/ssh-fixture');root.mkdir(parents=True,exist_ok=True,mode=0o700)
 def command(*args):subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for name,phrase in [('host-one',''),('host-two',''),('client','fixture-key-passphrase')]:
  key=root/name
  if not key.exists():command('ssh-keygen','-q','-t','ed25519','-N',phrase,'-f',str(key))
 forced=root/'forced.sh';forced.write_text('#!/bin/sh\ncat >/dev/null\necho DNSDOH_STAGE packages\necho fixture-secret-never-store\necho DNSDOH_STAGE ready\nexit 0\n');forced.chmod(0o700)
 config=root/'sshd.conf';log=root/'sshd.log'
 def start(hostkey):
  config.write_text(f'''Port 19993
ListenAddress 127.0.0.1
HostKey {root/hostkey}
PidFile {root/'sshd.pid'}
AuthorizedKeysFile {root/'client.pub'}
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
StrictModes no
ForceCommand {forced}
LogLevel VERBOSE
''')
  process=subprocess.Popen(['/usr/sbin/sshd','-D','-f',str(config),'-E',str(log)])
  time.sleep(.4);assert process.poll() is None,'OpenSSH fixture failed to start';return process
 daemon=start('host-one')
 try:
  m.sql("UPDATE dns_domains SET state='active'")
  first=c.api('/ssh/probe','POST',{'host':'127.0.0.1','port':19993})
  check(first['fingerprint'].startswith('SHA256:') and not first['trusted'],'SSH probe reports first-contact fingerprint before login')
  ssh={'port':19993,'username':'root','private_key':(root/'client').read_text(),'key_passphrase':'fixture-key-passphrase','fingerprint':first['fingerprint'],'trust_host_key':False}
  c.api('/managed-nodes','POST',{'name':'SSH fixture node','ip_address':'127.0.0.1','ssh':ssh},expected=409)
  check(m.sql('SELECT COUNT(*) FROM nodes')=='0','unconfirmed SSH fingerprint cannot start installation')
  ssh['trust_host_key']=True
  node=c.api('/managed-nodes','POST',{'name':'SSH fixture node','ip_address':'127.0.0.1','ssh':ssh})
  def job_state(j):return next(x for x in c.api('/infrastructure')['jobs'] if x['id']==j)['state']
  check(m.wait_for(lambda:job_state(node['job_id'])=='done',20),'encrypted OpenSSH private key authenticates and executes isolated deployment fixture')
  saved=c.api('/ssh/probe','POST',{'host':'127.0.0.1','port':19993})
  check(saved['trusted'] and not saved['changed'],'subsequent SSH probe matches stored host pin')
  daemon.terminate();daemon.wait(timeout=5);daemon=start('host-two')
  changed=c.api('/ssh/probe','POST',{'host':'127.0.0.1','port':19993})
  check(changed['changed'] and changed['previous_fingerprint']==first['fingerprint'],'reinstalled SSH host exposes both previous and changed fingerprints')
  stale=c.api('/managed-nodes/'+node['id']+'/deploy','POST',ssh)
  check(m.wait_for(lambda:job_state(stale['job_id'])=='failed',15),'live SSH key mismatch aborts before authentication and installer transmission')
  ssh['fingerprint']=changed['fingerprint'];ssh['trust_host_key']=False
  c.api('/managed-nodes/'+node['id']+'/deploy','POST',ssh,expected=409)
  check(True,'changed host requires explicit confirmation instead of disabling verification')
  ssh['trust_host_key']=True
  retry=c.api('/managed-nodes/'+node['id']+'/deploy','POST',ssh)
  check(m.wait_for(lambda:job_state(retry['job_id'])=='done',20),'confirmed replacement host pin permits redeployment')
  state=json.dumps(c.api('/infrastructure'))
  check('fixture-secret-never-store' not in state and 'fixture-key-passphrase' not in state and 'BEGIN OPENSSH' not in state,'deployment jobs redact arbitrary remote output and never retain SSH credentials')
  c.api('/managed-nodes/'+node['id'],'DELETE')
  check(m.sql('SELECT deploy_state FROM nodes WHERE id="'+node['id']+'"')=='deleting','node deletion keeps a tombstone until public DNS cleanup succeeds')
 finally:
  daemon.terminate();daemon.wait(timeout=5)
