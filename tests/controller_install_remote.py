#!/usr/bin/env python3
"""Run ON a disposable installer host only. Changes its generated administrator password."""
import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request

p=argparse.ArgumentParser();p.add_argument('--disposable',action='store_true',required=True);p.add_argument('--after-rerun',action='store_true');args=p.parse_args()
r=Path('/mnt/youlin-data/runtime');work=Path('/mnt/youlin-data/installer-test');work.mkdir(exist_ok=True,mode=0o700)
env=dict(l.split('=',1) for l in (r/'controller.env').read_text().splitlines() if l and not l.startswith('#'))
state=json.loads((r/'install-controller.json').read_text());assert state['stage']=='安装完成'
checks=[]
def check(ok,label):assert ok,label;checks.append(label);print('PASS',label,flush=True)
jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar));base=env['DNSDOH_PUBLIC_URL'];csrf=''
def request(path,method='GET',body=None):
 headers={'X-CSRF-Token':csrf}
 if body is not None:body=json.dumps(body).encode();headers['Content-Type']='application/json'
 try:response=opener.open(urllib.request.Request(base+path,data=body,headers=headers,method=method),timeout=20)
 except urllib.error.HTTPError as error:response=error
 return response.status,response.read()
def sql(query):
 result=subprocess.run(['mariadb','--no-defaults','--socket='+str(r/'mariadb-run/mariadb.sock'),'-u','root','-N','-B','dnsdoh'],input=query,text=True,capture_output=True);assert result.returncode==0,'SQL fixture operation failed';return result.stdout.strip()
private=work/'rerun-check.json'
if args.after_rerun:
 prior=json.loads(private.read_text());password=prior['changed_password']
 check(hashlib.sha256((r/'controller.env').read_bytes()).hexdigest()==prior['env_sha256'],'rerun preserves original database password, administrator identity and AES key')
 check(hashlib.sha256((r/'letsencrypt/live/dnsdoh-admin/fullchain.pem').read_bytes()).hexdigest()==prior['cert_sha256'],'rerun reuses still-valid HTTPS certificate')
 check(sql("SELECT COUNT(*) FROM audit_events WHERE action='installer-preservation-fixture'")=='1','rerun preserves existing database content')
else:
 password=env['DNSDOH_ADMIN_PASSWORD']
 check(re.fullmatch(r'admin_[a-f0-9]{6}',env['DNSDOH_ADMIN_USERNAME']) is not None,'administrator username generated instead of a shared default')
 check(len(password)>=32 and len(env['DNSDOH_MASTER_KEY'])==43,'independent high-entropy administrator password and encryption key generated')
status,body=request('/api/login','POST',{'username':env['DNSDOH_ADMIN_USERNAME'],'password':password});check(status==200,'generated/current administrator credentials authenticate over trusted HTTPS');csrf=json.loads(body)['csrf']
check(all(c.secure for c in jar),'administrator session uses Secure cookies')
status,body=request('/api/state');app=json.loads(body);check(status==200 and app['system']['database']=='MariaDB','installed dashboard reads real MariaDB')
check(app['infrastructure']['required'],'fresh installation requires user-owned DNS provider configuration')
check(request('/api/users','POST',{'name':'blocked-before-setup'})[0]==428,'business mutation blocked until DNS supplier setup')
for name in ['dnsdoh@controller.service','dnsdoh-mariadb.service','dnsdoh-admin-cert.timer','dnsdoh-domain-maintain.timer','dnsdoh-backup.timer']:
 check(subprocess.check_output(['systemctl','is-active',name],text=True).strip()=='active' and subprocess.check_output(['systemctl','is-enabled',name],text=True).strip()=='enabled',name+' active and enabled')
for path in [r/'controller.env',r/'管理员登录信息.txt']:
 check(path.stat().st_mode&0o777==0o600,path.name+' protected with 0600 permissions')
check(sql('SELECT @@datadir').startswith(str(r/'mariadb')),'MariaDB stores its actual data on the data disk')
check(sql('SELECT @@port')=='13306' and sql('SELECT @@bind_address')=='127.0.0.1','MariaDB bound only to dedicated loopback port')
backups=list((r/'backups').glob('*.sql.gz'));check(bool(backups) and all(x.with_suffix(x.suffix+'.env').exists() for x in backups),'successful initial backup includes matching original configuration')
check(subprocess.check_output(['systemctl','is-active','dnsdoh-node','sing-box'],text=True).splitlines()==['active','active'],'pre-existing DNS node and unrelated service remain active')
if not args.after_rerun:
 changed=secrets.token_urlsafe(24);check(request('/api/password','POST',{'current_password':password,'new_password':changed})[0]==200,'generated administrator can change initial password')
 sql("INSERT INTO audit_events(actor,action,target,created_at) VALUES('installer-test','installer-preservation-fixture','isolated-controller',UNIX_TIMESTAMP())")
 private.write_text(json.dumps({'changed_password':changed,'env_sha256':hashlib.sha256((r/'controller.env').read_bytes()).hexdigest(),'cert_sha256':hashlib.sha256((r/'letsencrypt/live/dnsdoh-admin/fullchain.pem').read_bytes()).hexdigest()}));private.chmod(0o600)
request('/api/logout','POST')
(work/('rerun-report.json' if args.after_rerun else 'fresh-report.json')).write_text(json.dumps({'passed':len(checks),'checks':checks,'platform':'Debian 13 x86_64','completed_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())},indent=2));print('ALL',len(checks),'CONTROLLER INSTALL CHECKS PASSED')
