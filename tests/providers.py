#!/usr/bin/env python3
"""Provider contract tests against independent signing verifiers; no real credentials."""
import base64,hashlib,hmac,http.server,importlib.util,json,secrets,subprocess,threading,time,urllib.parse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('m',ROOT/'tests/integration.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
checks=[];counts={'cloudflare':0,'alidns':0,'dnspod':0};records={};calls=[];ali_records={};pod_records={}
def check(condition,label):
 assert condition,label;checks.append(label);print('PASS',label,flush=True)
def mac(key,value,algorithm=hashlib.sha256):return hmac.new(key,value.encode(),algorithm).digest()
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):self.handle_api()
 def do_POST(self):self.handle_api()
 def do_PUT(self):self.handle_api()
 def do_DELETE(self):self.handle_api()
 def handle_api(self):
  try:
   parsed=urllib.parse.urlsplit(self.path);kind=parsed.path.split('/')[1];body=self.rfile.read(int(self.headers.get('Content-Length',0)));counts[kind]+=1
   if kind=='cloudflare':
    assert self.headers.get('Authorization')=='Bearer cf-contract-token' or (self.headers.get('X-Auth-Email')=='owner@example.test' and self.headers.get('X-Auth-Key')=='cf-global-contract')
    query=urllib.parse.parse_qs(parsed.query)
    if parsed.path.endswith('/zones'):
     page=int(query.get('page',['1'])[0]);names=[{'id':str(i),'name':f'contract{i}.test','status':'active','account':{'id':'account'}} for i in range(51)]
     result={'success':True,'result':names[(page-1)*50:page*50]}
    elif parsed.path.endswith('/dns_records'):
     if self.command=='GET':result={'success':True,'result':list(records.values())}
     else:
      v=json.loads(body);v['id']='record-'+str(len(records));records[v['id']]=v;result={'success':True,'result':v}
    else:
     records.pop(parsed.path.rsplit('/',1)[1],None);result={'success':True,'result':{}}
   elif kind=='alidns':
    args={k:v[0] for k,v in urllib.parse.parse_qs(body.decode()).items()};signature=args.pop('Signature');quote=lambda x:urllib.parse.quote(x,safe='-_.~')
    canonical='&'.join(quote(k)+'='+quote(v) for k,v in sorted(args.items()))
    assert signature==base64.b64encode(mac(b'ali-contract-secret&','POST&%2F&'+quote(canonical),hashlib.sha1)).decode()
    assert args['AccessKeyId']=='ali-contract-id';calls.append(args['Action'])
    action=args['Action']
    if action=='DescribeDomains':result={'Domains':{'Domain':[{'DomainName':'ali-contract.test'}]}}
    elif action=='DescribeDomainRecords':result={'DomainRecords':{'Record':list(ali_records.values())}}
    elif action=='AddDomainRecord':
     rid='ali-'+str(len(ali_records));ali_records[rid]={'RecordId':rid,'RR':args['RR'],'Type':args['Type'],'Value':args['Value']};result={'RecordId':rid}
    elif action=='DeleteDomainRecord':ali_records.pop(args['RecordId'],None);result={'RecordId':args['RecordId']}
    else:raise AssertionError('unexpected Ali action')
   else:
    stamp=self.headers['X-TC-Timestamp'];date=time.strftime('%Y-%m-%d',time.gmtime(int(stamp)));scope=date+'/dnspod/tc3_request'
    canonical='POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:dnspod.tencentcloudapi.com\n\ncontent-type;host\n'+hashlib.sha256(body).hexdigest()
    signing=mac(mac(mac(b'TC3dnspod-contract-secret',date),'dnspod'),'tc3_request');signature=mac(signing,'TC3-HMAC-SHA256\n'+stamp+'\n'+scope+'\n'+hashlib.sha256(canonical.encode()).hexdigest()).hex()
    assert self.headers['Authorization']=='TC3-HMAC-SHA256 Credential=dnspod-contract-id/'+scope+', SignedHeaders=content-type;host, Signature='+signature
    action=self.headers['X-TC-Action'];calls.append(action)
    args=json.loads(body)
    if action=='DescribeDomainList':result={'Response':{'DomainList':[{'DomainId':123,'Name':'dnspod-contract.test','Status':'ENABLE'}]}}
    elif action=='DescribeRecordList':result={'Response':{'RecordList':list(pod_records.values())}}
    elif action=='CreateRecord':
     rid=100+len(pod_records);pod_records[rid]={'RecordId':rid,'Name':args['SubDomain'],'Type':args['RecordType'],'Value':args['Value']};result={'Response':{'RecordId':rid}}
    elif action=='DeleteRecord':pod_records.pop(args['RecordId'],None);result={'Response':{}}
    else:raise AssertionError('unexpected DNSPod action')
   self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(result).encode())
  except Exception:
   self.send_response(403);self.end_headers();self.wfile.write(b'{}')
def main():
 tables=m.sql('SHOW TABLES').splitlines();m.sql('SET FOREIGN_KEY_CHECKS=0;'+''.join('DROP TABLE `'+t+'`;' for t in tables)+'SET FOREIGN_KEY_CHECKS=1;')
 server=http.server.ThreadingHTTPServer(('127.0.0.1',19992),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
 controller=m.start('provider-controller',{'DNSDOH_MODE':'controller','DNSDOH_PUBLIC_URL':m.BASE,'DNSDOH_DOH_URL':m.BASE,'DNSDOH_BIND':'127.0.0.1:19080','DNSDOH_PROVIDER_TEST_URL':'http://127.0.0.1:19992','DNSDOH_TEST_DISABLE_INFRA':'true','DNSDOH_REQUIRE_SETUP':'true'})
 try:
  check(m.wait_for(lambda:m.Client().request('/readyz')[0]==200),'isolated controller starts with provider schema')
  c=m.Client();c.login()
  check(c.api('/state')['infrastructure']['required'],'fresh controller requires DNS onboarding')
  c.api('/users','POST',{'name':'must-not-exist'},expected=428)
  check(m.sql('SELECT COUNT(*) FROM users')=='0','backend blocks operational writes before onboarding')
  fixtures=[('cloudflare',{'token':'cf-contract-token'}),('alidns',{'key_id':'ali-contract-id','key_secret':'ali-contract-secret'}),('dnspod',{'key_id':'dnspod-contract-id','key_secret':'dnspod-contract-secret'})]
  for kind,credentials in fixtures:
   result=c.api('/providers','POST',{'kind':kind,'name':'Contract '+kind,'credentials':credentials})
   check(bool(result['zones']),kind+' credential verification returns account zones')
   listed=c.api('/providers/'+result['id']+'/zones')
   check(listed['zones']==result['zones'],kind+' domain list endpoint uses authenticated provider API')
   ciphertext=m.sql('SELECT credential FROM dns_providers WHERE id="'+result['id']+'"')
   check(all(value not in ciphertext for value in credentials.values()),kind+' credentials encrypted in MariaDB')
   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
   decode=lambda s:base64.urlsafe_b64decode(s+'='*(-len(s)%4))
   raw=decode(ciphertext);plain=json.loads(AESGCM(decode(m.ENV['DNSDOH_MASTER_KEY'])).decrypt(raw[:12],raw[12:],('provider:'+result['id']).encode()))
   check(all(plain[k]==v for k,v in credentials.items()),kind+' AES-GCM ciphertext independently decrypts with bound provider identity')
   state=json.dumps(c.api('/state'))
   check(all(value not in state for value in credentials.values()),kind+' admin lists never expose saved API credentials')
   if kind=='cloudflare':
    check(len(result['zones'])==51 and counts[kind]>=4,'account-wide Cloudflare zones paginate beyond the first 50')
    c.api('/domains','POST',{'provider_id':result['id'],'zone_id':'unknown','label':'doh','controller_ip':'192.0.2.10'},expected=400)
    domain=c.api('/domains','POST',{'provider_id':result['id'],'zone_id':'0','label':'doh','controller_ip':'192.0.2.10'})
    check(m.sql('SELECT state FROM dns_domains WHERE id="'+domain['id']+'"')=='preparing','selected domain becomes resumable pending certificate job')
  check('DescribeDomains' in calls and 'DescribeDomainList' in calls,'AliDNS HMAC-SHA1 and DNSPod TC3 signatures independently verified')
  result=c.api('/providers','POST',{'kind':'cloudflare','name':'invalid token','credentials':{'token':'wrong'}},expected=400)
  check('wrong' not in json.dumps(result),'provider errors redact rejected credentials')
  check(m.sql('SELECT COUNT(*) FROM dns_providers')=='3','failed credential validation does not persist provider')
  global_key=c.api('/providers','POST',{'kind':'cloudflare','name':'Global Key contract','credentials':{'email':'owner@example.test','key_secret':'cf-global-contract'}})
  check(len(global_key['zones'])==51,'Cloudflare Global API Key plus email supports account-wide zone discovery')
  env=m.ENV.copy();env.update(DNSDOH_PROVIDER_TEST_URL='http://127.0.0.1:19992')
  with open(m.RUNTIME / 'provider-rust-contract.log','w') as log:
   child=subprocess.run(['cargo','test','--locked','providers::tests::provider_lifecycle_contract','--','--ignored','--exact'],cwd=ROOT,env=env,stdout=log,stderr=log)
  check(child.returncode==0,'Cloudflare/AliDNS/DNSPod A, AAAA and ACME TXT create/list/delete pass independent signing fixtures')
  check(not records and not ali_records and not pod_records,'all provider lifecycle fixtures cleaned up')
  from ssh_fixture import exercise
  exercise(m,c,check)
  (m.RUNTIME / 'provider-contract-report.json').write_text(json.dumps({'passed':len(checks),'checks':checks,'scope':'local HTTP contract fixtures with independent signature validation; only Cloudflare separately verified live'},indent=2))
  print('ALL',len(checks),'PROVIDER CONTRACT CHECKS PASSED')
 finally:
  m.stop(controller);server.shutdown();server.server_close()
if __name__=='__main__':main()
