#!/usr/bin/env python3
"""Standalone Web Security Audit engine 1.0.1."""
from __future__ import annotations
import argparse,csv,datetime as dt,html,json,os,re,shutil,socket,subprocess,time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse
V='1.0.2'; VERSION=V; ANSI=re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
ORDER={'FAIL':0,'INCONCLUSIVE':1,'RECOMMENDATION':2,'PROFILE_EXCEPTION':3,'NOT_APPLICABLE':4,'PASS':5,'INFORMATIONAL':6}
VISIBLE={'FAIL','INCONCLUSIVE','RECOMMENDATION','PROFILE_EXCEPTION'}
TEXT_SUFFIXES={'.txt','.html','.json','.log','.csv'}
def slug(s): return re.sub(r'[^A-Za-z0-9_.-]','_',str(s))
def css_class(result): return {'FAIL':'fail','INCONCLUSIVE':'inc','RECOMMENDATION':'rec','PROFILE_EXCEPTION':'exc','PASS':'pass'}.get(result,'')

def load(p): return json.loads(Path(p).read_text(encoding='utf-8'))
def save(p,s): Path(p).parent.mkdir(parents=True,exist_ok=True);Path(p).write_text(s,encoding='utf-8')
def elapsed(t): return f'{time.monotonic()-t:.1f}s'
def progress(i,total,label,t=None): print(f'  [{i:02d}/{total:02d}] {label}'+(f' ... {elapsed(t)}' if t else ''),flush=True)
def run(cmd,timeout,path,env=None):
 try:
  x=subprocess.run(cmd,input='',text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout,env=env);t=ANSI.sub('',x.stdout or '');save(path,t);return {'rc':x.returncode,'text':t,'timeout':False,'error':False}
 except subprocess.TimeoutExpired as e:
  z=e.stdout or '';z=z.decode('utf-8','replace') if isinstance(z,bytes) else z;t=ANSI.sub('',z)+f'\n[AUDIT] TIMEOUT after {timeout}s\n';save(path,t);return {'rc':124,'text':t,'timeout':True,'error':False}
 except Exception as e:
  t=f'[AUDIT] ERROR: {e}\n';save(path,t);return {'rc':125,'text':t,'timeout':False,'error':True}
def lines(t,pats):
 rs=[re.compile(p,re.I) for p in pats];return [(n,s) for n,s in enumerate(t.splitlines(),1) if any(r.search(s) for r in rs)]
def points(result,req):
 if result in {'PASS','PROFILE_EXCEPTION','NOT_APPLICABLE','INFORMATIONAL'}:return 0
 
 if result=='INCONCLUSIVE':return 5 if req=='MANDATORY' else 1
 return {'FAIL':15,'RECOMMENDATION':2}.get(result,0)
def add(fs,cid,title,result,req,expected,observed,source,hits=None,note='',origin='STANDARD_MANDATORY',severity='MEDIUM',group='Other',obs_state=None):
 fs.append({'id':cid,'title':title,'result':result,'requirement':req,'expected':expected,'observed':observed,'observation_state':obs_state or result,'source':source,'lines':hits or [],'note':note,'origin':origin,'severity':severity,'root_cause_group':group,'deduction':points(result,req)})
def cls(ok,req,inc=False): return 'INCONCLUSIVE' if inc else 'PASS' if ok else 'FAIL' if req=='MANDATORY' else 'RECOMMENDATION'
def overall(fs):
 if any(f['result']=='FAIL' and f['requirement']=='MANDATORY' for f in fs):return 'FAIL'
 if any(f['result']=='INCONCLUSIVE' and f['requirement']=='MANDATORY' for f in fs):return 'INCONCLUSIVE'
 if any(f['result']=='RECOMMENDATION' for f in fs):return 'PASS_WITH_RECOMMENDATIONS'
 return 'PASS'
def scores(fs):
 debt=-sum(f['deduction'] for f in fs)
 mandatory=[f for f in fs if f['requirement']=='MANDATORY' and f['result'] not in {'INFORMATIONAL','PROFILE_EXCEPTION','NOT_APPLICABLE'}]
 compliance=round(100*sum(f['result']=='PASS' for f in mandatory)/len(mandatory)) if mandatory else 100
 exposure=max(0,min(100,100-sum({'CRITICAL':10,'HIGH':6,'MEDIUM':3,'LOW':1}.get(f['severity'],0) for f in fs if f['result']=='FAIL')))
 return debt,compliance,exposure
def blocks(t):
 out=[];cur=None
 for raw in t.splitlines():
  s=raw.rstrip('\r')
  if s.startswith('HTTP/'):
   if cur:out.append(cur)
   cur={':status':[s]}
  elif ':' in s and cur is not None:
   k,v=s.split(':',1);cur.setdefault(k.strip().lower(),[]).append(v.strip())
 if cur:out.append(cur)
 return out
def header(h,n):return '; '.join(h.get(n.lower(),[]))
def tcp_probe(host,port,timeout):
 try:
  with socket.create_connection((host,port),timeout=timeout):return 'OPEN','connected'
 except ConnectionRefusedError:return 'CLOSED','connection refused'
 except socket.timeout:return 'FILTERED_OR_TIMEOUT','timeout'
 except OSError as e:return 'ERROR',str(e)
def cdn(h):
 z=' '.join(header(h,x) for x in ['server','via','cf-ray','x-akamai-transformed','x-azure-ref','x-amz-cf-id']).lower()
 for n,ts in {'Cloudflare':['cloudflare','cf-ray'],'Akamai':['akamai'],'Fastly':['fastly'],'Azure Front Door':['x-azure-ref','azurefd'],'CloudFront':['cloudfront','x-amz-cf-id'],'Imperva':['incapsula','imperva']}.items():
  if any(t in z for t in ts):return n
 return 'Not detected'
def blocked(status,body,provider):
 m=re.search(r'HTTP/\S+\s+(\d{3})',status);code=int(m.group(1)) if m else 0
 return code in {401,403,429} and (provider!='Not detected' or bool(re.search(r'access denied|forbidden|challenge|captcha|request blocked|error 1020',body,re.I)))
def tjson(path):
 try:
  x=load(path);return x if isinstance(x,list) else []
 except Exception:return []
def tjrow(rows,rid):return next((x for x in rows if str(x.get('id',''))==rid),None)
def proto_state(rows,rid):
 x=tjrow(rows,rid)
 if not x:return None,'missing testssl JSON entry',[]
 z=str(x.get('finding',''));return z.lower().startswith('offered'),z,[]
def cipher_rows(rows):
 out=[]
 for x in rows:
  rid=str(x.get('id','')); text=str(x.get('finding','')).strip()
  if not re.match(r'^cipher-tls1_[23]_',rid,re.I):continue
  m=re.match(r'^TLSv1\.[23]\s+x[0-9a-f]+\s+([A-Z0-9_-]+)\s+',text,re.I)
  if m:out.append(('TLS1.3' if 'tls1_3' in rid.lower() else 'TLS1.2',m.group(1).upper(),x))
 return out
def canon(s):
 z=s.upper().replace('TLS_','',1) if s.upper().startswith('TLS_') and '_WITH_' in s.upper() else s.upper()
 z=z.replace('_WITH_','-').replace('_','-');return re.sub(r'\b(AES|ARIA|CAMELLIA)-(128|256)\b',r'\1\2',z)
def permissions(v):
 d={}
 for q in v.split(','):
  if '=' in q:k,x=q.split('=',1);d[k.strip().lower()]=re.sub(r'\s+','',x.lower())
 return d
def csp(v):
 d={}
 for q in v.split(';'):
  x=q.strip().split()
  if x:d[x[0].lower()]=x[1:]
 return d
def mixed(body):
 pats=[r'<(?:script|img|iframe|embed|source|audio|video|input)\b[^>]*\bsrc\s*=\s*["\'](http://[^"\']+)',r'<link\b[^>]*\bhref\s*=\s*["\'](http://[^"\']+)',r'<form\b[^>]*\baction\s*=\s*["\'](http://[^"\']+)',r'<object\b[^>]*\bdata\s*=\s*["\'](http://[^"\']+)',r'url\(\s*["\']?(http://[^)"\']+)']
 out=[]
 for n,s in enumerate(body.splitlines(),1):
  for pat in pats:
   for m in re.finditer(pat,s,re.I):out.append((n,s,'resource',m.group(1)))
 return out
def cert_level(cert,ts):
 oid=re.search(r'Policy:\s*([0-9.]+)',cert)
 if re.search(r'EV cert.*\byes\b',ts,re.I) or (oid and oid.group(1)=='2.23.140.1.1'):return 'EV','EV policy evidence'
 if oid:
  if oid.group(1)=='2.23.140.1.2.2':return 'OV','CA/B Forum OV policy OID'
  if oid.group(1)=='2.23.140.1.2.1':return 'DV','CA/B Forum DV policy OID'
 subject=re.search(r'^subject=(.+)$',cert,re.M|re.I)
 if subject and re.search(r'(?:^|,)\s*O\s*=',subject.group(1)):return 'OV','organization in leaf subject'
 return 'UNKNOWN','no authoritative DV/OV/EV evidence'
def level_result(obs,minv):return cls({'UNKNOWN':-1,'DV':0,'OV':1,'EV':2}.get(obs,-1)>={'DV':0,'OV':1,'EV':2}.get(minv,1),'MANDATORY',obs=='UNKNOWN')
def root_for(cid):
 if cid.startswith('TLS-'):return 'TLS Configuration'
 if cid.startswith('CERT-'):return 'Certificate Management'
 if cid.startswith('CSP-') or cid=='HDR-CSP':return 'Content Security Policy'
 if cid.startswith('HDR-'):return 'HTTP Headers'
 return 'Other'
def render_report(out,profile,data):
 css='''html{scroll-behavior:smooth;scroll-padding-top:72px}body{font-family:Segoe UI,Arial;background:#f3f5f7;color:#17202a;margin:0}.wrap{max-width:1750px;margin:auto;padding:24px}.card,.note{background:#fff;border:1px solid #d8dee5;border-radius:10px;padding:15px;margin:14px 0}.toolbar{position:sticky;top:0;z-index:100;background:#17202a;color:#fff;padding:10px 14px;border-radius:8px}.toolbar a{color:#fff;margin-left:14px;font-weight:600}table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}th,td{border:1px solid #d8dee5;padding:8px;vertical-align:top;text-align:left}th{background:#eaf0f5}.PASS{color:#08783e}.PASS_WITH_RECOMMENDATIONS,.RECOMMENDATION{color:#986000}.FAIL{color:#b42318}.INCONCLUSIVE{color:#6b4fa1}.PROFILE_EXCEPTION{color:#0b7285}.NOT_APPLICABLE,.INFORMATIONAL{color:#59636e}.nav{background:#edf4f8;border:1px solid #c8d7e1;border-radius:8px;padding:10px;line-height:2}.nav a{display:inline-block;margin:2px 5px 2px 0;padding:2px 7px;border-radius:5px;background:#fff;text-decoration:none}.nav-fail{border:1px solid #b42318;color:#b42318}.nav-inc{border:1px solid #6b4fa1;color:#6b4fa1}.nav-rec{border:1px solid #986000;color:#986000}.nav-exc{border:1px solid #0b7285;color:#0b7285}.finding{border-left:5px solid #87909a;padding:10px;margin:8px 0;background:#fafafa;scroll-margin-top:72px}.finding.FAIL{border-color:#b42318}.finding.INCONCLUSIVE{border-color:#6b4fa1}.finding.RECOMMENDATION{border-color:#d28b00}.finding.PROFILE_EXCEPTION{border-color:#0b7285}.finding.PASS{border-color:#08783e}.finding:target,details.evidence:target{outline:3px solid #1683c4;outline-offset:3px;box-shadow:0 0 0 5px rgba(22,131,196,.12)}details.evidence{margin:9px 0;border:1px solid #c8d7e1;border-radius:7px;background:#fff;scroll-margin-top:72px}details.evidence>summary{cursor:pointer;padding:10px 12px;font-weight:700;background:#edf4f8}.evidence-tools{padding:7px 12px;background:#f7f9fa}.evidence-tools a{margin-right:12px}details.evidence pre{background:#111827;color:#eee;margin:0;padding:12px;border-radius:0 0 7px 7px;max-height:620px;overflow:auto;white-space:pre-wrap;line-height:1.25}.evidence-line{display:block;min-height:1.25em}.ev-fail{background:#5c1717}.ev-inc{background:#392552}.ev-rec{background:#5a4300}.ev-exc{background:#07525d}.ev-pass{background:#123f2a}.muted{color:#5f6b76}'''
 H=[f'<!doctype html><html lang="pt"><head><meta charset="utf-8"><title>Web Security Audit Report</title><style>{css}</style></head><body><div class="wrap" id="top"><h1>Web Security Audit Report</h1><nav class="toolbar">Engine v{VERSION}<a href="#summary">Domain summary</a><a href="#roots">Root causes</a><a href="#top">Top</a></nav><p>Profile: {html.escape(profile["name"])}</p>']
 H.append('''<section class="note"><h2>Como interpretar as métricas</h2><p><b>Technical Debt Score</b>: começa em 0 e acumula valores negativos. Falha obrigatória: -15; controlo obrigatório inconclusivo: -5; recomendação: -2; controlo recomendado inconclusivo: -1. Quanto mais próximo de 0, menor a dívida técnica observada.</p><p><b>Compliance Score</b>: percentagem de controlos obrigatórios aplicáveis que passaram. Controlos NOT_APPLICABLE, PROFILE_EXCEPTION e INFORMATIONAL são excluídos do denominador.</p><p><b>Exposure Score</b>: começa em 100 e deduz por falhas segundo a severidade: CRITICAL -10, HIGH -6, MEDIUM -3 e LOW -1. Quanto maior o valor, menor a exposição observada.</p></section>''')
 groups=defaultdict(lambda:{'FAIL':0,'INCONCLUSIVE':0,'RECOMMENDATION':0,'domains':set()})
 for r in data['results']:
  for f in r['findings']:
   if f['result'] in {'FAIL','INCONCLUSIVE','RECOMMENDATION'}:
    g=groups[f['root_cause_group']];g[f['result']]+=1;g['domains'].add(r['domain'])
 H.append('<h2 id="roots">Root Cause Groups</h2><table><tr><th>Group</th><th>FAIL</th><th>INCONCLUSIVE</th><th>RECOMMENDATION</th><th>Affected domains</th></tr>')
 for name,g in sorted(groups.items()):H.append(f'<tr><td>{html.escape(name)}</td><td>{g["FAIL"]}</td><td>{g["INCONCLUSIVE"]}</td><td>{g["RECOMMENDATION"]}</td><td>{html.escape(", ".join(sorted(g["domains"])))}</td></tr>')
 H.append('</table><h2 id="summary">Domain Summary</h2><table><tr><th>Domain</th><th>Platform</th><th>CDN/WAF</th><th>TLS Scope</th><th>Status</th><th>Technical Debt</th><th>Compliance</th><th>Exposure</th></tr>')
 for r in data['results']:H.append(f'<tr><td><a href="#d-{r["slug"]}">{html.escape(r["domain"])}</a></td><td>{html.escape(r.get("platform",""))}</td><td>{html.escape(r.get("cdn",""))}</td><td>{html.escape(r.get("tls_scope",""))}</td><td class="{r["status"]}">{r["status"]}</td><td>{r["technical_debt_score"]}</td><td>{r["compliance_score"]}%</td><td>{r["exposure_score"]}%</td></tr>')
 H.append('</table>')
 for r in data['results']:
  H.append(f'<section class="card" id="d-{r["slug"]}"><h2>{html.escape(r["domain"])}: <span class="{r["status"]}">{r["status"]}</span> | Technical Debt {r["technical_debt_score"]}</h2><nav class="nav"><b>Findings navigation:</b> ')
  for i,f in enumerate(r['findings']):
   if f['result'] in VISIBLE:H.append(f'<a class="nav-{css_class(f["result"])}" href="#f-{r["slug"]}-{i}">{html.escape(f["id"])} [{f["result"]}]</a>')
  H.append('<a href="#summary">Summary</a></nav>')
  for i,f in enumerate(r['findings']):
   eid=f'e-{r["slug"]}-{slug(f["source"])}';H.append(f'<div id="f-{r["slug"]}-{i}" class="finding {f["result"]}"><b>{f["result"]} | {f["severity"]} | {html.escape(f["id"])} | {html.escape(f["title"])}</b><br>Observation: {html.escape(f["observation_state"])} | Technical debt impact: -{f["deduction"]}<br>Expected: {html.escape(f["expected"])}<br>Observed: {html.escape(f["observed"])}<br>Evidence: <a href="#{eid}">{html.escape(f["source"])}</a>'+(' | Lines: '+', '.join(str(x[0]) for x in f.get('lines',[])) if f.get('lines') else '')+('<br>Reason: '+html.escape(f['note']) if f.get('note') else '')+'</div>')
  dd=out/'details'/r['slug'];files=sorted(x for x in dd.iterdir() if x.is_file() and x.suffix.lower() in TEXT_SUFFIXES) if dd.is_dir() else [];H.append('<h3>Evidence</h3>');marks={}
  for f in r['findings']:
   for x in f.get('lines',[]):
    try:marks[(f['source'],int(x[0]))]=f['result']
    except:pass
  for pth in files:
   eid=f'e-{r["slug"]}-{slug(pth.name)}';text=pth.read_text(encoding='utf-8',errors='replace');H.append(f'<details class="evidence" id="{eid}"><summary>{html.escape(pth.name)}</summary><div class="evidence-tools"><a href="#d-{r["slug"]}">Domain findings</a><a href="#top">Top</a></div><pre>')
   for n,line in enumerate(text.splitlines(),1):H.append(f'<span class="evidence-line ev-{css_class(marks.get((pth.name,n),""))}">{n:04d}: {html.escape(line)}</span>')
   H.append('</pre></details>')
  H.append('</section>')
 H.append('''</div><script>function openTarget(){if(!location.hash)return;const e=document.getElementById(location.hash.slice(1));if(!e)return;const d=e.tagName==='DETAILS'?e:e.closest('details');if(d)d.open=true;e.scrollIntoView({behavior:'smooth',block:'start'});}addEventListener('hashchange',openTarget);addEventListener('DOMContentLoaded',openTarget);</script></body></html>''');save(out/'WEB_SECURITY_AUDIT.html',''.join(H))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('-c','--config',default='audit-config.json');ap.add_argument('-p','--profile',default='profile-web-security-external.json');ap.add_argument('-o','--output');ap.add_argument('--validate-only',action='store_true');a=ap.parse_args();cfg=load(a.config);p=load(a.profile)
 required={'HTTPS-TRANSPORT','WEB-HTTP-80','TLS-1.0','TLS-1.1','TLS-1.2','TLS-1.3','TLS-CIPHER-ALLOWLIST','CERT-CHAIN','CERT-HOSTNAME','CERT-EXPIRY','CERT-WILDCARD','CERT-VALIDATION-LEVEL','HDR-HSTS','HDR-HSTS-EXACT','HDR-CSP','CSP-NO-UNSAFE-INLINE','CSP-NO-UNSAFE-EVAL','CSP-NO-WILDCARD','CSP-DEFAULT-NONE','HDR-PERMISSIONS','HDR-PERMISSIONS-EXACT','MIXED-CONTENT'};ids={x.get('id') for x in p.get('controls',[])};missing=sorted(required-ids)
 if not cfg.get('targets'):raise SystemExit('config requires at least one target')
 if not cfg.get('tests'):raise SystemExit('config requires tests')
 if missing:raise SystemExit('profile missing controls: '+', '.join(missing))
 if a.validate_only:print(f'Web Security Audit {V}: configuration and profile are valid.');return
 out=Path(a.output or 'web_security_audit_'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));(out/'details').mkdir(parents=True,exist_ok=True);C={c['id']:c for c in p['controls']};tsbin=shutil.which('testssl.sh') or shutil.which('testssl')
 if not tsbin:raise SystemExit('testssl.sh/testssl not found in PATH')
 rs=[];targets=cfg['targets'];total=10
 for di,target in enumerate(targets,1):
  d=target['domain'];port=target.get('port',443);slug=re.sub(r'[^A-Za-z0-9_.-]','_',d);dd=out/'details'/slug;dd.mkdir(parents=True,exist_ok=True);fs=[];print(f'\n[{di}/{len(targets)}] {d}',flush=True)
  t=time.monotonic();progress(1,total,'HTTPS transport');cc=cfg['tests']['curl'];curl=run(['curl','-sS','-L','--max-redirs',str(cc.get('max_redirects',5)),'--connect-timeout',str(cc.get('connect_timeout',10)),'--max-time',str(cc['timeout']),'-D','-','-o',str(dd/'body.html'),f'https://{d}:{port}/'],cc['timeout']+5,dd/'curl_headers.txt');body=(dd/'body.html').read_text(encoding='utf-8',errors='replace') if (dd/'body.html').exists() else '';bs=blocks(curl['text']);h=bs[-1] if bs else {};st=header(h,':status') or 'NO RESPONSE';provider=cdn(h);is_blocked=blocked(st,body,provider);tls_scope='CDN Edge' if provider!='Not detected' else 'Origin/Direct endpoint';platform=target.get('platform','Unspecified');c=C['HTTPS-TRANSPORT'];add(fs,c['id'],c['title'],cls(bool(bs) and not curl['timeout'],c['requirement'],curl['timeout']),c['requirement'],c['expected'],st,'curl_headers.txt',lines(curl['text'],[r'^HTTP/']),origin=c['origin'],severity=c['severity'],group=root_for(c['id']));progress(1,total,'HTTPS transport',t)
  t=time.monotonic();progress(2,total,'TLS scan (testssl)');tc=cfg['tests']['testssl'];jf=dd/'testssl.json';env=os.environ.copy();env.update(NO_COLOR='1',TERM='dumb');ts=run([tsbin,'--quiet','--warnings','off','--color','0','--jsonfile',str(jf),f'{d}:{port}'],tc['timeout'],dd/'testssl.txt',env);rows=tjson(jf);progress(2,total,'TLS scan (testssl)',t)
  t=time.monotonic();progress(3,total,'TLS protocols and cipher allowlist')
  for cid,rid in [('TLS-1.0','TLS1'),('TLS-1.1','TLS1_1'),('TLS-1.2','TLS1_2'),('TLS-1.3','TLS1_3')]:
   c=C[cid];state,detail,hh=proto_state(rows,rid);expected=c.get('expected_state')=='enabled';add(fs,cid,c['title'],cls(state==expected,c['requirement'],state is None),c['requirement'],c['expected'],detail,'testssl.json',hh,origin=c['origin'],severity=c['severity'],group='TLS Configuration',obs_state='NOT_OBSERVABLE' if state is None else 'OBSERVED')
  offered=cipher_rows(rows);allow={k:{canon(x) for x in v} for k,v in p['allowed_ciphers'].items()};bad=[(v,n) for v,n,_ in offered if canon(n) not in allow.get(v,set())];c=C['TLS-CIPHER-ALLOWLIST'];inc=ts['timeout'] or not offered;obs='; '.join(f'{v}: {n}' for v,n in bad) or ('no authoritative cipher entries' if inc else 'all offered suites allowed');add(fs,c['id'],c['title'],cls(not bad,c['requirement'],inc),c['requirement'],c['expected'],obs,'testssl.json',origin=c['origin'],severity=c['severity'],group='TLS Configuration',obs_state='NOT_OBSERVABLE' if inc else 'OBSERVED')
  for x in rows:
   if x.get('id')=='engine_problem':add(fs,'INFO-TESTSSL-ENGINE','testssl local engine limitation','INFORMATIONAL','INFORMATIONAL','informational only',str(x.get('finding','')),'testssl.json',origin='INFORMATIONAL',severity='INFORMATIONAL',group='Observation',obs_state='SCANNER_LIMITATION')
  progress(3,total,'TLS protocols and cipher allowlist',t)
  t=time.monotonic();progress(4,total,'Certificate validation');oc=cfg['tests']['openssl'];chain=run(['openssl','s_client','-showcerts','-verify_return_error','-connect',f'{d}:{port}','-servername',d],oc['timeout'],dd/'openssl_certificate.txt');c=C['CERT-CHAIN'];add(fs,c['id'],c['title'],cls(chain['rc']==0,c['requirement'],chain['timeout']),c['requirement'],c['expected'],f'rc={chain["rc"]}','openssl_certificate.txt',origin=c['origin'],severity=c['severity'],group='Certificate Management');pem=dd/'leaf.pem';leaf=run(['bash','-lc',f"openssl s_client -connect '{d}:{port}' -servername '{d}' -showcerts </dev/null 2>/dev/null|openssl x509 -outform PEM"],oc['timeout'],pem)
  if leaf['rc']==0 and pem.exists() and pem.stat().st_size:
   meta=run(['openssl','x509','-in',str(pem),'-noout','-subject','-issuer','-dates','-ext','subjectAltName','-ext','certificatePolicies'],10,dd/'certificate.txt');ct=meta['text']
   for cid,cmd,fn in [('CERT-HOSTNAME',['openssl','x509','-in',str(pem),'-noout','-checkhost',d],'certificate_hostname.txt'),('CERT-EXPIRY',['openssl','x509','-in',str(pem),'-noout','-checkend',str(C['CERT-EXPIRY'].get('minimum_days',30)*86400)],'certificate_expiry.txt')]:
    z=run(cmd,10,dd/fn);c=C[cid];add(fs,cid,c['title'],cls(z['rc']==0,c['requirement'],z['timeout']),c['requirement'],c['expected'],f'rc={z["rc"]}',fn,origin=c['origin'],severity=c['severity'],group='Certificate Management')
   wild='*.' in ct;allowed=target.get('certificate_policy',{}).get('wildcard_allowed',False);c=C['CERT-WILDCARD'];res='PROFILE_EXCEPTION' if wild and allowed else cls(not wild,c['requirement']);add(fs,c['id'],c['title'],res,c['requirement'],c['expected'],'wildcard with approved exception' if res=='PROFILE_EXCEPTION' else 'wildcard detected' if wild else 'no wildcard','certificate.txt',origin=c['origin'],severity=c['severity'],group='Certificate Management',obs_state=res)
   minimum=target.get('certificate_policy',{}).get('minimum_validation','OV');lev,why=cert_level(ct,ts['text']);c=C['CERT-VALIDATION-LEVEL'];add(fs,c['id'],c['title'],level_result(lev,minimum),c['requirement'],minimum+' or higher',lev,'certificate.txt',note=why,origin=c['origin'],severity=c['severity'],group='Certificate Management')
  progress(4,total,'Certificate validation',t)
  t=time.monotonic();progress(5,total,'HTTP headers')
  for c in [x for x in p['controls'] if x['test']=='header']:
   val=header(h,c['header']);ok=bool(val)
   if ok and c.get('accepted_values'):ok=val.strip().lower() in [x.lower() for x in c['accepted_values']]
   add(fs,c['id'],c['title'],cls(ok,c['requirement'],is_blocked),c['requirement'],c['expected'],val or ('not observable' if is_blocked else 'absent'),'curl_headers.txt',lines(curl['text'],[rf'^{re.escape(c["header"])}:']),origin=c['origin'],severity=c['severity'],group=root_for(c['id']),obs_state='NOT_OBSERVABLE' if is_blocked else 'ABSENT' if not val else 'OBSERVED')
  progress(5,total,'HTTP headers',t)
  t=time.monotonic();progress(6,total,'Exact header and CSP directives');hv=header(h,'Strict-Transport-Security');c=C['HDR-HSTS-EXACT']
  if not hv:add(fs,c['id'],c['title'],'NOT_APPLICABLE',c['requirement'],c['expected'],'parent HSTS header absent','curl_headers.txt',note='Presence control owns the failure.',origin=c['origin'],severity=c['severity'],group='HTTP Headers',obs_state='ABSENT')
  else:
   mm=re.search(r'max-age=(\d+)',hv,re.I);ok=bool(mm and int(mm.group(1))>=63072000 and 'includesubdomains' in hv.lower() and 'preload' in hv.lower());add(fs,c['id'],c['title'],cls(ok,c['requirement']),c['requirement'],c['expected'],hv,'curl_headers.txt',origin=c['origin'],severity=c['severity'],group='HTTP Headers')
  pv=header(h,'Permissions-Policy');c=C['HDR-PERMISSIONS-EXACT']
  if not pv:add(fs,c['id'],c['title'],'NOT_APPLICABLE',c['requirement'],c['expected'],'parent Permissions-Policy header absent','curl_headers.txt',note='Presence control owns the failure.',origin=c['origin'],severity=c['severity'],group='Permissions Framework',obs_state='ABSENT')
  else:
   pd=permissions(pv);diff=[f'{k}: expected {v}, observed {pd.get(k,"absent")}' for k,v in p['permissions_policy'].items() if pd.get(k)!=v];add(fs,c['id'],c['title'],cls(not diff,c['requirement']),c['requirement'],'; '.join(f'{k}={v}' for k,v in p['permissions_policy'].items()),'; '.join(diff) if diff else pv,'curl_headers.txt',origin=c['origin'],severity=c['severity'],group='Permissions Framework')
  cv=header(h,'Content-Security-Policy');cd=csp(cv)
  for cid,token in [('CSP-NO-UNSAFE-INLINE',"'unsafe-inline'"),('CSP-NO-UNSAFE-EVAL',"'unsafe-eval'")]:
   c=C[cid]
   if not cv:add(fs,cid,c['title'],'NOT_APPLICABLE',c['requirement'],c['expected'],'parent CSP header absent','curl_headers.txt',note='Presence control owns the failure.',origin=c['origin'],severity=c['severity'],group='Content Security Policy',obs_state='ABSENT')
   else:
    present=any(token in vals for vals in cd.values());add(fs,cid,c['title'],cls(not present,c['requirement']),c['requirement'],c['expected'],f'{token} present' if present else 'not present','curl_headers.txt',origin=c['origin'],severity=c['severity'],group='Content Security Policy')
  for cid,ok,obs in [('CSP-NO-WILDCARD',not any('*' in vals for vals in cd.values()),'wildcard present'),('CSP-DEFAULT-NONE',cd.get('default-src')==["'none'"],str(cd.get('default-src','absent')))]:
   c=C[cid]
   if not cv:add(fs,cid,c['title'],'NOT_APPLICABLE',c['requirement'],c['expected'],'parent CSP header absent','curl_headers.txt',note='Presence control owns the failure.',origin=c['origin'],severity=c['severity'],group='Content Security Policy',obs_state='ABSENT')
   else:add(fs,cid,c['title'],cls(ok,c['requirement']),c['requirement'],c['expected'],obs if not ok else 'compliant','curl_headers.txt',origin=c['origin'],severity=c['severity'],group='Content Security Policy')
  progress(6,total,'Exact header and CSP directives',t)
  t=time.monotonic();progress(7,total,'Mixed content');mix=mixed(body);c=C['MIXED-CONTENT'];obs='; '.join(f'{typ} {url} line {n}' for n,_,typ,url in mix) or ('body not observable' if is_blocked else 'none found');add(fs,c['id'],c['title'],cls(not mix,c['requirement'],is_blocked),c['requirement'],c['expected'],obs,'body.html',[(n,s) for n,s,_,_ in mix],origin=c['origin'],severity=c['severity'],group='Content Transport',obs_state='NOT_OBSERVABLE' if is_blocked else 'OBSERVED');progress(7,total,'Mixed content',t)
  t=time.monotonic();progress(8,total,'HTTP port 80');state,detail=tcp_probe(d,80,p['http80_policy'].get('tcp_timeout',5));save(dd/'http80_probe.txt',f'state={state}\ndetail={detail}\n');ok=state=='CLOSED';inc=state in {'FILTERED_OR_TIMEOUT','ERROR'};obs='port 80 '+state
  if state=='OPEN':
   r80=run(['curl','-sS','-I','--max-redirs','0','--max-time',str(cc['timeout']),f'http://{d}:80/'],cc['timeout']+5,dd/'http_redirect.txt');b80=blocks(r80['text']);hh=b80[-1] if b80 else {};sl=header(hh,':status');m=re.search(r'\s(\d{3})',sl);code=int(m.group(1)) if m else 0;loc=header(hh,'location');u=urlparse(loc);cross=p['http80_policy'].get('allow_cross_host',False);ok=code in p['http80_policy']['accepted_status_codes'] and u.scheme=='https' and (cross or (u.hostname or '').lower()==d.lower());inc=r80['timeout'] or not b80;obs=f'OPEN status={code} location={loc or "absent"}'
  c=C['WEB-HTTP-80'];http80_result=cls(ok,c['requirement'],inc)
  if target.get('http80_policy',{}).get('allow_service',False) and http80_result in {'FAIL','INCONCLUSIVE','RECOMMENDATION'}:http80_result='PROFILE_EXCEPTION'
  add(fs,c['id'],c['title'],http80_result,c['requirement'],c['expected'],obs,'http80_probe.txt',note='HTTP/80 service explicitly allowed for this target.' if http80_result=='PROFILE_EXCEPTION' else '',origin=c['origin'],severity=c['severity'],group='Transport');progress(8,total,'HTTP port 80',t)
  t=time.monotonic();progress(9,total,'Complementary tools');
  if cfg['tests'].get('nmap',{}).get('enabled'):
   nc=cfg['tests']['nmap'];run(['nmap','-Pn','-p',str(port),'--script','ssl-enum-ciphers',d],nc['timeout'],dd/'nmap.txt');add(fs,'INFO-NMAP','Nmap complementary evidence','INFORMATIONAL','INFORMATIONAL','informational only','completed','nmap.txt',origin='INFORMATIONAL',severity='INFORMATIONAL',group='Observation')
  if cfg['tests'].get('nikto',{}).get('enabled'):
   nk=cfg['tests']['nikto'];z=run(['nikto','-h',f'https://{d}','-port',str(port),'-maxtime',f'{nk["timeout"]}s','-nointeractive'],nk['timeout']+15,dd/'nikto.txt');partial=z['timeout'] or 'maximum execution time' in z['text'].lower();add(fs,'INFO-NIKTO','Nikto complementary scan','INFORMATIONAL','INFORMATIONAL','informational only','INCOMPLETE_SCAN' if partial else 'completed','nikto.txt',origin='INFORMATIONAL',severity='INFORMATIONAL',group='Observation',obs_state='INCOMPLETE_SCAN' if partial else 'OBSERVED')
  progress(9,total,'Complementary tools',t)
  t=time.monotonic();progress(10,total,'Domain result');
  for f in fs:
   seen=set();f['lines']=[x for x in f.get('lines',[]) if not (int(x[0]) in seen or seen.add(int(x[0])))]
  fs.sort(key=lambda x:(ORDER.get(x['result'],9),x['id']));debt,comp,expo=scores(fs);rs.append({'domain':d,'slug':slug,'platform':platform,'cdn':provider,'tls_scope':tls_scope,'status':overall(fs),'technical_debt_score':debt,'compliance_score':comp,'exposure_score':expo,'findings':fs});progress(10,total,'Domain result',t);print('  Domain collection complete. Final metrics will use Technical Debt.',flush=True)
 payload={'version':V,'metadata':cfg.get('metadata',{}),'results':rs};save(out/'audit-results.json',json.dumps(payload,ensure_ascii=False,indent=2));render_report(out,p,payload)
 with open(out/'executive-summary.csv','w',newline='',encoding='utf-8') as f:
  w=csv.writer(f);w.writerow(['Domain','Status','TechnicalDebtScore','ComplianceScore','ExposureScore','FailCount','RecommendationCount','InconclusiveCount','AffectedRootCauseGroups','Platform','CDN','TLSScope'])
  for r in rs:
   fs=r['findings'];groups=sorted({x['root_cause_group'] for x in fs if x['result'] in {'FAIL','INCONCLUSIVE','RECOMMENDATION'}});w.writerow([r['domain'],r['status'],r['technical_debt_score'],r['compliance_score'],r['exposure_score'],sum(x['result']=='FAIL' for x in fs),sum(x['result']=='RECOMMENDATION' for x in fs),sum(x['result']=='INCONCLUSIVE' for x in fs),'; '.join(groups),r['platform'],r['cdn'],r['tls_scope']])
 from collections import Counter
 counts=Counter(r['status'] for r in rs);ranked=sorted(rs,key=lambda x:x['technical_debt_score'])
 print(f'\nAudit Summary (v{V})');print(f'  Domains audited: {len(rs)}')
 for state in ['FAIL','INCONCLUSIVE','PASS_WITH_RECOMMENDATIONS','PASS']:print(f'  {state}: {counts.get(state,0)}')
 print('\n  Technical Debt ranking (lowest first):')
 for i,r in enumerate(ranked,1):print(f'    {i}. {r["domain"]} | {r["technical_debt_score"]} | Compliance {r["compliance_score"]}% | Exposure {r["exposure_score"]}%')
 print(f'\nReport: {out/"WEB_SECURITY_AUDIT.html"}')
if __name__=='__main__':main()
