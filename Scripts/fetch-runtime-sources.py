#!/usr/bin/env python3
"""Fetch exact corresponding-source archives; verify every SHA-256."""
import concurrent.futures, hashlib, json, re, subprocess, sys
from pathlib import Path
root=Path(sys.argv[1]).resolve()
manifest=json.loads((root/'runtime-manifest.json').read_text())
def fetch(item):
 name,meta=item
 url=meta['url']; target=root/name/url.rsplit('/',1)[1].split('?')[0]
 if not target.exists():
  subprocess.run(['curl','--fail','--location','--retry','2','--silent','--show-error',url,'--output',str(target)],check=True)
 actual=hashlib.sha256(target.read_bytes()).hexdigest()
 if actual!=meta['sha256']: raise RuntimeError('Source checksum mismatch: '+name)
 return name+' '+actual
items=list(manifest['components'].items())
patches=[]
for name,meta in manifest['components'].items():
 text=(root/meta['formula']).read_text()
 for i,block in enumerate(re.findall(r'patch do\n(.*?)\n  end',text,re.S)):
  url=re.search(r'url "([^"\n]+)"',block); sha=re.search(r'sha256 "([0-9a-f]{64})"',block)
  if not url or not sha: raise RuntimeError('Review patch metadata: '+name)
  patches.append((name,{'url':url[1],'sha256':sha[1]}))
 if name=='readline':
  for number,sha in re.findall(r'^    (\d{3}) ([0-9a-f]{64})$',text,re.M):
   patches.append((name,{'url':'https://ftp.gnu.org/gnu/readline/readline-8.3-patches/readline83-'+number,'sha256':sha}))
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
 for result in pool.map(fetch,items+patches): print(result,flush=True)
(root/'patches.json').write_text(json.dumps(patches,indent=2)+'\n')
