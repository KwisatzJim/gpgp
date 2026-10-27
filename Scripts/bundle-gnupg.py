#!/usr/bin/env python3
"""Build a relocatable runtime from pinned, installed Homebrew components.
No user keyring or configuration is read. Run before signing the containing app.
"""
import argparse, hashlib, json, os, re, shutil, subprocess
from pathlib import Path

p = argparse.ArgumentParser(); p.add_argument('destination', type=Path); p.add_argument('--sources', type=Path, required=True)
a = p.parse_args(); root = a.destination.resolve(); sources = a.sources.resolve()
if root.exists(): raise SystemExit('Destination already exists; choose a fresh staging directory.')
for name in ['bin','lib','libexec','Licenses','share/gnupg','etc/gnupg']:
    (root/name).mkdir(parents=True, exist_ok=True)
sources.mkdir(parents=True, exist_ok=True)
formulae = {}; copied = {}; queue = []
def run(*args): return subprocess.check_output(args, text=True).strip()
def record(path):
    real = path.resolve()
    parts = real.parts
    if 'Cellar' not in parts: raise RuntimeError('Unexpected non-system dependency: '+str(real))
    i = parts.index('Cellar'); prefix = Path(*parts[:i+3]); name = parts[i+1]
    if name not in formulae:
        recipe = prefix/'.brew'/(name+'.rb')
        text = recipe.read_text()
        # Pin metadata to the installed formula, not today’s latest Homebrew version.
        url = re.search(r'^  url "([^"]+)"', text, re.M)
        sha = re.search(r'^  sha256 "([0-9a-f]{64})"', text, re.M)
        if not url or not sha: raise RuntimeError('Source metadata needs explicit review: '+name)
        dest = sources/name; dest.mkdir(exist_ok=True)
        shutil.copy2(recipe, dest/recipe.name)
        receipt = prefix/'INSTALL_RECEIPT.json'
        if receipt.exists(): shutil.copy2(receipt, dest/receipt.name)
        licenses = root/'Licenses'/name; licenses.mkdir()
        for f in prefix.iterdir():
            if f.is_file() and re.match(r'^(COPYING|LICENSE|AUTHORS|NOTICE|COPYRIGHT)', f.name, re.I):
                shutil.copy2(f, licenses/f.name); shutil.copy2(f, dest/f.name)
        formulae[name] = {'version':prefix.name, 'url':url[1], 'sha256':sha[1], 'formula':name+'/'+recipe.name}
    return real

def add(original, target):
    real = record(original)
    if real in copied: return copied[real]
    target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(real,target); target.chmod(0o755)
    copied[real]=target; queue.append((real,target)); return target

gpgprefix = Path(run('/opt/homebrew/bin/brew','--prefix','gnupg')).resolve()
for name in ['gpg','gpg-agent','gpgconf','gpg-connect-agent','gpgv','dirmngr']:
    add(gpgprefix/'bin'/name, root/'bin'/('.'+name+'-real'))
for name in ['keyboxd','scdaemon','gpg-protect-tool','gpg-preset-passphrase','gpg-check-pattern','dirmngr_ldap']:
    add(gpgprefix/'libexec'/name, root/'libexec'/name)
for f in (gpgprefix/'share/gnupg').glob('*'):
    if f.is_file(): shutil.copy2(f,root/'share/gnupg'/f.name)
# Every GnuPG process finds this control file relative to its own executable.
(root/'bin/gpgconf.ctl').write_text('rootdir = ${GPGP_GNUPG_ROOT}\nsysconfdir = ${GPGP_GNUPG_ROOT}/etc/gnupg\n')
pinprefix = Path(run('/opt/homebrew/bin/brew','--prefix','pinentry-mac')).resolve()
pinapp = root/'libexec/pinentry-mac.app'; shutil.copytree(pinprefix/'pinentry-mac.app',pinapp)
pinoriginal = pinprefix/'pinentry-mac.app/Contents/MacOS/pinentry-mac'
pinbinary = pinapp/'Contents/MacOS/pinentry-mac'
record(pinoriginal); copied[pinoriginal.resolve()]=pinbinary; queue.append((pinoriginal.resolve(),pinbinary))
# Native launchers are code-signed normally; shell-script signatures stored
# in extended attributes do not survive all disk-image/copy workflows.
launcher = Path(__file__).with_name('runtime-launcher.c')
subprocess.run(['xcrun','clang','-arch','arm64','-mmacosx-version-min=14.0',str(launcher),'-o',str(root/'bin/gpg')],check=True)
launchers=['gpg','gpg-agent','gpgconf','gpg-connect-agent','gpgv','dirmngr','pinentry','pinentry-mac']
for name in launchers:
    if name!='gpg': shutil.copy2(root/'bin/gpg',root/'bin'/name)
shutil.copy2(launcher,sources/'runtime-launcher.c')
index=0
while index<len(queue):
    original,target = queue[index]; index+=1
    subprocess.run(['codesign','--remove-signature',str(target)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    deps = [line.strip().split(' (compatibility')[0] for line in run('otool','-L',str(original)).splitlines()[1:]]
    ownid = run('otool','-D',str(original)).splitlines()[1:]
    for dep in deps:
        if dep in ownid: continue
        if dep.startswith(('/System/','/usr/lib/')): continue
        if not dep.startswith('/opt/homebrew/'): raise RuntimeError('Unresolved dependency '+dep)
        library = add(Path(dep),root/'lib'/Path(dep).name)
        relative = os.path.relpath(library,target.parent)
        subprocess.run(['install_name_tool','-change',dep,'@loader_path/'+relative,str(target)],check=True)
    if ownid:
        subprocess.run(['install_name_tool','-id','@loader_path/'+target.name,str(target)],check=True)
# Build-time absolute Homebrew rpaths are unnecessary and must not leak into the runtime.
for target in copied.values():
    text=run('otool','-l',str(target))
    for rpath in re.findall(r'cmd LC_RPATH\n.*?path (.*?) \(offset',text,re.S):
        if rpath.startswith('/opt/homebrew/'):
            subprocess.run(['install_name_tool','-delete_rpath',rpath,str(target)],check=True)
    deps=run('otool','-L',str(target))
    if '/opt/homebrew/' in '\n'.join(deps.splitlines()[1:]): raise RuntimeError('Absolute dependency remains: '+str(target))
manifest={'gnupg':formulae['gnupg']['version'].split('_')[0],'architecture':'arm64','components':formulae,
          'executables':[str(x.relative_to(root)) for x in copied.values()]+['bin/'+name for name in launchers]}
(root/'runtime-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(sources/'runtime-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
shutil.copy2(__file__,sources/'bundle-gnupg.py')
print(json.dumps({'runtime':str(root),'components':list(formulae),'binaries':len(copied)},indent=2))

# Preserve the original project license beside redistributed integration scripts.
project = Path(__file__).resolve().parent.parent
for name in ['LICENSE', 'THIRD_PARTY_NOTICES.md']:
    if (project/name).is_file(): shutil.copy2(project/name, sources/('GPGP-'+name))
