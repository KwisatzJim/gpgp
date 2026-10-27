#!/usr/bin/env python3
"""Sign the embedded runtime before re-sealing the already built host app."""
import argparse, json, subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('app',type=Path);p.add_argument('--identity',required=True);a=p.parse_args()
app=a.app.resolve();root=app/'Contents/Resources/GnuPG'
files=json.loads((root/'runtime-manifest.json').read_text())['executables']
def sign(path):
 subprocess.run(['codesign','--force','--sign',a.identity]+([] if a.identity=='-' else ['--timestamp'])+['--options','runtime',str(path)],check=True)
for relative in sorted(files,key=lambda x: not x.endswith('.dylib')): sign(root/relative)
sign(root/'libexec/pinentry-mac.app')
sign(app)
subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True)
