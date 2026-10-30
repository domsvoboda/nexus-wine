// SPDX-License-Identifier: MIT
import fs from 'node:fs';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const lock=JSON.parse(fs.readFileSync(path.join(root,'nexus/source.lock.json'),'utf8'));
const git=args=>execFileSync('git',args,{cwd:root,encoding:'utf8'}).trim();
if(lock.base!=='7fc704ef49c50e9702c9983a5250d5738697bb04'||!/^[a-f0-9]{40}$/.test(lock.xgameruntime))throw Error('Unpinned Wine/runtime source');
const link=git(['ls-files','--stage','--','dlls/xgameruntime']);
if(link!==`160000 ${lock.xgameruntime} 0\tdlls/xgameruntime`)throw Error('Wrong C++ runtime gitlink');
if(git(['config','-f','.gitmodules','--get','submodule.dlls/xgameruntime.url'])!=='https://github.com/domsvoboda/nexus-xgameruntime.git')throw Error('Wrong C++ runtime fork');
if(fs.readFileSync(path.join(root,'configure.ac'),'utf8').includes('WINE_CONFIG_MAKEFILE(dlls/xgameruntime)'))throw Error('C++ runtime must use its upstream CMake build');
for(const [name,expected]of Object.entries(lock.files)){
  if(!/^(?:configure\.ac|nexus\/(?:tools\/package-register\.c|tests\/diagnostics-(?:options|channel|event-options)\.cpp)|loader\/wine\.inf\.in|include\/(?:appmodel\.h|windows\.(?:applicationmodel|foundation\.diagnostics)\.idl|Makefile\.in)|dlls\/[a-zA-Z0-9_.\/-]+)$/.test(name)||name.includes('..')||!/^[a-f0-9]{64}$/.test(expected))throw Error('Unsafe source lock');
  const actual=crypto.createHash('sha256').update(fs.readFileSync(path.join(root,name))).digest('hex');
  if(actual!==expected)throw Error('Wine source mismatch: '+name);
}
console.log('Pinned Wine source and C++ gitlink checks passed. Full runtime validation is separate.');
