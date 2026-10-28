// SPDX-License-Identifier: LGPL-2.1-or-later
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const text=fs.readFileSync(new URL('../loader/wine.inf.in',import.meta.url),'utf8');
const section=name=>text.split('['+name+']')[1]?.split(/^\[/m)[0]??'';
test('StoreContext registration is available in native and Wow64 installations',()=>{
 for(const name of ['BaseInstall','BaseWow64Install'])assert.match(section(name),/\bMisc\b/);
 const misc=section('Misc');
 assert.match(misc,/Windows\.Services\.Store\.StoreContext,"DllPath",0,"%11%\\xgameruntime\.dll"/);
 assert.match(misc,/Windows\.Services\.Store\.StoreContext,"ThreadingModel",0x10001,0/);
 assert.equal((text.match(/Windows\.Services\.Store\.StoreContext,"DllPath"/g)||[]).length,1);
});
