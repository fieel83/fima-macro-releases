import assert from 'node:assert/strict';
import {verify,createHash} from 'node:crypto';
export const publicKey='-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAogP5GW0r1kAa2pHFrlqqMqN/OeCaQpgCJghuCNTdfPQ=\n-----END PUBLIC KEY-----';
export const sha=b=>createHash('sha256').update(b).digest('hex');
export function peVersions(bytes) {
 assert.equal(bytes.subarray(0,2).toString(),'MZ');
 const pe=bytes.readUInt32LE(60);assert.equal(bytes.subarray(pe,pe+4).toString(),'PE\0\0');
 const optional=pe+24,magic=bytes.readUInt16LE(optional);assert([0x10b,0x20b].includes(magic));
 const table=optional+bytes.readUInt16LE(pe+20),sections=bytes.readUInt16LE(pe+6);
 const rvaOffset=rva=>{for(let n=0;n<sections;n++){const s=table+n*40,va=bytes.readUInt32LE(s+12),size=Math.max(bytes.readUInt32LE(s+8),bytes.readUInt32LE(s+16));if(rva>=va&&rva<va+size)return bytes.readUInt32LE(s+20)+rva-va;}throw Error('Unmapped PE resource');};
 const resources=rvaOffset(bytes.readUInt32LE(optional+(magic===0x20b?112:96)+16));
 const entries=off=>{const n=bytes.readUInt16LE(off+12)+bytes.readUInt16LE(off+14);assert(n<10000);return Array.from({length:n},(_,i)=>({id:bytes.readUInt32LE(off+16+i*8),target:bytes.readUInt32LE(off+20+i*8)}));};
 let entry=entries(resources).find(e=>e.id===16);assert(entry,'Missing PE VERSIONINFO resource');
 for(let depth=0;entry.target&0x80000000;depth++){assert(depth<4);entry=entries(resources+(entry.target&0x7fffffff))[0];assert(entry);}
 const data=resources+entry.target,start=rvaOffset(bytes.readUInt32LE(data)),size=bytes.readUInt32LE(data+4),resource=bytes.subarray(start,start+size);
 assert(resource.length===size);const key=Buffer.from('VS_VERSION_INFO\0','utf16le');assert(resource.subarray(6,6+key.length).equals(key));
 const fixed=(6+key.length+3)&~3;assert.equal(resource.readUInt32LE(fixed),0xfeef04bd);
 const version=offset=>{const ms=resource.readUInt32LE(fixed+offset),ls=resource.readUInt32LE(fixed+offset+4);return [ms>>>16,ms&65535,ls>>>16,ls&65535].join('.');};
 return {file:version(8),product:version(16)};
}
export function verifyUnifiedMetadata(policy,hub,variants) {
 assert.equal(policy.format,'fima-unified-release-v1');assert.match(policy.version,/^\d+\.\d+\.\d+$/);
 assert.equal(policy.ownerId,215785493);assert.equal(policy.tag,'v'+policy.version);
 assert.equal(policy.variants.length,2);assert.equal(new Set(policy.assets.map(a=>a.name)).size,policy.assets.length);
 assert.deepEqual(policy.variants.map(v=>v.label).sort(),['Member','Owner']);
 assert.equal(hub.signatureAlgorithm,'ed25519');assert(verify(null,Buffer.from(JSON.stringify(hub.payload)),publicKey,Buffer.from(hub.signature,'base64')));
 assert.deepEqual(hub.payload,{format:'fima-hub-release-v1',version:policy.version,sha256:policy.installer.sha256,size:policy.installer.size,downloadUrl:'/downloads/FIMA-Hub-Setup.exe',publisherThumbprint:null});
 for(const v of policy.variants){
  assert.equal(v.version,policy.version,'Variant metadata version must match the common release');
  const e=variants[v.label],m=e.manifest;
  assert.equal(e.signatureAlgorithm,'ed25519');assert(verify(null,Buffer.from(JSON.stringify(m)),publicKey,Buffer.from(e.signature,'base64')));
  assert.equal(m.version,policy.version,'All three signed application versions must match');
  assert.equal(m.format,'fima-update-manifest-v1');assert.equal(m.schemaVersion,1);
  assert.equal(m.productId,v.label==='Member'?'fima-macro':'fima-macro-owner');assert.equal(v.productId,m.productId);
  assert.equal(m.channel,v.label==='Member'?'candidate':'owner-candidate');assert.equal(m.channel,v.channel);
  assert.equal(m.files.find(f=>f.path==='FimaMacroStudio.exe')?.sha256,v.executableSha256);
  const zip=policy.assets.find(a=>a.name===v.zip);assert(zip);assert.match(zip.sha256,/^[a-f0-9]{64}$/);assert(zip.size>0);
  assert(m.files.length>=80);assert.equal(new Set(m.files.map(f=>f.path.toLowerCase())).size,m.files.length);
  for(const f of m.files){
   assert(!f.path.includes('..')&&!f.path.startsWith('/')&&!f.path.includes('\\'));assert.match(f.sha256,/^[a-f0-9]{64}$/);
   const a=policy.assets.find(a=>a.name==='file-'+f.sha256);assert(a);assert.equal(a.sha256,f.sha256);assert.equal(a.size,f.size);
  }
 }
 assert.notEqual(policy.variants[0].executableSha256,policy.variants[1].executableSha256);
}
export function verifyActualVersion(bytes,version) {
 const versions=peVersions(bytes);
 for(const v of Object.values(versions))assert([version,version+'.0'].includes(v.split('+')[0]),'Actual executable version mismatch');
 return versions;
}
