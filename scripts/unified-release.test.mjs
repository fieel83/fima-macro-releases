import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {verifyUnifiedMetadata,verifyActualVersion,verifyRuntimeReceipts} from './unified-release.mjs';
const dir=new URL('../releases/1.0.136/',import.meta.url);
const read=n=>JSON.parse(fs.readFileSync(new URL(n,dir)));
const policy=read('policy.json'),hub=read('hub-release-signed.json');
const variants={Member:read('Member-catalog-update-envelope.json'),Owner:read('Owner-catalog-update-envelope.json')};
test('matching signed Hub, Member and Owner 136 metadata passes',()=>verifyUnifiedMetadata(policy,hub,variants));
for(const label of ['Member','Owner'])test('stale or substituted '+label+' fails',()=>{
 const changed=structuredClone(variants);changed[label].manifest.version='1.0.133';assert.throws(()=>verifyUnifiedMetadata(policy,hub,changed));
});
test('a forged common version fails signed Hub verification',()=>{
 const p=structuredClone(policy);p.version='1.0.137';p.tag='v1.0.137';assert.throws(()=>verifyUnifiedMetadata(p,hub,variants));
});
test('Member and Owner identities cannot be swapped',()=>{
 const p=structuredClone(policy);[p.variants[0].executableSha256,p.variants[1].executableSha256]=[p.variants[1].executableSha256,p.variants[0].executableSha256];assert.throws(()=>verifyUnifiedMetadata(p,hub,variants));
});
test('non executable bytes cannot pass the actual version check',()=>assert.throws(()=>verifyActualVersion(Buffer.alloc(200),'1.0.136')));

test('unsigned variant version drift fails even when signed metadata is intact',()=>{
 const p=structuredClone(policy);p.variants[0].version='1.0.133';assert.throws(()=>verifyUnifiedMetadata(p,hub,variants));
});
test('a missing pinned distribution ZIP fails',()=>{
 const p=structuredClone(policy);p.assets=p.assets.filter(a=>a.name!==p.variants[1].zip);assert.throws(()=>verifyUnifiedMetadata(p,hub,variants));
});

test('runtime-ready receipts bind both products to their exact signed package identities',()=>{
 const receipts=policy.variants.map(v=>({metadata:{productId:v.productId,appVersion:policy.version,
  executableSha256:v.executableSha256,packageIdentity:v.packageIdentity,clientReported:true}}));
 verifyRuntimeReceipts(policy,receipts);
 const forged=structuredClone(receipts);forged[0].metadata.packageIdentity='a'.repeat(64);
 assert.throws(()=>verifyRuntimeReceipts(policy,forged));
 assert.throws(()=>verifyRuntimeReceipts(policy,[receipts[0],receipts[0],receipts[1]]));
});
