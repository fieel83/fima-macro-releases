import fs from 'node:fs';
import { createHash, verify } from 'node:crypto';
import assert from 'node:assert/strict';
const policy=JSON.parse(fs.readFileSync('releases/1.0.132/policy.json'));
const sha=b=>createHash('sha256').update(b).digest('hex');
const publicKey='-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAogP5GW0r1kAa2pHFrlqqMqN/OeCaQpgCJghuCNTdfPQ=\n-----END PUBLIC KEY-----';
assert.equal(policy.version,'1.0.132');assert.equal(policy.tag,'v1.0.132');assert.equal(policy.ownerId,215785493);
assert.equal(policy.variants.length,2);assert.equal(new Set(policy.assets.map(x=>x.name)).size,policy.assets.length);
for(const v of policy.variants){
 const signedBytes=fs.readFileSync('releases/1.0.132/'+v.envelope),nativeBytes=fs.readFileSync('releases/1.0.132/'+v.native);
 for(const [name,b] of [[v.envelope,signedBytes],[v.native,nativeBytes]]){const a=policy.assets.find(x=>x.name===name);assert(a);assert.equal(a.sha256,sha(b));assert.equal(a.size,b.length);}
 const signed=JSON.parse(signedBytes),m=signed.manifest,n=JSON.parse(nativeBytes);
 assert.equal(signed.signatureAlgorithm,'ed25519');assert(verify(null,Buffer.from(JSON.stringify(m)),publicKey,Buffer.from(signed.signature,'base64')));
 assert.equal(m.format,'fima-update-manifest-v1');assert.equal(m.schemaVersion,1);assert.equal(m.version,policy.version);assert.equal(m.productId,v.productId);assert.equal(m.channel,v.channel);
 assert.equal(v.productId,v.label==='Member'?'fima-macro':'fima-macro-owner');assert.equal(n.variant,v.label);assert.equal(n.version,policy.version);
 assert.equal(n.result.ok,true);assert.equal(n.result.productId,v.productId);assert.equal(n.native.isolatedDesktop,true);assert.equal(n.native.inputDesktopSwitched,false);assert.equal(n.native.exitCode,0);assert(n.native.responsiveWindows>0);
 assert.equal(n.verifiedExecutableSha256,v.executableSha256);assert.equal(m.files.find(x=>x.path==='FimaMacroStudio.exe').sha256,v.executableSha256);
 assert(policy.assets.some(x=>x.name===v.zip));assert(m.files.length>=80);
 for(const f of m.files){assert(!f.path.includes('..'));assert(!f.path.startsWith('/'));assert.match(f.sha256,/^[a-f0-9]{64}$/);const a=policy.assets.find(x=>x.name==='file-'+f.sha256);assert(a);assert.equal(a.sha256,f.sha256);assert.equal(a.size,f.size);}
}
const receiptBytes=fs.readFileSync('releases/1.0.132/'+policy.runtimeReady);
const receiptAsset=policy.assets.find(a=>a.name===policy.runtimeReady);assert.equal(sha(receiptBytes),receiptAsset.sha256);assert.equal(receiptBytes.length,receiptAsset.size);
const ready=JSON.parse(receiptBytes).receipts;
for(const v of policy.variants){const r=ready.find(x=>x.metadata.productId===v.productId);assert(r);assert.equal(r.metadata.appVersion,policy.version);assert.equal(r.metadata.executableSha256,v.executableSha256);assert.equal(r.metadata.clientReported,true);assert.match(r.metadata.packageIdentity,/^[a-f0-9]{64}$/);}
if(process.argv.includes('--verify-local')){console.log('PASS: both signed runtime candidates and native evidence; '+policy.assets.length+' immutable assets');process.exit(0);}
assert.equal(process.env.GITHUB_ACTIONS,'true');
assert.equal(process.env.GITHUB_REPOSITORY,'fieel83/fima-macro-releases');
assert.equal(process.env.GITHUB_EVENT_NAME,'workflow_dispatch');
assert.equal(process.env.GITHUB_REF,'refs/heads/main');
assert.equal(process.env.GITHUB_ACTOR_ID,String(policy.ownerId));
assert.equal(process.env.GITHUB_WORKFLOW_REF,'fieel83/fima-macro-releases/.github/workflows/hub-public-release.yml@refs/heads/main');
const event=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH));
assert.equal(event.inputs.product,'macro-runtime');
assert.equal(event.inputs.target,process.env.GITHUB_SHA);
assert.match(event.inputs.target,/^[a-f0-9]{40}$/);
assert.equal(Number(event.sender.id),policy.ownerId);
assert.match(event.inputs.release_id,/^\d+$/);
const base='https://api.github.com/repos/fieel83/fima-macro-releases';
async function api(route,method='GET',body) {
  const r=await fetch(base+route,{method,headers:{Authorization:'Bearer '+process.env.GH_TOKEN,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(30000)});
  if(!r.ok) throw Error('GitHub API '+r.status+' '+route);
  return r.json();
}
const run=await api('/actions/runs/'+process.env.GITHUB_RUN_ID+'/attempts/'+process.env.GITHUB_RUN_ATTEMPT);
assert.equal(run.event,'workflow_dispatch'); assert.equal(run.head_sha,event.inputs.target); assert.equal(run.head_branch,'main');
assert.equal(run.status,'in_progress'); assert.equal(run.actor.id,policy.ownerId); assert.equal(run.triggering_actor.id,policy.ownerId);
assert.equal(run.path,'.github/workflows/hub-public-release.yml');
const workflow=await api('/actions/workflows/'+run.workflow_id);
assert.equal(workflow.state,'active'); assert.equal(workflow.path,'.github/workflows/hub-public-release.yml');
assert.equal((await api('/branches/main')).commit.sha,event.inputs.target);
const release=await api('/releases/'+event.inputs.release_id);
assert.equal(release.draft,true); assert.equal(release.prerelease,false);
assert.equal(release.tag_name,policy.tag); assert.equal(release.target_commitish,event.inputs.target);
assert.equal(release.author.id,policy.ownerId);
assert.equal(release.assets.length,policy.assets.length);
for(const expected of policy.assets) {
  const matches=release.assets.filter(a=>a.name===expected.name); assert.equal(matches.length,1);
  const a=matches[0]; assert.equal(a.state,'uploaded'); assert.equal(a.uploader.id,policy.ownerId);
  assert.equal(a.digest,'sha256:'+expected.sha256);
  if(expected.size) assert.equal(a.size,expected.size);
  const r=await fetch(base+'/releases/assets/'+a.id,{headers:{Authorization:'Bearer '+process.env.GH_TOKEN,Accept:'application/octet-stream'},signal:AbortSignal.timeout(180000)});
  if(!r.ok) throw Error('Asset download '+r.status);
  const bytes=Buffer.from(await r.arrayBuffer()); assert.equal(bytes.length,a.size); assert.equal(sha(bytes),expected.sha256);
}
// Recheck branch and draft identity immediately before the sole publication mutation.
assert.equal((await api('/branches/main')).commit.sha,event.inputs.target);
const current=await api('/releases/'+release.id);
assert.equal(current.draft,true); assert.equal(current.target_commitish,event.inputs.target);
assert.equal(current.tag_name,policy.tag); assert.equal(current.author.id,policy.ownerId);
assert.deepEqual(current.assets.map(a=>[a.id,a.digest,a.size,a.updated_at]),release.assets.map(a=>[a.id,a.digest,a.size,a.updated_at]));
const published=await api('/releases/'+release.id,'PATCH',{draft:false,make_latest:'false'});
assert.equal(published.draft,false); assert.equal(published.tag_name,policy.tag);
console.log(JSON.stringify({product:policy.product,version:policy.version,releaseUrl:published.html_url,packages:policy.variants.map(v=>policy.assets.find(a=>a.name===v.zip)),run:run.html_url,scope:policy.acceptanceScope}));
