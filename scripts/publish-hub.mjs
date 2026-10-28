import fs from 'node:fs';
import { createHash, verify } from 'node:crypto';
import assert from 'node:assert/strict';
const policy=JSON.parse(fs.readFileSync('releases/1.0.135/policy.json'));
const sha=b=>createHash('sha256').update(b).digest('hex');
const publicKey='-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAogP5GW0r1kAa2pHFrlqqMqN/OeCaQpgCJghuCNTdfPQ=\n-----END PUBLIC KEY-----';
const signedBytes=fs.readFileSync('releases/1.0.135/hub-release-signed.json');
const nativeBytes=fs.readFileSync('releases/1.0.135/hub-native-acceptance.json');
assert.equal(sha(signedBytes),policy.manifest.sha256);
assert.equal(sha(nativeBytes),policy.native.sha256);
const signed=JSON.parse(signedBytes), p=signed.payload, native=JSON.parse(nativeBytes);
assert.equal(signed.signatureAlgorithm,'ed25519');
assert(verify(null,Buffer.from(JSON.stringify(p)),publicKey,Buffer.from(signed.signature,'base64')));
assert.deepEqual(p,{format:'fima-hub-release-v1',version:policy.version,sha256:policy.installer.sha256,size:policy.installer.size,downloadUrl:'/downloads/FIMA-Hub-Setup.exe',publisherThumbprint:null});
assert.equal(native.result,'PASS_NATIVE_INSTALL_UPGRADE_AND_UNAUTHENTICATED_HUB_WINDOW');
assert.equal(native.hostDesktopUsed,false);
assert.equal(native.authenticatedCustomerFlow,false);
assert(native.stages.every(s=>s.pass===true));
for(const version of ['1.0.133','1.0.134','1.0.135']) {
  assert(native.stages.some(s=>s.stage==='native-install' && s.version===version+'.0' && s.exitCode===0));
}
assert(native.stages.some(s=>s.stage==='download-integrity' && s.sha256===policy.installer.sha256 && s.version===policy.version));
if(process.argv.includes('--verify-local')) { console.log('PASS: exact signed candidate and native acceptance evidence'); process.exit(0); }
assert.equal(process.env.GITHUB_ACTIONS,'true');
assert.equal(process.env.GITHUB_REPOSITORY,'fieel83/fima-macro-releases');
assert.equal(process.env.GITHUB_EVENT_NAME,'workflow_dispatch');
assert.equal(process.env.GITHUB_REF,'refs/heads/main');
assert.equal(process.env.GITHUB_ACTOR_ID,String(policy.ownerId));
assert.equal(process.env.GITHUB_WORKFLOW_REF,'fieel83/fima-macro-releases/.github/workflows/hub-public-release.yml@refs/heads/main');
const event=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH));
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
assert.equal(release.assets.length,3);
for(const expected of [policy.installer,policy.manifest,policy.native]) {
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
console.log(JSON.stringify({product:policy.product,version:policy.version,releaseUrl:published.html_url,sha256:policy.installer.sha256,run:run.html_url,scope:policy.acceptanceScope}));
