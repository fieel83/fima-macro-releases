import fs from 'node:fs';
import {createPublicKey,verify} from 'node:crypto';
import assert from 'node:assert/strict';
import {sha,verifyUnifiedMetadata,verifyActualVersion} from './unified-release.mjs';
const directory='releases/1.0.136/';
const read=name=>JSON.parse(fs.readFileSync(directory+name));
const policy=read('policy.json');
const variants=Object.fromEntries(policy.variants.map(v=>[v.label,read(v.envelope)]));
verifyUnifiedMetadata(policy,read(policy.manifest),variants);
for(const name of [policy.manifest,...policy.variants.map(v=>v.envelope)]) {
 const b=fs.readFileSync(directory+name),a=policy.assets.find(a=>a.name===name);assert(a);assert.equal(sha(b),a.sha256);assert.equal(b.length,a.size);
}
assert.equal(policy.nsisWaiver.version,'1.0.136');assert.equal(policy.version,policy.nsisWaiver.version);
assert.equal(policy.nsisWaiver.installerSha256,policy.installer.sha256);
if(process.argv.includes('--verify-metadata')){console.log('PASS unified signed metadata; native/runtime and RSA policy gates still required');process.exit(0);}
const publicXml="<RSAKeyValue><Modulus>2OYlvluknnl2tefzkwCdPwlS3eCfQvRI7APs6fchs15x3wxX87mwF9ghp6vv6bSRSn2ZvNHsDoFDzYFtibAQxkyFO0Rk5ayQ9LDIeadu1xWDDxiB5cds0rkPk/SxY5ecFhvKsFpM2jVG+uT/48K9j3PdTkdDeR/GD3lTmLDQg+6UbRcLbvOsedvslEa484Ub36owcZ+Y4rai1jkGW8oF22NkiyPy7CfAnzxFVD/l5FU8ENfpl85cuiD9xi13e3LTB6f48gjTtmQPLjk94FkvxAaVLDqQq3ASVstxDCOaGLUpGuxjsSaoLJC/Df88tanmVv/wK9KgBxRrKOdq3qwQiT581U5RMCE8HBYv9TCjm192LjEFCKqKvCSkdbUxVvdACK+c5LAzuV3hg2nObv7FSaBeHXm2VCVmJTaylcnUAA20dtHwxsV3uK5CWIMehuUIrfDpJmLaVcvULz0d0S28PYn+9Mrp/ioXs3hxWL5Ei2xZbGs7uwz2T3tAZTiAHyn9</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
const field=name=>Buffer.from(publicXml.match(new RegExp('<'+name+'>([^<]+)</'+name+'>'))[1],'base64').toString('base64url');
const policyKey=createPublicKey({key:{kty:'RSA',n:field('Modulus'),e:field('Exponent')},format:'jwk'});
for(const v of policy.variants) {
 const n=read(v.native);assert.equal(n.variant,v.label);assert.equal(n.version,policy.version);assert.equal(n.result.ok,true);assert.equal(n.result.productId,v.productId);
 assert.equal(n.native.isolatedDesktop,true);assert.equal(n.native.inputDesktopSwitched,false);assert.equal(n.native.exitCode,0);assert(n.native.responsiveWindows>0);assert.equal(n.verifiedExecutableSha256,v.executableSha256);
 const e=read(v.updatePolicy),payload=Buffer.from(e.payload,'base64');assert.equal(sha(payload),v.approvedPolicySha256);
 assert(verify('sha256',Buffer.concat([Buffer.from('FIMA-UPDATE-POLICY-V1\n'),payload]),policyKey,Buffer.from(e.signature,'base64')));
 const p=JSON.parse(payload);assert.equal(p.Version,policy.version);assert.equal(p.Product,v.productId);assert.equal(p.Channel,'stable');assert.equal(p.MinimumVersion,'1.0.132');assert.equal(p.Mandatory,false);
 assert(Date.parse(p.ExpiresAt)>Date.now());assert(Date.parse(p.IssuedAt)<=Date.now()+120000);assert(Date.parse(p.ExpiresAt)-Date.parse(p.IssuedAt)<=7*86400000);
 for(const name of [v.native,v.updatePolicy]){const b=fs.readFileSync(directory+name),a=policy.assets.find(a=>a.name===name);assert(a,'Evidence must be pinned as an immutable release asset');assert.equal(sha(b),a.sha256);assert.equal(b.length,a.size);}
}
const readyBytes=fs.readFileSync(directory+policy.runtimeReady),readyAsset=policy.assets.find(a=>a.name===policy.runtimeReady);assert(readyAsset);assert.equal(sha(readyBytes),readyAsset.sha256);assert.equal(readyBytes.length,readyAsset.size);
const ready=JSON.parse(readyBytes).receipts;
for(const v of policy.variants){const r=ready.find(x=>x.metadata.productId===v.productId);assert(r);assert.equal(r.metadata.appVersion,policy.version);assert.equal(r.metadata.executableSha256,v.executableSha256);assert.equal(r.metadata.clientReported,true);assert.match(r.metadata.packageIdentity,/^[a-f0-9]{64}$/);}
const health=await(await fetch('https://api.fimamacro.com/health',{signal:AbortSignal.timeout(30000)})).json();assert.equal(health.ok,true);assert.equal(health.commit,policy.backendSha);
if(process.argv.includes('--verify-local')){console.log('PASS all local and production runtime gates');process.exit(0);}
assert.equal(process.env.GITHUB_ACTIONS,'true');
assert.equal(process.env.GITHUB_REPOSITORY,'fieel83/fima-macro-releases');
assert.equal(process.env.GITHUB_EVENT_NAME,'workflow_dispatch');
assert.equal(process.env.GITHUB_REF,'refs/heads/main');
assert.equal(process.env.GITHUB_ACTOR_ID,String(policy.ownerId));
assert.equal(process.env.GITHUB_WORKFLOW_REF,'fieel83/fima-macro-releases/.github/workflows/hub-public-release.yml@refs/heads/main');
const event=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH));
assert.equal(event.inputs.product,'unified');
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
  if(expected.name===policy.installer.name||policy.variants.some(v=>'file-'+v.executableSha256===expected.name))verifyActualVersion(bytes,policy.version);
}
// Recheck production and draft identity immediately before the sole publication mutation.
const finalHealth=await(await fetch('https://api.fimamacro.com/health',{signal:AbortSignal.timeout(30000)})).json();assert.equal(finalHealth.ok,true);assert.equal(finalHealth.commit,policy.backendSha);
assert.equal((await api('/branches/main')).commit.sha,event.inputs.target);
const current=await api('/releases/'+release.id);
assert.equal(current.draft,true); assert.equal(current.target_commitish,event.inputs.target);
assert.equal(current.tag_name,policy.tag); assert.equal(current.author.id,policy.ownerId);
assert.deepEqual(current.assets.map(a=>[a.id,a.digest,a.size,a.updated_at]),release.assets.map(a=>[a.id,a.digest,a.size,a.updated_at]));
const published=await api('/releases/'+release.id,'PATCH',{draft:false,make_latest:'true'});
assert.equal(published.draft,false); assert.equal(published.tag_name,policy.tag);
console.log(JSON.stringify({product:policy.product,version:policy.version,releaseUrl:published.html_url,packages:policy.variants.map(v=>policy.assets.find(a=>a.name===v.zip)),run:run.html_url,scope:policy.acceptanceScope}));
