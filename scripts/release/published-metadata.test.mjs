import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkPublishedMetadata, verifyPublishedMetadata } from './verify-published.mjs';
const server={name:'io.github.MHaggis/security-detections-mcp',version:'3.3.3',packages:[{identifier:'security-detections-mcp',version:'3.3.3'}]};
const published={name:'security-detections-mcp',version:'3.3.3',mcpName:server.name};

test('persisted npm identity must exactly match the materialized Registry metadata',()=>{
  verifyPublishedMetadata(published,server);
  for(const invalid of [null,[],{}, {...published,name:'other'}, {...published,version:'3.3.2'},
    {...published,mcpName:'io.github.mhaggis/security-detections-mcp'}, {...published,mcpName:undefined}]) {
    assert.throws(()=>verifyPublishedMetadata(invalid,server));
  }
  assert.throws(()=>verifyPublishedMetadata({...published,mcpName:'io.github.mhaggis/security-detections-mcp'},
    {...server,name:'io.github.mhaggis/security-detections-mcp'}));
});

test('exact npm endpoint is read without auth; missing or malformed results fail closed',async()=>{
  await checkPublishedMetadata(server,async(url,options)=>{
    assert.equal(url,'https://registry.npmjs.org/security-detections-mcp/3.3.3');
    assert.equal(options.redirect,'error');assert.equal(options.headers,undefined);
    return {status:200,json:async()=>published};
  });
  for(const status of [404,403,500]) await assert.rejects(checkPublishedMetadata(server,async()=>({status})),/exact published/);
  await assert.rejects(checkPublishedMetadata(server,async()=>({status:200,json:async()=>({})})),/name mismatch/);
  await assert.rejects(checkPublishedMetadata(server,async()=>({status:200,json:async()=>{throw new SyntaxError('malformed JSON')}})),/malformed/);
  await assert.rejects(checkPublishedMetadata(server,async()=>{throw new Error('offline')}),/offline/);
});
