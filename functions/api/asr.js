// Cloudflare Pages Function - Tencent Cloud ASR proxy
export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const action = body.action;

    const SECRET_ID = context.env.TENCENT_SECRET_ID;
    const SECRET_KEY = context.env.TENCENT_SECRET_KEY;
    const REGION = context.env.TENCENT_REGION || 'ap-guangzhou';

    if (!SECRET_ID || !SECRET_KEY) {
      return new Response(JSON.stringify({ error: 'API not configured' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    if (action === 'CreateRecTask') {
      return await handleCreateRecTask(body, SECRET_ID, SECRET_KEY, REGION);
    } else if (action === 'DescribeTaskStatus') {
      return await handleDescribeTaskStatus(body, SECRET_ID, SECRET_KEY, REGION);
    }
    return new Response(JSON.stringify({ error: 'Unknown action' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

async function handleCreateRecTask(body, secretId, secretKey, region) {
  const payload = JSON.stringify({
    EngineModelType: '16k_zh', ChannelNum: 1, ResTextFormat: 0, SourceType: 1,
    Data: body.audio, DataLen: body.dataLen
  });
  const resp = await tc3Request(secretId, secretKey, region, 'CreateRecTask', payload);
  const taskId = resp.Data && resp.Data.TaskId;
  if (!taskId) return new Response(JSON.stringify({ error: '创建任务失败' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  return new Response(JSON.stringify({ taskId: taskId }), { headers: { 'Content-Type': 'application/json' } });
}

async function handleDescribeTaskStatus(body, secretId, secretKey, region) {
  const payload = JSON.stringify({ TaskId: body.taskId });
  const resp = await tc3Request(secretId, secretKey, region, 'DescribeTaskStatus', payload);
  const data = resp.Data;
  return new Response(JSON.stringify({ status: data.Status, result: data.Result || '', errorMsg: data.ErrorMsg || '' }), { headers: { 'Content-Type': 'application/json' } });
}

async function tc3Request(secretId, secretKey, region, action, payloadStr) {
  const service = 'asr', host = 'asr.tencentcloudapi.com', version = '2019-06-14';
  const timestamp = Math.floor(Date.now() / 1000);
  const date = new Date(timestamp * 1000).toISOString().slice(0, 10);
  const hashedPayload = await sha256Hex(payloadStr);
  const canonicalHeaders = 'content-type:application/json; charset=utf-8\nhost:' + host + '\n';
  const signedHeaders = 'content-type;host';
  const canonicalRequest = 'POST\n/\n\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + hashedPayload;
  const algorithm = 'TC3-HMAC-SHA256';
  const credentialScope = date + '/' + service + '/tc3_request';
  const stringToSign = algorithm + '\n' + timestamp + '\n' + credentialScope + '\n' + await sha256Hex(canonicalRequest);
  const sd = await hmacSha256('TC3' + secretKey, date);
  const ss = await hmacSha256(sd, service);
  const sk = await hmacSha256(ss, 'tc3_request');
  const signature = await hmacSha256Hex(sk, stringToSign);
  const auth = algorithm + ' Credential=' + secretId + '/' + credentialScope + ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;
  const resp = await fetch('https://' + host, { method: 'POST', headers: { 'Content-Type': 'application/json; charset=utf-8', 'Host': host, 'X-TC-Action': action, 'X-TC-Version': version, 'X-TC-Timestamp': '' + timestamp, 'X-TC-Region': region, 'Authorization': auth }, body: payloadStr });
  return await resp.json();
}

async function sha256Hex(msg) { var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg)); return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''); }
async function hmacSha256(key, msg) { var enc = new TextEncoder(); var kb = typeof key === 'string' ? enc.encode(key) : new Uint8Array(key); var ck = await crypto.subtle.importKey('raw', kb, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', ck, enc.encode(msg))); }
async function hmacSha256Hex(key, msg) { var sig = await hmacSha256(key, msg); return Array.from(sig).map(b => b.toString(16).padStart(2, '0')).join(''); }
