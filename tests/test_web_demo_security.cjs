// Behavioral regressions against the actual inline demo functions; synthetic state only.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { parse } = require('@babel/parser');
const html = fs.readFileSync('web_demo/wasm_browser_example_FULL.html', 'utf8');
const source = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
const ast = parse(source, { sourceType: 'module' });
function declaration(name) {
    const node = ast.program.body.find(n => n.id?.name === name || n.declarations?.some(d => d.id.name === name));
    assert.ok(node, `missing ${name}`);
    return source.slice(node.start, node.end);
}
function context(extra = {}) {
    return vm.createContext({ Uint8Array, DataView, TextEncoder, TextDecoder, Map, Set, Promise, Error, ...extra });
}
test('file envelopes omit original names and retain payload bytes and v4 decoding', () => {
    const c = context({ encoder: new TextEncoder(), decoder: new TextDecoder(), getSecurityParams: () => ({memoryKib:131072, iterations:8}) });
    vm.runInContext(declaration('packPayload') + declaration('unpackPayload'), c);
    const salt = new Uint8Array(16).fill(7), nonce = new Uint8Array(12).fill(8), cipher = new Uint8Array(64).fill(9);
    const packed = c.packPayload(salt, nonce, cipher, 'private-client-keys.zip');
    assert.equal(packed[0], 4);
    assert.equal(Buffer.from(packed).includes(Buffer.from('private-client-keys')), false);
    const parsed = c.unpackPayload(packed);
    assert.equal(parsed.fileName, 'meow-file.bin');
    assert.deepEqual(parsed.ciphertext, cipher);
    assert.deepEqual(parsed.salt, salt);
    assert.equal(parsed.memoryKib, 131072);
    assert.equal(parsed.iterations, 8);
    assert.equal(c.unpackPayload(c.packPayload(salt, nonce, cipher, null)).version, 3);
});
test('panic invalidates both live key pairs, cancels requests, stops worker and clears UI', async () => {
    const fsSecret = new Uint8Array(32).fill(42), pqSecret = new Uint8Array(64).fill(43);
    const elements = new Map();
    const field = {value:'secret'}, result = {textContent:'previous plaintext'};
    const storage = new Map([['meow_fs_keypair','secret'], ['meow_pq_keypair','secret'], ['unrelated','keep']]);
    let terminated = 0, rejected = 0, stopped = 0;
    const c = context({
        uploadedFileData:new Uint8Array([1]), animatedFileData:null, duressUploadedFileData:null,
        uploadedFileName:'private', animatedFileName:null, duressUploadedFileName:null, catBinaryData:'101',
        fsKeyPair:{secret:fsSecret}, pqKeyPair:{mlkemSecret:pqSecret}, sessionRevoked:false,
        cryptoWorker:{terminate(){terminated++;}}, wasm:{}, workerReady:true, useWorker:true,
        pendingRequests:new Map([[1,{reject(){rejected++;}}]]),
        window:{catModeStop(){stopped++;},catAnimatedStop(){stopped++;}},
        sessionStorage:{getItem:k=>storage.get(k)??null,removeItem:k=>storage.delete(k)},
        document:{getElementById(id){if(!elements.has(id))elements.set(id,{textContent:'old'});return elements.get(id);},querySelectorAll:s=>s.includes('password')?[field]:[result]},
        hideProgress(){},
    });
    vm.runInContext(declaration('wipeDemoSession') + declaration('workerCall'), c);
    assert.equal(c.wipeDemoSession().length,2);
    assert.ok(fsSecret.every(x=>x===0));assert.ok(pqSecret.every(x=>x===0));
    assert.equal(c.fsKeyPair,null);assert.equal(c.pqKeyPair,null);assert.equal(c.wasm,null);
    assert.equal(terminated,1);assert.equal(rejected,1);assert.equal(stopped,2);
    assert.equal(c.pendingRequests.size,0);assert.equal(storage.get('unrelated'),'keep');
    assert.equal(field.value,'');assert.equal(result.textContent,'');
    assert.equal(elements.get('log').textContent,'');
    await assert.rejects(c.workerCall('generate_keypair',{}),/Session cleared/);
    // Main-thread fallback must also refuse use after panic.
    vm.runInContext(declaration('crypto')+'; this.api = crypto;',c);
    await assert.rejects(c.api.deriveKey(new Uint8Array(),new Uint8Array()),/Session cleared/);
    await assert.rejects(c.api.decrypt(new Uint8Array(),new Uint8Array(),new Uint8Array()),/Session cleared/);
    c.sessionStorage.getItem=()=>{throw new Error('storage disabled');};
    assert.doesNotThrow(()=>c.wipeDemoSession());
});
test('all panic paths use the same wipe and asynchronous key imports reject revoked sessions', () => {
    assert.equal((source.match(/wipeDemoSession\(\);/g)||[]).length,2);
    assert.match(source,/reader.onload = function\(e\) \{\s*try \{\s*if \(sessionRevoked\)/);
    assert.match(source,/await file.text\(\);\s*if \(sessionRevoked\)/);
});
test('logs omit key bytes and plaintext excerpts; bundled QR paths exist', () => {
    const logging=source.split('\n').filter(line=>/\blog\(/.test(line)).join('\n');
    assert.doesNotMatch(logging,/keyResult\.data|plaintext\.substring|uploadedFileName\}|decodedFileName\}|animatedFileName\}|duressUploadedFileName\}/);
    assert.doesNotMatch(source,/https:\/\/(?:api\.qrserver|quickchart|cdn\.|unpkg|cdnjs)/);
    for(const name of ['static/jsQR.js','static/qrcode.min.js'])assert.ok(fs.existsSync('web_demo/'+name));
    const sw=fs.readFileSync('web_demo/sw.js','utf8');
    const assets=sw.match(/const PRECACHE_ASSETS = \[([\s\S]*?)\];/)[1];
    for(const match of assets.matchAll(/'([^']+)'/g))assert.ok(fs.existsSync('web_demo/'+match[1]),match[1]);
    assert.match(sw,/name.startsWith\('meow-decoder-'\)/);
});
test('real shipped WASM encrypts file envelope, decrypts bytes, and rejects tampering', async () => {
    const wasm = await import('../crypto_core/pkg/crypto_core.js');
    await wasm.default({module_or_path:fs.readFileSync('crypto_core/pkg/crypto_core_bg.wasm')});
    const c = context({encoder:new TextEncoder(),decoder:new TextDecoder(),getSecurityParams:()=>({memoryKib:65536,iterations:3})});
    vm.runInContext(declaration('packPayload')+declaration('unpackPayload'),c);
    const salt=wasm.generate_salt().data, nonce=wasm.generate_nonce().data;
    const key=wasm.derive_key(new TextEncoder().encode('Synthetic regression passphrase'),salt,65536,3).data;
    const bytes=new Uint8Array([0,255,254,128,0,17]);
    const cipher=wasm.encrypt(bytes,key,nonce,null).data;
    const packed=c.packPayload(salt,nonce,cipher,'confidential.zip');
    const parsed=c.unpackPayload(packed);
    assert.deepEqual(wasm.decrypt(parsed.ciphertext,key,parsed.nonce,null).data,bytes);
    parsed.ciphertext[0]^=1;
    const rejected = wasm.decrypt(parsed.ciphertext,key,parsed.nonce,null);
    assert.equal(rejected.success, false);
    assert.equal(rejected.data.length, 0);
    assert.ok(rejected.error);
    key.fill(0);
});
