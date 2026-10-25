import assert from 'node:assert/strict';
import { JsonRpcProvider, Wallet } from 'ethers';

// The fixture server is started separately with `zig-out/bin/hightower-rpc-test`.
const provider = new JsonRpcProvider('http://127.0.0.1:18545/', { chainId: 1, name: 'hightower' }, { staticNetwork: true });
const wallet = new Wallet('0x' + '00'.repeat(31) + '01');
const sender = wallet.address;
const recipient = '0x2222222222222222222222222222222222222222';
const topic = `0x${'11'.repeat(32)}`;
let nextId = 1;
async function rpc(method, params = []) {
  const response = await fetch('http://127.0.0.1:18545/', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
  });
  assert.equal(response.status, 200);
  return response.json();
}

assert.equal((await provider.getNetwork()).chainId, 1n);
assert.equal(await provider.getBlockNumber(), 1);
const block = await provider.getBlock(1, true);
assert.equal(block.number, 1);
assert.equal(block.transactions.length, 1);
assert.equal(block.prefetchedTransactions[0].from, sender);
const txHash = block.transactions[0];
const receipt = await provider.getTransactionReceipt(txHash);
assert.equal(receipt.status, 1);
assert.equal(receipt.logs.length, 1);
assert.equal(receipt.logs[0].topics[0], topic);
assert.equal((await rpc('eth_getTransactionReceipt', [txHash])).result.logs[0].logIndex, '0x0');
assert.equal((await rpc('eth_getBlockByHash', [block.hash, false])).result.transactions[0], txHash);
assert.equal((await rpc('eth_getBlockByNumber', ['0x999', false])).result, null);
const logs = await provider.getLogs({ fromBlock: 1, toBlock: 1, address: recipient, topics: [topic] });
assert.equal(logs.length, 1);
assert.equal(logs[0].transactionHash, txHash);
assert.equal((await rpc('eth_getLogs', [{ fromBlock: '0x1', toBlock: '0x1', topics: [topic] }])).result.length, 1);
assert.equal((await rpc('eth_getLogs', [{ fromBlock: '0x1', toBlock: '0x1', topics: [`0x${'ff'.repeat(32)}`] }])).result.length, 0);
assert.equal((await rpc('eth_getLogs', [{ fromBlock: '0x1', toBlock: '0x1', topics: [null, null] }])).result.length, 0);
assert.equal(await provider.getBalance(sender) < 1_000_000_000_000_000_000n, true);
assert.equal(await provider.call({ to: recipient }), '0x');
assert.equal(await provider.estimateGas({ to: recipient }) > 21_000n, true);
assert.equal((await rpc('eth_call', [{ to: `0x${'55'.repeat(20)}` }, 'latest'])).error.code, 3);
assert.equal((await rpc('eth_getBalance', [sender, '0x999'])).error.code, -32001);
assert.equal((await rpc('eth_getBalance', ['bad-address', 'latest'])).error.code, -32602);
assert.equal((await rpc('eth_getLogs', [{ topics: ['bad-topic'] }])).error.code, -32602);
assert.equal((await rpc('eth_getLogs', [{ fromBlock: '0x0', toBlock: '0x1000' }])).error.code, -32005);
assert.equal((await rpc('eth_noSuchMethod')).error.code, -32601);
const malformed = await fetch('http://127.0.0.1:18545/', { method: 'POST', body: '{' });
assert.equal((await malformed.json()).error.code, -32700);
const oversized = await fetch('http://127.0.0.1:18545/', { method: 'POST', body: 'x'.repeat(1_048_577) });
assert.equal(oversized.status, 413);
const batch = await fetch('http://127.0.0.1:18545/', { method: 'POST', body: JSON.stringify(Array.from({ length: 21 }, (_, id) => ({ jsonrpc: '2.0', id, method: 'eth_chainId' }))) });
assert.equal((await batch.json()).error.code, -32600);

const raw = await wallet.signTransaction({ type: 2, chainId: 1, nonce: 1, gasLimit: 21_000, maxPriorityFeePerGas: 1, maxFeePerGas: 2, to: recipient, value: 0 });
assert.equal((await provider.send('eth_sendRawTransaction', [raw])).length, 66);
console.log('ethers 6.15.0 execution RPC compatibility passed');
