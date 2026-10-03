#!/usr/bin/env node
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import {
  commitmentFor,
  computeDigest,
  decryptKey,
  describeRequest,
  encryptKey,
  pointFromJson,
  pointToJson,
  popDigestFor,
  randomScalar,
  bytesToHex,
  selfTest,
  signDigest,
  type KeyFile,
  type SigningRequest
} from './lib.js';
import { pureCircuits as T } from './tools-module.js';

const USAGE = `signer-tool -- offline Schnorr approvals for FungibleToken multisig

  selftest
  keygen  --out <keyfile>
  pubkey  --key <keyfile> [--salt <64-hex contract salt>]
  sign    --key <keyfile> --request <request.json> --out <approval.json> [--pop]

--pop signs the proof-of-possession digest of a rotateSigner request; only the
INCOMING signer uses it. Never put secrets in a request or approval file.`;

function args(argv: string[]): Record<string, string | true> {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) throw new Error(`Unexpected argument: ${argv[i]}`);
    const k = argv[i].slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out[k] = true;
    else {
      out[k] = next;
      i++;
    }
  }
  return out;
}

const need = (a: Record<string, string | true>, k: string): string => {
  const v = a[k];
  if (typeof v !== 'string') throw new Error(`Missing --${k}\n\n${USAGE}`);
  return v;
};

function promptHidden(q: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) return reject(new Error('An interactive terminal is required for passphrase entry.'));
    process.stdout.write(q);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const done = (fn: () => void) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      process.stdout.write('\n');
      fn();
    };
    const onData = (chunk: string) => {
      for (const c of chunk) {
        if (c === '\r' || c === '\n' || c === '\u0004') return done(() => resolve(buf));
        if (c === '\u0003') return done(() => reject(new Error('Cancelled.')));
        if (c === '\u007f' || c === '\b') buf = buf.slice(0, -1);
        else buf += c;
      }
    };
    stdin.on('data', onData);
  });
}

function promptLine(q: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(q, (a) => (rl.close(), resolve(a))));
}

function writeSecure(path: string, data: unknown, overwrite = false): void {
  if (!overwrite && existsSync(path)) throw new Error(`${path} already exists; refusing to overwrite.`);
  writeFileSync(path, JSON.stringify(data, null, 2), { mode: 0o600 });
  chmodSync(path, 0o600);
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === '--help' || cmd === 'help') return console.log(USAGE);
  const a = args(rest);

  selfTest(); // abort if any runtime assumption is wrong, before touching keys

  if (cmd === 'selftest') return console.log('Self-test passed.');

  if (cmd === 'keygen') {
    const out = need(a, 'out');
    const p1 = await promptHidden('New passphrase (12+ chars): ');
    const p2 = await promptHidden('Repeat passphrase: ');
    if (p1 !== p2) throw new Error('Passphrases do not match.');
    const sk = randomScalar();
    const pk = T.derivePublicKey(sk);
    writeSecure(out, encryptKey(sk, pk, p1));
    console.log(`Wrote encrypted key to ${out} (mode 600).`);
    console.log('Public key (share this; it is not secret):');
    console.log(JSON.stringify(pointToJson(pk)));
    console.log('BACK UP the key file and passphrase separately, offline. Losing enough signer keys bricks governance.');
    return;
  }

  if (cmd === 'pubkey') {
    const f = JSON.parse(readFileSync(need(a, 'key'), 'utf8')) as KeyFile;
    console.log('Public key:', JSON.stringify(f.publicKey));
    if (typeof a.salt === 'string') {
      console.log('Signer commitment:', commitmentFor(pointFromJson(f.publicKey), a.salt));
    }
    return;
  }

  if (cmd === 'sign') {
    const req = JSON.parse(readFileSync(need(a, 'request'), 'utf8')) as SigningRequest;
    const keyFile = JSON.parse(readFileSync(need(a, 'key'), 'utf8')) as KeyFile;
    const out = need(a, 'out');
    const pop = a.pop === true;

    const digest = computeDigest(req);
    console.log('\n=== REVIEW BEFORE SIGNING ===');
    for (const l of describeRequest(req, digest)) console.log(l);

    let toSign = digest;
    if (pop) {
      if (req.op.type !== 'rotateSigner') throw new Error('--pop only applies to rotateSigner requests.');
      const mine = keyFile.publicKey;
      const theirs = req.op.newSignerPubkey;
      if (mine.x !== theirs.x || mine.y !== theirs.y) {
        throw new Error('This key is not the newSignerPubkey in the request; refusing to sign proof-of-possession.');
      }
      toSign = popDigestFor(digest);
      console.log(`PoP digest: ${bytesToHex(toSign)}`);
    }

    console.log(
      '\nNot checkable offline -- confirm yourself against the chain: the contract address, and that the' +
        '\nnonce equals the current _multisigNonce. Compare the digest with the other signers.'
    );
    if ((await promptLine('Type SIGN to approve, anything else to abort: ')) !== 'SIGN') {
      throw new Error('Aborted; nothing signed.');
    }

    const { sk, pk } = decryptKey(keyFile, await promptHidden('Passphrase: '));
    const sig = signDigest(sk, pk, toSign);
    writeSecure(out, {
      version: 1,
      kind: pop ? 'pop' : 'approval',
      operation: req.op.type,
      contractAddress: req.contractAddress,
      nonce: req.nonce,
      digest: bytesToHex(toSign),
      publicKey: pointToJson(pk),
      signature: { announcement: pointToJson(sig.announcement), response: sig.response.toString() }
    });
    console.log(`\nWrote ${out}. It contains no secrets and can be sent to the coordinator.`);
    return;
  }

  throw new Error(`Unknown command: ${cmd}\n\n${USAGE}`);
}

main().catch((e: Error) => {
  console.error(`Error: ${e.message}`);
  process.exit(1);
});
