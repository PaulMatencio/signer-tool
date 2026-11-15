import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync
} from 'node:crypto';
import { pureCircuits as T } from './tools-module.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Order of the prime-order subgroup of Jubjub (scalar field modulus for signing). */
export const JUBJUB_SCALAR_ORDER =
  6554484396890773809930967563523245729705921265872317281365359162392183254199n;
const TWO_248 = 1n << 248n;
const TWO_64 = 1n << 64n;
const TWO_128 = 1n << 128n;

export type Point = ReturnType<typeof T.derivePublicKey>;
export interface PointJson {
  x: string;
  y: string;
}

/** Identity point (0, 1) on Jubjub, used for unused multisig approval slots. */
export const EMPTY_PUBKEY: Point = { x: 0n, y: 1n } as unknown as Point;
export const EMPTY_SIGNATURE = {
  announcement: EMPTY_PUBKEY,
  response: 0n
};

// ---------------------------------------------------------------------------
// Byte / point helpers. The ONLY place that assumes a JubjubPoint is {x, y}.
// selfTest() verifies that assumption before any key is created or used.
// ---------------------------------------------------------------------------

export function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

export function bigIntToBytes32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error('value does not fit in 32 bytes');
  return out;
}

export function hexToBytes32(hex: string, name: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(h)) throw new Error(`${name}: expected 64 hex chars (32 bytes)`);
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

export const bytesToHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

export function pointToJson(p: Point): PointJson {
  const q = p as unknown as { x: bigint; y: bigint };
  return { x: q.x.toString(), y: q.y.toString() };
}

export function pointFromJson(j: PointJson): Point {
  return { x: BigInt(j.x), y: BigInt(j.y) } as unknown as Point;
}

function parseUint(s: string, bits: bigint, name: string): bigint {
  if (!/^\d+$/.test(s)) throw new Error(`${name}: must be a non-negative decimal integer`);
  const v = BigInt(s);
  if (v >= bits) throw new Error(`${name}: out of range`);
  return v;
}

// ---------------------------------------------------------------------------
// Keys and signing
// ---------------------------------------------------------------------------

/** Uniform scalar in [1, r-1] (512 random bits reduced: bias is negligible). */
export function randomScalar(): bigint {
  return (bytesToBigInt(randomBytes(64)) % (JUBJUB_SCALAR_ORDER - 1n)) + 1n;
}

/** Hedged nonce: hash(secret || digest || fresh randomness). Safe even if the RNG is weak. */
function hedgedNonce(sk: bigint, digest: Uint8Array): bigint {
  const h = createHash('sha512')
    .update(bigIntToBytes32(sk))
    .update(digest)
    .update(randomBytes(32))
    .digest();
  return (bytesToBigInt(h) % (JUBJUB_SCALAR_ORDER - 1n)) + 1n;
}

export interface SchnorrSig {
  announcement: Point;
  response: bigint;
}

/** Signs a 32-byte digest and self-verifies before returning. */
export function signDigest(sk: bigint, pk: Point, digest: Uint8Array): SchnorrSig {
  if (digest.length !== 32) throw new Error('digest must be 32 bytes');
  const k = hedgedNonce(sk, digest);
  const announcement = T.derivePublicKey(k);
  const cFull = T.schnorrChallenge(announcement, pk, digest);
  const c = cFull % TWO_248; // contract verifies with the low 248 bits
  const response = (k + sk * c) % JUBJUB_SCALAR_ORDER;
  if (!T.schnorrEquationHolds(announcement, response, pk, c)) {
    throw new Error('Self-verification failed; refusing to release this signature.');
  }
  return { announcement, response };
}

/** Refuses to run if any assumption this tool makes about the runtime is false. */
export function selfTest(): void {
  const g = T.derivePublicKey(1n) as unknown as { x: unknown; y: unknown };
  if (typeof g.x !== 'bigint' || typeof g.y !== 'bigint') {
    throw new Error(
      'SELFTEST: JubjubPoint is not {x: bigint, y: bigint} in your runtime version. ' +
        'Adjust pointToJson/pointFromJson in lib.ts before using this tool.'
    );
  }
  const id = T.derivePublicKey(0n) as unknown as { x: bigint; y: bigint };
  const orderHolds = T.schnorrEquationHolds(
    T.derivePublicKey(JUBJUB_SCALAR_ORDER - 1n),
    0n,
    T.derivePublicKey(1n),
    1n
  );
  if (!(id.x === 0n && id.y === 1n && orderHolds)) {
    throw new Error(
      'SELFTEST: (r-1)*G + G is not the identity (0,1). Either the subgroup-order constant or the ' +
        'point representation differs from what this tool assumes. Do NOT sign.'
    );
  }
  const sk = randomScalar();
  const pk = T.derivePublicKey(sk);
  signDigest(sk, pk, randomBytes(32)); // includes equation self-check
}

// ---------------------------------------------------------------------------
// Encrypted keystore: scrypt -> AES-256-GCM, public key bound as AAD.
// ---------------------------------------------------------------------------

export interface KeyFile {
  version: 1;
  kdf: { name: 'scrypt'; salt: string; N: number; r: number; p: number };
  cipher: { name: 'aes-256-gcm'; iv: string; tag: string };
  ciphertext: string;
  publicKey: PointJson;
}

const SCRYPT = { N: 1 << 17, r: 8, p: 1 };

function deriveKey(passphrase: string, salt: Buffer, N: number, r: number, p: number): Buffer {
  return scryptSync(passphrase.normalize('NFKC'), salt, 32, {
    N,
    r,
    p,
    maxmem: 256 * 1024 * 1024
  });
}

export function encryptKey(sk: bigint, pk: Point, passphrase: string): KeyFile {
  if (passphrase.length < 12) throw new Error('Passphrase must be at least 12 characters.');
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt, SCRYPT.N, SCRYPT.r, SCRYPT.p);
  const publicKey = pointToJson(pk);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify(publicKey)));
  const ct = Buffer.concat([cipher.update(bigIntToBytes32(sk)), cipher.final()]);
  return {
    version: 1,
    kdf: { name: 'scrypt', salt: salt.toString('hex'), ...SCRYPT },
    cipher: { name: 'aes-256-gcm', iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex') },
    ciphertext: ct.toString('hex'),
    publicKey
  };
}

/** Decrypts and confirms the secret actually corresponds to the stored public key. */
export function decryptKey(f: KeyFile, passphrase: string): { sk: bigint; pk: Point } {
  if (f.version !== 1) throw new Error('Unsupported key file version');
  const key = deriveKey(passphrase, Buffer.from(f.kdf.salt, 'hex'), f.kdf.N, f.kdf.r, f.kdf.p);
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(f.cipher.iv, 'hex'));
  d.setAAD(Buffer.from(JSON.stringify(f.publicKey)));
  d.setAuthTag(Buffer.from(f.cipher.tag, 'hex'));
  let pt: Buffer;
  try {
    pt = Buffer.concat([d.update(Buffer.from(f.ciphertext, 'hex')), d.final()]);
  } catch {
    throw new Error('Wrong passphrase or corrupted key file.');
  }
  const sk = bytesToBigInt(pt);
  const pk = T.derivePublicKey(sk);
  const stored = f.publicKey;
  const derived = pointToJson(pk);
  if (derived.x !== stored.x || derived.y !== stored.y) {
    throw new Error('Decrypted key does not match the stored public key.');
  }
  return { sk, pk };
}

// ---------------------------------------------------------------------------
// Signing requests: the signer's tool recomputes the digest from the
// human-readable operation, so a signer never signs an opaque hash.
// ---------------------------------------------------------------------------

export type Op =
  | { type: 'mint'; to: string; value: string }
  // v2.6: burn {account, value}; v3 (native token): burn {value} — contract-held tokens only, no account.
  | { type: 'burn'; account?: string; value: string }
  // v3 (native token): pay contract-held tokens to a wallet (UserAddress bytes).
  | { type: 'contractWithdraw'; to: string; value: string }
  | { type: 'setEmergencyPauser'; newPauser: string }
  // v3: change the approval threshold (1..3).
  | { type: 'setThreshold'; threshold: string }
  | { type: 'adminReallocate'; trappedAccount: string; targetSpendableAccount: string; amount: string }
  | { type: 'rotateSigner'; oldSignerCommitment: string; newSignerPubkey: PointJson };

export interface SigningRequest {
  version: 1;
  network?: string;
  contractAddress: string; // 32 bytes hex (kernel.self().bytes)
  contractSalt?: string; // 32 bytes hex; required for rotateSigner
  nonce: string; // _multisigNonce at the time of the call
  op: Op;
}

export function computeDigest(req: SigningRequest): Uint8Array {
  if (req.version !== 1) throw new Error('Unsupported request version');
  const addr = hexToBytes32(req.contractAddress, 'contractAddress');
  const nonce = parseUint(req.nonce, TWO_64, 'nonce');
  const op = req.op;
  switch (op.type) {
    case 'mint':
      return T.mintDigest(addr, nonce, hexToBytes32(op.to, 'to'), parseUint(op.value, TWO_128, 'value'));
    case 'burn':
      return op.account === undefined
        ? T.burnDigestV3(addr, nonce, parseUint(op.value, TWO_128, 'value'))
        : T.burnDigest(addr, nonce, hexToBytes32(op.account, 'account'), parseUint(op.value, TWO_128, 'value'));
    case 'contractWithdraw':
      return T.withdrawDigest(addr, nonce, hexToBytes32(op.to, 'to'), parseUint(op.value, TWO_128, 'value'));
    case 'setEmergencyPauser':
      return T.setEmergencyPauserDigest(addr, nonce, hexToBytes32(op.newPauser, 'newPauser'));
    case 'setThreshold':
      return T.setThresholdDigest(addr, nonce, parseUint(op.threshold, 4n, 'threshold'));
    case 'adminReallocate':
      return T.adminReallocateDigest(
        addr,
        nonce,
        hexToBytes32(op.trappedAccount, 'trappedAccount'),
        hexToBytes32(op.targetSpendableAccount, 'targetSpendableAccount'),
        parseUint(op.amount, TWO_128, 'amount')
      );
    case 'rotateSigner': {
      if (!req.contractSalt) throw new Error('rotateSigner requests need contractSalt');
      return T.rotateSignerDigest(
        addr,
        nonce,
        hexToBytes32(op.oldSignerCommitment, 'oldSignerCommitment'),
        pointFromJson(op.newSignerPubkey),
        hexToBytes32(req.contractSalt, 'contractSalt')
      );
    }
    default:
      throw new Error(`Unknown operation: ${(op as { type: string }).type}`);
  }
}

export function describeRequest(req: SigningRequest, digest: Uint8Array): string[] {
  const o = req.op;
  const lines = [
    `Operation : ${o.type}`,
    `Network   : ${req.network ?? '(not specified)'}`,
    `Contract  : ${req.contractAddress}`,
    `Nonce     : ${req.nonce}`
  ];
  switch (o.type) {
    case 'mint':
      lines.push(`Mint to   : ${o.to}`, `Amount    : ${o.value} (base units)`);
      break;
    case 'burn':
      lines.push(o.account === undefined ? `Burn      : tokens HELD BY THE CONTRACT (v3)` : `Burn from : ${o.account}`, `Amount    : ${o.value} (base units)`);
      break;
    case 'contractWithdraw':
      lines.push(`Pay to    : ${o.to} (wallet address bytes)`, `Amount    : ${o.value} (base units, from the contract-held balance)`);
      break;
    case 'setEmergencyPauser':
      lines.push(`New pauser: ${o.newPauser}`);
      break;
    case 'setThreshold':
      lines.push(`New threshold: ${o.threshold} of 3 signers`);
      break;
    case 'adminReallocate':
      lines.push(
        `Move from : ${o.trappedAccount}`,
        `Move to   : ${o.targetSpendableAccount}`,
        `Amount    : ${o.amount} (base units)`
      );
      break;
    case 'rotateSigner':
      lines.push(
        `Remove    : ${o.oldSignerCommitment} (commitment)`,
        `Add pubkey: x=${o.newSignerPubkey.x}`,
        `            y=${o.newSignerPubkey.y}`
      );
      break;
  }
  lines.push(`Digest    : ${bytesToHex(digest)}`);
  return lines;
}

export function popDigestFor(rotateDigest: Uint8Array): Uint8Array {
  return T.rotatePopDigest(rotateDigest);
}

export function commitmentFor(pk: Point, saltHex: string): string {
  return bytesToHex(T.calculateSignerCommitment(pk, hexToBytes32(saltHex, 'salt')));
}

// ---------------------------------------------------------------------------
// Validation & Approval Verification
// ---------------------------------------------------------------------------

export interface ApprovalFile {
  version: 1;
  kind: 'approval' | 'pop';
  operation: Op['type'];
  contractAddress: string;
  nonce: string;
  digest: string;
  publicKey: PointJson;
  signature: {
    announcement: PointJson;
    response: string;
  };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function assertString(v: unknown, name: string): string {
  if (typeof v !== 'string') throw new Error(`${name}: expected string`);
  return v;
}

export function parsePointJson(v: unknown, name: string): PointJson {
  if (!isRecord(v)) throw new Error(`${name}: expected { x, y } object`);
  const x = assertString(v.x, `${name}.x`);
  const y = assertString(v.y, `${name}.y`);
  if (!/^\d+$/.test(x) || !/^\d+$/.test(y)) {
    throw new Error(`${name}: x and y must be non-negative decimal integers`);
  }
  return { x, y };
}

export function parseKeyFile(raw: unknown): KeyFile {
  if (!isRecord(raw)) throw new Error('Key file must be a JSON object.');
  if (raw.version !== 1) throw new Error('Unsupported key file version.');
  if (!isRecord(raw.kdf) || raw.kdf.name !== 'scrypt') throw new Error('Invalid key file KDF.');
  if (!isRecord(raw.cipher) || raw.cipher.name !== 'aes-256-gcm') throw new Error('Invalid key file cipher.');
  assertString(raw.ciphertext, 'ciphertext');
  const publicKey = parsePointJson(raw.publicKey, 'publicKey');
  return {
    version: 1,
    kdf: {
      name: 'scrypt',
      salt: assertString(raw.kdf.salt, 'kdf.salt'),
      N: Number(raw.kdf.N),
      r: Number(raw.kdf.r),
      p: Number(raw.kdf.p)
    },
    cipher: {
      name: 'aes-256-gcm',
      iv: assertString(raw.cipher.iv, 'cipher.iv'),
      tag: assertString(raw.cipher.tag, 'cipher.tag')
    },
    ciphertext: raw.ciphertext as string,
    publicKey
  };
}

export function parseSigningRequest(raw: unknown): SigningRequest {
  if (!isRecord(raw)) throw new Error('Signing request must be a JSON object.');
  if (raw.version !== 1) throw new Error('Unsupported signing request version.');
  const contractAddress = assertString(raw.contractAddress, 'contractAddress');
  const nonce = assertString(raw.nonce, 'nonce');
  const network = raw.network !== undefined ? assertString(raw.network, 'network') : undefined;
  const contractSalt = raw.contractSalt !== undefined ? assertString(raw.contractSalt, 'contractSalt') : undefined;
  if (!isRecord(raw.op)) throw new Error('op: expected object');
  const type = assertString(raw.op.type, 'op.type');

  let op: Op;
  switch (type) {
    case 'mint':
      op = { type: 'mint', to: assertString(raw.op.to, 'op.to'), value: assertString(raw.op.value, 'op.value') };
      break;
    case 'burn':
      op = {
        type: 'burn',
        ...(raw.op.account !== undefined ? { account: assertString(raw.op.account, 'op.account') } : {}),
        value: assertString(raw.op.value, 'op.value')
      };
      break;
    case 'contractWithdraw':
      op = {
        type: 'contractWithdraw',
        to: assertString(raw.op.to, 'op.to'),
        value: assertString(raw.op.value, 'op.value')
      };
      break;
    case 'setEmergencyPauser':
      op = { type: 'setEmergencyPauser', newPauser: assertString(raw.op.newPauser, 'op.newPauser') };
      break;
    case 'setThreshold':
      op = { type: 'setThreshold', threshold: assertString(raw.op.threshold, 'op.threshold') };
      break;
    case 'adminReallocate':
      op = {
        type: 'adminReallocate',
        trappedAccount: assertString(raw.op.trappedAccount, 'op.trappedAccount'),
        targetSpendableAccount: assertString(raw.op.targetSpendableAccount, 'op.targetSpendableAccount'),
        amount: assertString(raw.op.amount, 'op.amount')
      };
      break;
    case 'rotateSigner':
      op = {
        type: 'rotateSigner',
        oldSignerCommitment: assertString(raw.op.oldSignerCommitment, 'op.oldSignerCommitment'),
        newSignerPubkey: parsePointJson(raw.op.newSignerPubkey, 'op.newSignerPubkey')
      };
      break;
    default:
      throw new Error(`Unknown operation: ${type}`);
  }

  const req: SigningRequest = {
    version: 1,
    ...(network !== undefined ? { network } : {}),
    contractAddress,
    ...(contractSalt !== undefined ? { contractSalt } : {}),
    nonce,
    op
  };
  // Validate all hex/uint constraints by computing digest
  computeDigest(req);
  return req;
}

export function parseApprovalFile(raw: unknown): ApprovalFile {
  if (!isRecord(raw)) throw new Error('Approval file must be a JSON object.');
  if (raw.version !== 1) throw new Error('Unsupported approval file version.');
  const kind = assertString(raw.kind, 'kind');
  if (kind !== 'approval' && kind !== 'pop') throw new Error('kind must be "approval" or "pop".');
  const operation = assertString(raw.operation, 'operation') as Op['type'];
  const contractAddress = assertString(raw.contractAddress, 'contractAddress');
  hexToBytes32(contractAddress, 'contractAddress');
  const nonce = assertString(raw.nonce, 'nonce');
  parseUint(nonce, TWO_64, 'nonce');
  const digest = assertString(raw.digest, 'digest');
  hexToBytes32(digest, 'digest');
  const publicKey = parsePointJson(raw.publicKey, 'publicKey');
  if (!isRecord(raw.signature)) throw new Error('signature: expected object');
  const announcement = parsePointJson(raw.signature.announcement, 'signature.announcement');
  const response = assertString(raw.signature.response, 'signature.response');
  if (!/^\d+$/.test(response)) throw new Error('signature.response: expected non-negative decimal integer');

  return {
    version: 1,
    kind,
    operation,
    contractAddress,
    nonce,
    digest,
    publicKey,
    signature: { announcement, response }
  };
}

export interface ApprovalVerificationResult {
  valid: boolean;
  reason?: string;
  signerKey: string;
  kind: 'approval' | 'pop';
  digestHex: string;
}

export function verifyApproval(approval: ApprovalFile, req?: SigningRequest): ApprovalVerificationResult {
  const signerKey = `${approval.publicKey.x}:${approval.publicKey.y}`;
  try {
    const digestBytes = hexToBytes32(approval.digest, 'digest');

    if (req) {
      if (approval.contractAddress.toLowerCase() !== req.contractAddress.toLowerCase()) {
        return { valid: false, reason: 'Contract address mismatch.', signerKey, kind: approval.kind, digestHex: approval.digest };
      }
      if (approval.nonce !== req.nonce) {
        return { valid: false, reason: 'Nonce mismatch.', signerKey, kind: approval.kind, digestHex: approval.digest };
      }
      if (approval.operation !== req.op.type) {
        return { valid: false, reason: 'Operation type mismatch.', signerKey, kind: approval.kind, digestHex: approval.digest };
      }
      const baseDigest = computeDigest(req);
      const expectedDigest = approval.kind === 'pop' ? popDigestFor(baseDigest) : baseDigest;
      const expectedHex = bytesToHex(expectedDigest);
      if (approval.digest.toLowerCase() !== expectedHex.toLowerCase()) {
        return {
          valid: false,
          reason: `Digest mismatch (expected ${expectedHex}).`,
          signerKey,
          kind: approval.kind,
          digestHex: approval.digest
        };
      }
      if (approval.kind === 'pop' && req.op.type === 'rotateSigner') {
        if (
          approval.publicKey.x !== req.op.newSignerPubkey.x ||
          approval.publicKey.y !== req.op.newSignerPubkey.y
        ) {
          return {
            valid: false,
            reason: 'PoP signer public key does not match newSignerPubkey.',
            signerKey,
            kind: approval.kind,
            digestHex: approval.digest
          };
        }
      }
    }

    const pk = pointFromJson(approval.publicKey);
    const announcement = pointFromJson(approval.signature.announcement);
    const response = BigInt(approval.signature.response);
    const c = T.schnorrChallenge(announcement, pk, digestBytes) % TWO_248;
    const ok = T.schnorrEquationHolds(announcement, response, pk, c);
    if (!ok) {
      return { valid: false, reason: 'Schnorr verification equation failed.', signerKey, kind: approval.kind, digestHex: approval.digest };
    }
    return { valid: true, signerKey, kind: approval.kind, digestHex: approval.digest };
  } catch (err) {
    return {
      valid: false,
      reason: err instanceof Error ? err.message : String(err),
      signerKey,
      kind: approval.kind,
      digestHex: approval.digest
    };
  }
}

export interface BundleSlotPreview {
  pubkey: PointJson;
  signature: { announcement: PointJson; response: string };
}

export interface BundleVerificationResult {
  allValid: boolean;
  validApprovalCount: number;
  hasPop: boolean;
  duplicateSigners: boolean;
  items: Array<ApprovalVerificationResult & { duplicate: boolean }>;
  sdkSlots: BundleSlotPreview[];
}

export function verifyApprovalBundle(req: SigningRequest, approvals: ApprovalFile[]): BundleVerificationResult {
  const seenApprovals = new Set<string>();
  let duplicateSigners = false;
  let validApprovalCount = 0;
  let hasPop = false;
  let allValid = approvals.length > 0;

  const items = approvals.map((a) => {
    const res = verifyApproval(a, req);
    let duplicate = false;
    if (a.kind === 'approval') {
      if (seenApprovals.has(res.signerKey)) {
        duplicate = true;
        duplicateSigners = true;
      }
      seenApprovals.add(res.signerKey);
      if (res.valid && !duplicate) validApprovalCount++;
    } else if (res.valid) {
      hasPop = true;
    }
    if (!res.valid || duplicate) allValid = false;
    return { ...res, duplicate };
  });

  const approvalItems = approvals.filter((a) => a.kind === 'approval').slice(0, 3);
  const emptyPt = pointToJson(EMPTY_PUBKEY);
  const sdkSlots: BundleSlotPreview[] = [];
  for (let i = 0; i < 3; i++) {
    const a = approvalItems[i];
    if (a) {
      sdkSlots.push({ pubkey: a.publicKey, signature: a.signature });
    } else {
      sdkSlots.push({
        pubkey: emptyPt,
        signature: { announcement: emptyPt, response: '0' }
      });
    }
  }

  return { allValid, validApprovalCount, hasPop, duplicateSigners, items, sdkSlots };
}
