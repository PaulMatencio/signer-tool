# signer-tool

Offline Schnorr approvals for the FungibleToken v2.6 multisig. Each signer runs
this on their own machine, reviews a human-readable request, and returns a
`SchnorrSignature` file that contains no secrets.

## Why it is built this way

- **No hand-written hashing.** `compact/SignerTools.compact` copies each digest
  and the Schnorr challenge from the contract as exported pure circuits. The
  CLI calls the compiled bindings, so it uses the same standard-library code as
  the chain. This file is **never deployed**.
- **Signers never sign an opaque hash.** A request describes the operation
  (who, how much, which nonce). The tool recomputes the digest itself, shows you
  the fields, and only then asks you to type `SIGN`.
- **Self-checking.** Before any key is created or used, the tool checks that
  `JubjubPoint` is `{x, y}`, that `r*G` is the identity (validating the
  subgroup-order constant), and that a throwaway signature verifies. Every real
  signature is verified again before it is written. If a check fails, it aborts.
- **Keys at rest:** scrypt (N=2^17) + AES-256-GCM, public key bound as AAD, file
  mode 600, passphrase entered without echo, never accepted as a flag or env var.
- **Nonces are hedged** (hash of secret + digest + fresh randomness), so a weak
  RNG alone cannot leak a key.

## Setup

```bash
npm install
npm run compile:tools     # compact compile --skip-zk ... (pure circuits need no proving keys)
npm run build
```

`--skip-zk` is fine here: nothing in this file is ever proven or deployed.
Match `@midnight-ntwrk/compact-runtime` to the version your compiler targets.
For an offline signer machine, copy `dist/`, `managed/signer-tools/`, and
`node_modules/`, then run with no network.

## Usage

```bash
node dist/cli.js selftest
node dist/cli.js keygen --out alice.key.json          # prints the PUBLIC key
node dist/cli.js pubkey --key alice.key.json --salt <64-hex contractSalt>   # also prints commitment

node dist/cli.js sign --key alice.key.json --request req.json --out alice.approval.json
node dist/cli.js sign --key new.key.json   --request rotate.json --out new.pop.json --pop
```

Commitments for the constructor's `initialSigners` come from the `pubkey`
command with `--salt` set to the salt you deploy with.

## Request format

```json
{
  "version": 1,
  "network": "preprod",
  "contractAddress": "<64 hex: contract address bytes>",
  "contractSalt": "<64 hex, required for rotateSigner>",
  "nonce": "12",
  "op": { "type": "mint", "to": "<64 hex>", "value": "500" }
}
```

Operations: `mint {to, value}`, `burn {account, value}` (v2.6) or `burn {value}` (v3 native token: contract-held
tokens only), `contractWithdraw {to, value}` (v3 native token),
`setEmergencyPauser {newPauser}`, `setThreshold {threshold}` (v3), `adminReallocate {trappedAccount,
targetSpendableAccount, amount}`, `rotateSigner {oldSignerCommitment,
newSignerPubkey:{x,y}}`. Amounts are decimal integers in base units.

For `rotateSigner`, `threshold` current signers use plain `sign`, and the
**incoming** signer additionally uses `sign --pop` (the tool refuses unless the
key matches `newSignerPubkey`).

## What the tool cannot check for you

1. **Contract address and nonce.** Confirm the address is the real contract and
   that `nonce` equals the current `_multisigNonce` (`client.getLedgerState`).
   A stale nonce produces a signature that fails on-chain; a wrong address is a
   request you should not sign.
2. **That the recipient/amount is what you intend.** Read the review screen.
3. **Digest agreement.** Have signers compare the printed digest.

## Feeding approvals to the SDK

```ts
import { readFileSync } from 'node:fs';
const pt = (j: any) => ({ x: BigInt(j.x), y: BigInt(j.y) });
const load = (f: string) => {
  const j = JSON.parse(readFileSync(f, 'utf8'));
  return { pubkey: pt(j.publicKey),
           signature: { announcement: pt(j.signature.announcement), response: BigInt(j.signature.response) } };
};
const approvals = [load('alice.approval.json'), load('bob.approval.json'), EMPTY_SLOT]; // 3 slots
await client.mint(to, 500n, approvals);
```

## Limits

- JavaScript cannot reliably wipe secrets from memory; use a dedicated machine.
- Back up each key file and its passphrase separately, offline. Rotation needs
  `threshold` valid signatures, so do not lose enough keys to fall below it.
- Tested here only against a stub with real Jubjub arithmetic and placeholder
  hashes. It has not been run against your compiled module or a live network.
