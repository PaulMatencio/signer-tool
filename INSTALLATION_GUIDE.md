# Signer Tool — Installation Guide

This guide covers all supported ways to install and run **Signer Tool** (both the **CLI** and the **Desktop GUI**), including air-gapped / offline setups.

---

## Option 1: Offline CLI in Docker (Recommended for Offline Signing)

Running the CLI in Docker provides a reproducible, cross-platform (Linux, macOS, Windows) environment that can be locked down with `--network none`.

### Prerequisites
- Docker (Docker Engine on Linux, or Docker Desktop on macOS / Windows)
- Compiled `managed/signer-tools/` artifacts in the repository. If `managed/signer-tools/` is not already present, generate it once on a machine with the Compact CLI installed:
  ```bash
  npm run compile:tools
  ```

### 1. Build the Docker Image
From the repository root:
```bash
docker build -t signer-tool-cli .
```

The `.dockerignore` file uses a strict whitelist (`package.json`, `package-lock.json`, `tsconfig.json`, `src/`, `managed/`), so local keyfiles, requests, and approvals are never copied into the image.

### 2. Verify the Installation
Run the built-in cryptographic self-test with networking disabled:
```bash
docker run --rm --network none signer-tool-cli selftest
```
Expected output:
```text
Self-test passed.
```

### 3. Transfer to an Air-Gapped Machine (Optional)
To move the image to an offline signing machine without internet access:

```bash
# On the build machine:
docker save -o signer-tool-cli.tar signer-tool-cli
sha256sum signer-tool-cli.tar

# Copy signer-tool-cli.tar to the offline machine via USB, verify the SHA-256 hash, then load:
docker load -i signer-tool-cli.tar
docker run --rm --network none signer-tool-cli selftest
```

### 4. Running Commands (Volume Mount & Interactive TTY)
Mount a host directory to `/data` to store keyfiles, requests, and approvals. Always pass `--network none` and `-it` (interactive TTY is required for hidden passphrase prompts and `SIGN` confirmation).

**Linux / macOS:**
```bash
mkdir -p signer-data

# Generate an encrypted keyfile (mode 0600)
docker run --rm -it --network none \
  -u "$(id -u):$(id -g)" \
  -v "$(pwd)/signer-data:/data" \
  signer-tool-cli keygen --out /data/alice.key.json

# Print public key & compute signer commitment
docker run --rm --network none \
  -u "$(id -u):$(id -g)" \
  -v "$(pwd)/signer-data:/data" \
  signer-tool-cli pubkey --key /data/alice.key.json --salt <64-hex-contract-salt>

# Sign a request
docker run --rm -it --network none \
  -u "$(id -u):$(id -g)" \
  -v "$(pwd)/signer-data:/data" \
  signer-tool-cli sign \
    --key /data/alice.key.json \
    --request /data/req.json \
    --out /data/alice.approval.json

# Sign a Proof-of-Possession (incoming signer during rotateSigner only)
docker run --rm -it --network none \
  -u "$(id -u):$(id -g)" \
  -v "$(pwd)/signer-data:/data" \
  signer-tool-cli sign \
    --key /data/new.key.json \
    --request /data/rotate.json \
    --out /data/new.pop.json \
    --pop
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force -Path .\signer-data | Out-Null

# Generate an encrypted keyfile
docker run --rm -it --network none `
  -v "${PWD}\signer-data:/data" `
  signer-tool-cli keygen --out /data/alice.key.json

# Sign a request
docker run --rm -it --network none `
  -v "${PWD}\signer-data:/data" `
  signer-tool-cli sign `
    --key /data/alice.key.json `
    --request /data/req.json `
    --out /data/alice.approval.json
```

---

## Option 2: Desktop Application (GUI)

### Linux AppImage (Pre-built)
If a pre-built AppImage is available under `desktop/release/`:
```bash
chmod +x "desktop/release/Signer Tool-0.1.0.AppImage"
./desktop/release/"Signer Tool-0.1.0.AppImage"
```

### Build & Run Desktop App from Source
Requires **Node.js 22+**. From the repository root:
```bash
npm install
npm run compile:tools   # only needed if managed/signer-tools is missing or contract changed
npm run build
npm --prefix desktop install
npm --prefix desktop start
```

### Package Native Installers
From the repository root (after building the root library):
```bash
npm --prefix desktop run pack:linux   # AppImage (run on Linux)
npm --prefix desktop run pack:mac     # .dmg / .zip (run on macOS)
npm --prefix desktop run pack:win     # NSIS installer + portable .exe (run on Windows)
```
Packaged artifacts are written to `desktop/release/`.

---

## Option 3: Local CLI from Source (Without Docker)

Requires **Node.js 22+**. From the repository root:
```bash
npm install
npm run compile:tools   # only needed if managed/signer-tools is missing or contract changed
npm run build
node dist/cli.js selftest
```

To prepare an offline directory without Docker, copy `dist/`, `managed/signer-tools/`, `package.json`, and `node_modules/` to the offline machine and run `node dist/cli.js ...`.

---

## Next Steps
- For Desktop GUI workflows (Key Management, Request Builder, Signing, and Approval Verification), see [desktop/USER_GUIDE.md](desktop/USER_GUIDE.md).
- For CLI request JSON schemas and SDK integration examples, see [README.md](README.md).

