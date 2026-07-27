# neurai-sign-esp32

Create and sign Neurai (XNA) and asset transactions via ESP32 hardware wallet.

This library handles the full PSBT workflow against an ESP32 hardware wallet:
build an unsigned PSBT, send it over USB Serial for signing, receive
the signed PSBT back, finalize it, and extract the raw transaction hex
ready for broadcast.

Uses [bitcoinjs-lib](https://www.npmjs.com/package/bitcoinjs-lib) v7 for
PSBT construction and the Web Serial API for device communication.

It also supports **Post-Quantum (ML-DSA-44 / AuthScript) addresses**: sending to
PQ addresses (`nq1…`/`tnq1…`) and spending from them. The library auto-detects
the device mode from `info` and routes accordingly — see
[Post-Quantum support](#post-quantum-pq--ml-dsa-44-support).

##

EXPERIMENTAL.

This library supports:
- XNA transfers
- Asset transfers
- BIP32 account discovery via `get_bip32_pubkey`
- Message signing (prove address ownership)
- **Post-Quantum addresses (ML-DSA-44 / AuthScript)** — send to and spend from `nq1…`/`tnq1…`

Asset transfers use the same PSBT signing flow as XNA transfers. The transaction
outputs are still signed from the raw unsigned transaction, while optional
display metadata can be provided to the device so the firmware can show the
asset name, transferred amount, destination address, and fee more clearly.

## Install

```
npm i @neuraiproject/neurai-sign-esp32
```

For browser-specific consumption you can also import the explicit browser entry:

```javascript
import { NeuraiESP32 } from "@neuraiproject/neurai-sign-esp32/browser";
```

For classic HTML pages without ESM imports, load the global bundle:

```html
<script src="./dist/NeuraiSignESP32.global.js"></script>
<script>
  const device = new window.NeuraiSignESP32.NeuraiESP32();
</script>
```

## How to use

### Full transaction flow

```javascript
import { NeuraiESP32 } from "@neuraiproject/neurai-sign-esp32";

const device = new NeuraiESP32();

// Connect — opens the browser port selection dialog
await device.connect();

// Get device info (no physical confirmation needed)
const info = await device.getInfo();
console.log(info.network);           // "Neurai"
console.log(info.master_fingerprint); // "a1b2c3d4"

// Get address and public key (user must press Confirm on device)
const { address, pubkey, path } = await device.getAddress();
console.log(address); // "Nxxx..."

// Build, sign and finalize in one call
// Each UTXO must include rawTxHex (full previous tx hex from getrawtransaction)
const result = await device.signTransaction({
  utxos: [
    {
      txid: "abcd1234....",
      vout: 0,
      scriptPubKey: "76a914...88ac",
      satoshis: 500000000,
      rawTxHex: "0200000001...",
    },
  ],
  outputs: [
    { address: "Nxxx...", value: 100000000 },
  ],
  changeAddress: address,
});

console.log(result.txHex);       // raw tx hex, broadcast with sendrawtransaction
console.log(result.txId);        // transaction id
console.log(result.signedInputs); // number of inputs signed by the device

await device.disconnect();
```

### Step by step (manual PSBT)

If you want to build the PSBT yourself:

```javascript
import { NeuraiESP32, buildPSBT, finalizePSBT } from "@neuraiproject/neurai-sign-esp32";

const device = new NeuraiESP32();
await device.connect();

const info = await device.getInfo();
const { address, pubkey, path } = await device.getAddress();

// 1. Build unsigned PSBT
const psbtBase64 = buildPSBT({
  network: "xna",
  utxos: [
    {
      txid: "abcd1234....",
      vout: 0,
      scriptPubKey: "76a914...88ac",
      satoshis: 500000000,
      rawTxHex: "0200000001...",
    },
  ],
  outputs: [{ address: "Nxxx...", value: 100000000 }],
  changeAddress: address,
  pubkey: pubkey,
  masterFingerprint: info.master_fingerprint,
  derivationPath: path,
  feeRate: 1024,
});

// 2. Send to device for signing (user confirms with physical button)
const signed = await device.signPsbt(psbtBase64);

// 3. Finalize and extract raw transaction
const { txHex, txId } = finalizePSBT(signed.psbt, "xna");
console.log(txHex); // ready for sendrawtransaction

await device.disconnect();
```

### Asset transfer display metadata

When signing an asset transfer, you can attach optional display metadata to
the `sign_psbt` request. This does not affect the signature itself. It only
helps the ESP32 firmware render a better transaction review screen.

```javascript
import {
  NeuraiESP32,
  buildAssetTransferDisplayMetadata,
} from "@neuraiproject/neurai-sign-esp32";

const device = new NeuraiESP32();
await device.connect();

const display = buildAssetTransferDisplayMetadata({
  assetName: "MY_ASSET",
  assetAmount: 1,
  destinationAddress: "Nxxx...",
  destinationCount: 1,
  changeAddress: "Nchange...",
  changeCount: 1,
  inputAddresses: ["Ninput1...", "Ninput2..."],
  feeAmount: 0.01234567,
  baseCurrency: "XNA",
});

const signed = await device.signPsbt(psbtBase64, display);
```

This metadata is especially useful for asset transfers because a standard PSBT
does not expose high-level fields such as `assetName` or `assetAmount` in a
simple, display-ready form.

### Sign a message (prove address ownership)

```javascript
const device = new NeuraiESP32();
await device.connect();

// User must press Confirm on device
const result = await device.signMessage("Hello, I own this address");
console.log(result.signature); // base64-encoded recoverable signature
console.log(result.address);   // address that signed the message
console.log(result.message);   // the original message
```

The signature uses the standard Bitcoin message signing format with the
`"Neurai Signed Message:\n"` prefix. It is compatible with
`NeuraiMessage.verify()` from the Neurai addon.

### Get BIP32 extended public key

```javascript
// Request the account xpub (user must press Confirm on device)
const bip32 = await device.getBip32Pubkey();
console.log(bip32.bip32_pubkey);       // "xpub6..."
console.log(bip32.master_fingerprint); // "a1b2c3d4"
console.log(bip32.path);              // "m/44'/1900'/0'"
```

### DePIN chat identity (sign/decrypt on the device)

The device holds a **dedicated DePIN chat identity** on BIP44 account `100'`
(`m/44'/<coin>'/100'/0/0`), separate from the funds account, so a wallet can
chat over Neurai DePIN messaging without ever exposing its mnemonic. Signing and
decryption happen **on the chip**.

Feature-detect first — `ping()` advertises `capabilities`: `"depin_identity"`
(identity + session) and `"depin_message"` (on-device `depinSign`/`depinDecrypt`).
Firmware 0.5.11 also advertises `"depin_bulk_decrypt_b64"` and
`depin_max_decrypt_bytes` (currently 32768). This library negotiates those
automatically on the first decrypt: it preserves the public hex API, but sends
valid inputs in Base64 when supported, avoiding hex's 2× serial expansion.

```javascript
const { capabilities = [] } = await device.ping();
if (!capabilities.includes("depin_identity")) throw new Error("update firmware");

// 1) Open a session on the channel token — ONE physical approval on the device.
//    While active the device reveals its identity and auto-signs/decrypts on
//    this channel (bounded by an idle timeout, a hard cap, and a rate limit).
const session = await device.depinSessionBegin("&NEURAI.CHAT", {
  ttlMinutes: 15,   // idle window (1–60, default 15)
  ratePerMin: 100,  // in-session sign/decrypt cap (default 100)
});
console.log(session.expires_in_s, session.max_session_s, session.rate_per_min);

// 2) Read the chat identity (no per-call prompt while the session is open).
//    This is what a hardware wallet uses instead of deriving from a mnemonic.
const id = await device.getDepinIdentity();
console.log(id.address, id.pubkey, id.path, id.network); // "xna" | "xna-test"

// 3) Sign an outgoing message. The host does the recipient-pubkey ECIES
//    encryption and passes the fields; the device builds the canonical
//    CDepinMessage preimage and returns the DER signature.
const { signature, op_count } = await device.depinSign({
  token: "&NEURAI.CHAT",
  sender: id.address,                 // must equal the device's DePIN address
  timestamp: Math.floor(Date.now() / 1000),
  messageType: 1,                     // 1 = direct (DATA), 2 = group (BROADCAST)
  encryptedPayload: eciesPayloadHex,  // built host-side
});

// 4) Decrypt an incoming CDepinMessage addressed to this identity.
//    GCM-authenticated; the sender's signature is verified host-side.
const { plaintext_b64 } = await device.depinDecrypt(cdepinMessageHex);

// For a privacy-wrapped server response { encrypted: "<hex>" }, decrypt the
// bare ECIES payload. Oversize payloads are rejected locally with a clear
// error; paginate the server response instead of risking a device reset.
const result = await device.depinDecryptPayload(encryptedPayloadHex);

// 5) End the session when done (also revoked on lock / USB disconnect / timeout).
await device.depinSessionEnd();
```

> **Note on time:** the device has no real-time clock, so it does **not** check
> the freshness of `timestamp` — the host supplies it and the chip only validates
> the message structure and channel/sender scope.

### Provision an unconfigured device (`setup_seed`)

Firmware with the security layer boots **unconfigured** until a seed is stored
(and **locked** at every boot after that, until the owner enters the PIN on the
device). Instead of typing 12/24 words with two buttons, a host that holds the
mnemonic (e.g. it just generated the wallet) can push it over USB:

```javascript
// 1) Where is the device at?
const state = await device.getDeviceState(); // "ready" | "locked" | "unconfigured"

if (state === "unconfigured") {
  // 2) Send the seed. The owner must physically approve a SUMMARY on the
  //    device within 60 s (word count + network + key type — never the words).
  const res = await device.setupSeed({
    mnemonic: "word1 word2 ... word12",  // 12 or 24 BIP39 words
    network: "testnet",                  // REQUIRED: "mainnet" | "testnet"
    keyType: "pq",                       // REQUIRED: "pq" | "legacy" (pq = testnet-only)
  });
  console.log(res.state);                // "pin_required"

  // 3) The owner now creates the PIN ON THE DEVICE (it never travels over
  //    USB). Poll until the seed is encrypted and the keys are derived:
  await device.waitUntilReady();         // default: every 2 s, up to 5 min
}

// 4) Normal operation from here.
const info = await device.getInfo();
```

Notes:

- `setup_seed` is **only accepted while no encrypted seed is stored** (first
  boot, dev-fallback firmware, or after an on-device wipe). On a configured
  device it throws `"Device already configured: wipe it on-device first"`
  without prompting — it can never overwrite an existing wallet.
- If the owner rejects (or the 60 s pass) you get `"User cancelled"`; if they
  cancel during PIN entry the device stays unconfigured and you can simply call
  `setupSeed` again.
- `getDeviceState()` distinguishes `locked` (ask the user to enter the PIN on
  the device) from `unconfigured` (provisioning applies) by parsing the
  firmware's gate errors; it never prompts and is safe to poll.
- **Security:** the mnemonic transits the host OS and the USB link in
  plaintext — acceptable when this host generated the seed, but entering the
  words directly on the device remains the more private path.

## Post-Quantum (PQ / ML-DSA-44) support

The device operates in one mode at a time, declared via `info` on two
orthogonal axes:

- **network**: `mainnet` / `testnet`
- **key_type**: `legacy` (ECDSA/secp256k1 P2PKH) / `pq` (ML-DSA-44 AuthScript)

The library reads `info.key_type` and routes automatically — the same
`getAddress()` / `signTransaction()` calls work in both modes. PQ uses the
AuthScript witness-v1 format (`nq1…` mainnet / `tnq1…` testnet), which cannot be
represented in a PSBT, so spending from PQ uses a raw-transaction transport
(`sign_tx`) under the hood. See [`docs/pq-protocol-design.md`](./docs/pq-protocol-design.md).

> The device exposes **only the public key** of its single address; the library
> derives the `nq1…`/`tnq1…` address from that pubkey + mode.

### Read a PQ address

```javascript
const device = new NeuraiESP32();
await device.connect();

const info = await device.getInfo();
console.log(info.key_type); // "pq"
console.log(info.network);  // "NeuraiTest"

// In PQ mode the device returns only the pubkey; the library derives the address.
const addr = await device.getAddress(); // requires confirmation on device
console.log(addr.type);       // "pq"
console.log(addr.address);    // "tnq1..."
console.log(addr.commitment); // 32-byte AuthScript commitment (hex)
```

### Send to a PQ address (from a legacy ECDSA wallet)

No special handling is needed: pass a `nq1…`/`tnq1…` destination to
`signTransaction`/`buildPSBT`. The library encodes the AuthScript output script
automatically; the ECDSA inputs are still signed via `sign_psbt`.

```javascript
const result = await device.signTransaction({
  utxos: [/* legacy P2PKH UTXOs with rawTxHex */],
  outputs: [{ address: "tnq1...", value: 100000000 }], // PQ destination
  changeAddress: address,
});
```

### Spend from a PQ address

When the device is in PQ mode, `signTransaction` routes to the PQ path
(`signPqTransaction`): it builds an unsigned raw transaction, sends it with
per-input metadata via `sign_tx`, and returns the fully-signed transaction.
Change defaults to the device's own single address.

```javascript
const result = await device.signTransaction({
  utxos: [
    {
      txid: "abcd1234....",
      vout: 0,
      satoshis: 100000000,
      scriptPubKey: "5120<32-byte commitment>", // the PQ address script
      type: "pq",
      // sighashAmount: 0,  // use 0 for asset-wrapped inputs
    },
  ],
  outputs: [{ address: "tnq1...", value: 50000000 }],
  // changeAddress defaults to the device's PQ address
});

console.log(result.txHex); // signed raw tx, ready to broadcast via the node RPC
console.log(result.txId);
```

### Verify a device signature (optional)

You can independently verify the ML-DSA-44 signature the device produced by
recomputing the AuthScript sighash and checking it against the pubkey (using
`@noble/post-quantum`, which is not a runtime dependency of this library):

```javascript
import {
  extractPQWitness,
  pqAuthScriptSighash,
} from "@neuraiproject/neurai-sign-esp32";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";

const w = extractPQWitness(result.txHex, 0);
const sighash = pqAuthScriptSighash({
  tx: result.txHex,
  inputIndex: 0,
  amount: 100000000,      // the prevout amount used for that input
  witnessScript: "51",    // OP_TRUE (phase 1)
  authType: 1,
});
const ok = ml_dsa44.verify(w.signature, sighash, w.pubkey); // verify(sig, msg, pub)
```

[`examples/browser-test.html`](./examples/browser-test.html) demonstrates this
full flow end-to-end (read PQ address → sign a test transaction → verify the
ML-DSA-44 signature).

### Check Web Serial API support

```javascript
import { NeuraiESP32 } from "@neuraiproject/neurai-sign-esp32";

if (!NeuraiESP32.isSupported()) {
  console.log("Web Serial API not supported. Use Chrome, Edge, or Opera.");
}
```

## Manual browser smoke test

There is a browser demo at
[`examples/browser-test.html`](./examples/browser-test.html) that imports the
generated browser ESM bundle from `dist/browser.js`. It reads a PQ address from
the device and (in PQ mode) signs a test transaction and verifies the ML-DSA-44
signature.

Suggested flow:

1. Run `npm run build`.
2. Serve the **repository root** over HTTP (so `dist/` is reachable), for example
   `npx serve .` or `python3 -m http.server 8000`.
3. Open `http://localhost:8000/examples/browser-test.html` in Chrome or Edge.
4. Click `Conectar`, pick the port, and confirm on the device. The page shows the
   derived `tnq1…` address.
5. Click `Firmar transacción de prueba` and confirm on the device. The page signs
   a fictitious transaction and shows `✓ Firma ML-DSA-44 VÁLIDA`.

> Serve from the repo root — serving only `examples/` leaves `../dist/browser.js`
> unreachable and the page cannot load the library.

## React Native / Android USB

The same library drives a NeuraiHW device from a React Native app over USB-C on
**Android** (iOS does not expose generic USB serial to apps). The device class
talks to a small transport interface, so the only platform-specific part is
moving raw bytes — all protocol logic (the 256-byte / 8 ms chunked writes, line
buffering, JSON parsing, timeouts) is shared.

The package does **not** depend on any native USB module. You adapt your chosen
module (e.g. `react-native-usb-serialport-for-android`, `react-native-serialport`,
or your own TurboModule) to the tiny `IUsbSerialDriver` interface and pass it in.

```ts
import {
  createNeuraiESP32OverUsb,
  bytesToBase64,
  base64ToBytes,
  type IUsbSerialDriver,
} from "@neuraiproject/neurai-sign-esp32/react-native";

// Adapt your native module here. This sketch assumes a module that exchanges
// data as base64 strings (the common case on Android).
const usbDriver: IUsbSerialDriver = {
  async open({ baudRate }) {
    const native = await MyUsbModule.open({ baudRate }); // your module
    return {
      write: (data) => native.send(bytesToBase64(data)),
      onReceive: (handler) => {
        const sub = native.onData((b64: string) => handler(base64ToBytes(b64)));
        return { remove: () => sub.remove() };
      },
      close: () => native.close(),
    };
  },
};

const device = createNeuraiESP32OverUsb(usbDriver);
await device.connect();
const info = await device.getInfo();
const { address } = await device.getAddress(); // user confirms on the device
const result = await device.signTransaction({ utxos, outputs, changeAddress: address });
console.log(result.txHex);
await device.disconnect();
```

From here the API is identical to the browser flow (`getInfo`, `getAddress`,
`signTransaction`, `signMessage`, `getBip32Pubkey`, PQ support…).

### Building a custom transport

`createNeuraiESP32OverUsb` is sugar over the same building blocks the Web Serial
transport uses. To target any other platform, implement `IByteChannel` (four
methods: `isOpen`, `onData`, `open`, `write`, `close`) and wrap it in a
`SerialProtocol`:

```ts
import { NeuraiESP32, SerialProtocol, type IByteChannel } from "@neuraiproject/neurai-sign-esp32";

class MyByteChannel implements IByteChannel { /* … */ }

const device = new NeuraiESP32({ transport: new SerialProtocol(new MyByteChannel()) });
```

You do **not** need to replicate the chunked-write workaround in your channel —
`SerialProtocol` handles it for every transport.

### Android setup notes

- Add `<uses-feature android:name="android.hardware.usb.host" />` to the app
  manifest, and request runtime USB permission for the device.
- The ESP32-S3 enumerates with USB vendor id `0x303a` (and CDC bridges such as
  `0x10c4`, `0x1a86`, `0x0403`, `0x067b` for other boards).
- Open the port at **115200** baud, 8-N-1.

## Build outputs

After `npm run build`, the package publishes:

- `dist/index.js`: primary ESM entry
- `dist/index.cjs`: CommonJS entry
- `dist/browser.js`: explicit browser ESM entry
- `dist/react-native.js`: React Native entry (no Web Serial; adds the USB transport)
- `dist/NeuraiSignESP32.global.js`: IIFE bundle exposing `globalThis.NeuraiSignESP32`
- `dist/index.d.ts` / `dist/react-native.d.ts`: public types

## UTXO requirements

Each UTXO requires the `rawTxHex` field — the full raw hex of the previous
transaction. This is needed because P2PKH inputs use `nonWitnessUtxo` in the
PSBT spec. You can get it from your Neurai node:

```javascript
const rawTxHex = await rpc("getrawtransaction", [txid]);
```

## Networks

The public model has two orthogonal axes: **network** (`mainnet`/`testnet`) and
**key_type** (`legacy`/`pq`). The device declares both via `info`. Internally
these resolve to a `NetworkType` identifier:

| network | key_type | Internal `NetworkType` | Coin type | Address prefix |
|---|---|---|---|---|
| mainnet | legacy | `xna` | 1900 | `N…` (P2PKH) |
| testnet | legacy | `xna-test` | 1 | testnet P2PKH |
| mainnet | pq | `xna-pq` | 1900 | `nq1…` (AuthScript) |
| testnet | pq | `xna-pq-test` | 1 | `tnq1…` (AuthScript) |

`xna-legacy` / `xna-legacy-test` (coin type 0) remain available for the legacy
coin-type-0 derivation and are unrelated to `key_type: "legacy"`. Use
`resolveNetwork(network, keyType)` to map the two axes to a `NetworkType`.

## Chunked serial writes (important)

The ESP32 CDC serial buffer can lose data when the host sends a large payload
in a single write. This is a known issue with USB CDC on ESP32-S3 — the
firmware's `Serial.read()` loop cannot drain the buffer fast enough if the
host flushes several kilobytes at once.

This library works around the problem by splitting every outgoing message into
**256-byte chunks** with a **8 ms pause** between each one.

The newline terminator (`\n`) is sent separately after all chunks, so the
firmware only processes the command once the full JSON has arrived.

If you build your own serial transport, make sure to replicate this chunked
write strategy — otherwise `sign_psbt` commands (which carry large base64
payloads) will fail silently or produce corrupted data on the device.

## Device protocol

The library communicates with the ESP32 firmware over USB Serial (115200 baud)
using JSON messages. Supported commands:

| Command | Confirmation | Timeout |
|---|---|---|
| `info` | None | 5s |
| `setup_seed` | Physical button (summary on screen) | 60s approval + on-device PIN entry |
| `get_address` | Physical button | 30s |
| `get_bip32_pubkey` | Physical button | 30s |
| `sign_psbt` | Physical button + TX review | 60s |
| `sign_tx` (PQ) | Physical button + TX review | per-heartbeat (ML-DSA is slow) |
| `sign_message` | Physical button | 30s |
| `depin_session_begin` | Physical button (channel token on screen) | 30s |
| `get_depin_identity` | None (session-gated) | 10s |
| `depin_sign_digest` | Physical button | 30s |
| `depin_sign` | None (session-gated, rate-limited) | 30s |
| `depin_decrypt` | None (session-gated, rate-limited) | 30s |
| `depin_decrypt_payload` | None (session-gated, rate-limited) | 30s |
| `depin_session_status` | None (session-key gated) | 10s |
| `depin_session_end` | None (session-key gated) | 10s |

`info` reports `key_type` (`"legacy"` | `"pq"`). In PQ mode, `get_address`
returns only the public key (the library derives the address) and signing uses
`sign_tx` (raw transaction) instead of `sign_psbt`.

While the device is **locked** (encrypted seed stored, PIN pending) or
**unconfigured** (no seed), the firmware rejects every command except
`setup_seed` with a distinct error message; `getDeviceState()` parses those
into `"locked"` / `"unconfigured"`.

## API

### `NeuraiESP32`

Main class for device interaction.

| Method | Description |
|---|---|
| `connect()` | Open USB Serial connection (browser dialog) |
| `disconnect()` | Close connection |
| `ping()` | Detect/handshake the device (no confirmation, no wallet-identifying data) — use this to enumerate devices |
| `getDeviceState()` | `"ready"` \| `"locked"` \| `"unconfigured"` — safe to poll, no confirmation |
| `setupSeed({ mnemonic, network, keyType })` | Provision an unconfigured device with a host-held seed (owner approves on device, then sets the PIN there) |
| `waitUntilReady(opts?)` | Poll until the device is operational (after `setupSeed` PIN entry or unlock) |
| `getInfo()` | Get device info incl. `key_type` (**requires confirmation** on consent-model firmware) |
| `getAddress()` | Get address + pubkey (requires confirmation); derives the address from the pubkey + mode (legacy or PQ) |
| `getBip32Pubkey()` | Get account xpub (requires confirmation) |
| `signPsbt(base64)` | Sign a PSBT (requires confirmation) |
| `signPsbt(base64, display?)` | Sign a PSBT and optionally send display metadata |
| `signMessage(message)` | Sign a message to prove address ownership (requires confirmation) |
| `depinSessionBegin(token, opts?)` | Open a DePIN chat session on a channel token (one approval); enables identity read + auto sign/decrypt |
| `getDepinIdentity()` | Read the DePIN chat identity (address + pubkey + path); session-gated, no per-call prompt |
| `depinSign(params)` | Sign a DePIN message on-device (DER over the canonical CDepinMessage); session-gated, rate-limited |
| `depinDecrypt(depinMessageHex)` | Decrypt a CDepinMessage addressed to this identity → `plaintext_b64`; session-gated. Uses Base64 automatically on firmware 0.5.11+ |
| `depinDecryptPayload(encryptedPayloadHex)` | Decrypt a bare ECIES `encrypted_payload_hex` (decomposed server item) → `plaintext_b64`; session-gated. Uses Base64 automatically on firmware 0.5.11+ and rejects data above its announced limit |
| `depinSignDigest(digestHex)` | Sign a tx sighash with the DePIN key (account 100') → `{ signature, pubkey }`; physical confirmation, for the pubkey-reveal burn |
| `depinSessionStatus()` | Check whether the cached/`setDepinSessionKey` key still names a live session → `{ active, token?, expires_in_s? }` (proto v2) |
| `getDepinSessionKey()` / `setDepinSessionKey(key)` | Read / restore the per-session capability key (persist it in the OS keystore across restarts) |
| `depinSessionEnd()` | End the DePIN session (also revoked on lock / disconnect / timeout) |
| `signTransaction(opts)` | Build + sign + finalize in one call; auto-routes legacy (PSBT) vs PQ (`sign_tx`) by device mode |
| `signPqTransaction(opts)` | Spend from a PQ address: build raw tx + sign via `sign_tx` (used internally by `signTransaction` in PQ mode) |

### Post-Quantum helpers

| Function | Description |
|---|---|
| `isPQAddress(addr)` | True for `nq1…`/`tnq1…` AuthScript addresses |
| `decodeAddress(addr)` | Decode a legacy or PQ address (`{ type, commitment \| hash, … }`) |
| `encodeDestinationScript(addr)` | Output scriptPubKey for any supported address |
| `publicKeyToAddress(pubkeyHex, { network, keyType })` | Derive an address from a public key + mode |
| `resolveNetwork(network, keyType)` | Map the two axes to a `NetworkType` |
| `buildUnsignedPQTransaction(opts)` | Build the unsigned raw tx + per-input metadata for `sign_tx` |
| `extractPQWitness(signedTxHex, index?)` | Decode the AuthScript witness (`authType`, `signature`, `pubkey`, `witnessScript`) |
| `pqAuthScriptSighash(opts)` | Recompute the AuthScript sighash (to verify device signatures) |

### `buildPSBT(options)`

Build an unsigned PSBT for P2PKH. Returns base64 string.

### `buildPSBTFromRawTransaction(options)`

Build an unsigned PSBT from an already-created raw unsigned transaction plus
input metadata. This is the preferred path when the wallet already handles coin
selection, fee calculation, asset outputs, and change outputs externally.

### `finalizePSBT(base64, network)`

Finalize a signed PSBT. Returns `{ txHex, txId }`.

### `finalizeSignedPSBT(originalPsbtBase64, signedPsbtBase64, network)`

Merge a signed PSBT returned by the device with the original PSBT and finalize it.
This helper also supports the minimal PSBT format returned by `uNeurai`, and
includes fallback logic for legacy P2PKH finalization used by Neurai.

### `validatePSBT(base64, network)`

Check if a PSBT base64 string is parseable. Returns boolean.

[Check the TypeScript definitions](./dist/index.d.ts) for all the details.

## Browser support

The default transport requires the Web Serial API: Chrome 89+, Edge 89+,
Opera 75+. Firefox and Safari are not supported.

For non-browser platforms (React Native / Android USB, Node test doubles, …)
inject a custom transport instead — see
[React Native / Android USB](#react-native--android-usb).
