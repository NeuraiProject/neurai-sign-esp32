# neurai-sign-esp32

Create and sign Neurai (XNA) and asset transactions via ESP32 hardware wallet.

This library handles the full PSBT workflow against an ESP32 hardware wallet:
build an unsigned PSBT, send it over USB Serial for signing, receive
the signed PSBT back, finalize it, and extract the raw transaction hex
ready for broadcast.

Uses [bitcoinjs-lib](https://www.npmjs.com/package/bitcoinjs-lib) v7 for
PSBT construction and the Web Serial API for device communication.

It also supports **Post-Quantum (ML-DSA-44 / AuthScript) addresses**: sending to
them and spending from the device's PQ address (`nc1p…`/`tnc1p…`). The library
auto-detects the device mode from `info` and routes accordingly — see
[Post-Quantum support](#post-quantum-pq--ml-dsa-44-support). Outputs can pay to
every Neurai address type — see [Address types](#address-types).

> **0.7.0 follows the new Neurai address types** (node Neurai-DePIN,
> `@neuraiproject/neurai-key` 5): the device's PQ address is now encoded as
> `nc1p…`/`tnc1p…` (it used to be `nq1p…`/`tnq1p…`, which the node rejects) and
> `nq1…`/`tnq1…` now means strict ECDSA witness v3. See
> [Upgrading to 0.7.0](#upgrading-to-070).

##

EXPERIMENTAL.

This library supports:
- XNA transfers
- Asset transfers
- BIP32 account discovery via `get_bip32_pubkey`
- Message signing (prove address ownership)
- **Post-Quantum addresses (ML-DSA-44 / AuthScript)** — send to and spend from `nc1p…`/`tnc1p…`
- Sending to every Neurai address type: Legacy P2PKH, `nc1p…`, `pq1z…`, `nq1r…`
- Strict ECDSA witness v3 (`nq1r…`) inputs through `sign_psbt` (firmware built with uNeurai >= 0.2.0)

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
  // The IIFE exposes the DePIN adapter too:
  // window.NeuraiSignESP32.createDepinDeviceIdentity(device, options)
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

### DePIN protocol 2: use the device as a messaging identity

The calls above are the raw device commands. For the full **DePIN Messaging
Protocol 2** flows (challenge → receive → publish → purge) there is an adapter
that turns the device into an identity consumable by
[`@neuraiproject/neurai-depin-msg`](https://www.npmjs.com/package/@neuraiproject/neurai-depin-msg)
`>= 3.1.0`, without the private key ever leaving the chip:

```javascript
import { createDepinDeviceIdentity } from "@neuraiproject/neurai-sign-esp32";
import { requestDepinChallenge, receiveDepinMessages } from "@neuraiproject/neurai-depin-msg";

// Opens (or reuses) a session for the token and validates the announced
// identity against the network you expect. ONE physical approval.
const identity = await createDepinDeviceIdentity(device, {
  token: "&NEURAI.CHAT",
  expectedNetwork: "test",                      // must match the app's network
  sessionPermissions: ["receive", "publish"],   // default: ["receive"]
  ttlMinutes: 15,
});

// From here it is an ordinary depin-msg identity.
const challenge = await requestDepinChallenge({
  rpc, identity, token: "&NEURAI.CHAT", poolPublicKey,
});
const page = await receiveDepinMessages({
  rpc, identity, token: "&NEURAI.CHAT", challenge: challenge.challenge,
  poolPublicKey, network: "test", limit: 25,
});
```

**Session permissions.** They are independent capabilities, because a session
approved for reading must not be able to publish in the owner's name or purge
the pool:

| Permission | Authorises |
| --- | --- |
| `receive` | `DEPIN-REQ` (type `receive`) and `DEPIN-GET` — reading |
| `publish` | `depin_sign` — publishing messages |
| `admin` | `DEPIN-REQ` (type `admin`) and `DEPIN-CLEAR` — purging |

Decryption is inherent to **any** live session, so say so when asking for
approval. An omitted list grants only `["receive"]`, never `admin`. Requesting
a different set than the device granted fails instead of silently reusing a
more privileged session. And `admin` implies a *total* purge: the `mode`
argument of `depinclearmsg` is not part of the signed `DEPIN-CLEAR` preimage,
so a purge signature cannot be narrowed after the fact.

**Why not `depinSignDigest`.** That command signs an arbitrary 32-byte hash —
possibly a transaction sighash — which is exactly why it is *not* session-gated
and always asks for a physical confirmation. The adapter never uses it:
authentication goes through `depinSignAuth`, where the device receives the
structured fields, rebuilds `DEPIN-REQ|…` / `DEPIN-GET|…` / `DEPIN-CLEAR|…`
plus the signed-message envelope itself, and validates them against the session
before signing. `depinSignDigest` stays for what it was meant for, such as the
pubkey-reveal transaction.

Every signature the device returns is verified on the host before it is used,
so a device that signs the wrong digest or with another key fails locally
instead of at the node. Errors are `DepinDeviceIdentityError` with stable
`code`s (`SESSION_PERMISSION_INSUFFICIENT`, `SESSION_TIME_BUDGET_INSUFFICIENT`,
`INVALID_DEVICE_SIGNATURE`, `PAYLOAD_TOO_LARGE`…) so a UI can map them to
concrete actions.

**Sizing the session.** `identity.maxDecryptBytes` reports what the device can
decrypt in one go; pick `limit` so a page fits, because a reply the device
cannot open costs the whole challenge (`next_challenge` travels *inside* it).
A round costs roughly 4 device operations for an initial read, 2 for a chained
one, 2 to publish and 4 to purge — size `ratePerMin` accordingly. Before a
sequence that spans several calls, reserve time explicitly:

```javascript
await identity.session.ensure({ minRemainingSeconds: 60 });
```

> **Firmware requirement.** The adapter needs firmware advertising protocol 2
> with `depin_identity`, `depin_message`, `depin_auth_sign`,
> `depin_session_key` and `depin_session_permissions`; it refuses to downgrade.
> `depin_sign_auth` and session permissions are **not implemented in current
> firmware yet** — the contract they must satisfy is specified, and exercised
> by a cryptographically faithful device mock, in this package's tests.
> `@neuraiproject/neurai-depin-msg@3.1.2` must be published before installing
> this repository from scratch or publishing `neurai-sign-esp32@0.7.0`. The
> package has no runtime dependency on `neurai-depin-msg`; it is a `^3.1.2`
> development dependency used only by the integration tests. The package gate
> validates the adapter from a clean `neurai-sign-esp32` tarball.

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
generic AuthScript witness-v1 format (`nc1p…` mainnet / `tnc1p…` testnet;
authType `0x01`, witnessScript `OP_TRUE`), which cannot be represented in a
PSBT, so spending from PQ uses a raw-transaction transport (`sign_tx`) under the
hood. See [`docs/pq-protocol-design.md`](./docs/pq-protocol-design.md).

> The device exposes **only the public key** of its single address; the library
> derives the `nc1p…`/`tnc1p…` address from that pubkey + mode. The firmware
> sends `auth_type` / `witness_script` in snake_case; `getAddress()` returns them
> as `authType` / `witnessScript`.

> Firmware built against uNeurai < 0.2.0 still reports its address as
> `nq1p…`/`tnq1p…` in `info`; `getInfo()` / `getAddress()` re-encode it to the
> valid `nc1p…`/`tnc1p…` form (same scriptPubKey), so it keeps working as a
> change address. The strict PQ family (witness v2, `pq1z…`) is not produced by
> the current firmware; `sign_tx` refuses v2/v3 prevouts before contacting the
> device.

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
console.log(addr.address);    // "tnc1p..."
console.log(addr.commitment); // 32-byte AuthScript commitment (hex)
```

### Send to a PQ address (from a legacy ECDSA wallet)

No special handling is needed: pass any AuthScript destination (`tnc1p…`,
`tpq1z…`, `tnq1r…`, or the mainnet forms) to `signTransaction`/`buildPSBT`. The
library encodes the output script (`OP_1`/`OP_2`/`OP_3` `0x20 <commitment>`)
automatically and checks that the address belongs to the PSBT's chain; the
ECDSA inputs are still signed via `sign_psbt`.

```javascript
const result = await device.signTransaction({
  utxos: [/* legacy P2PKH UTXOs with rawTxHex */],
  outputs: [{ address: "tnc1p...", value: 100000000 }], // PQ destination
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
      scriptPubKey: "5120<32-byte commitment>", // the PQ address script (witness v1)
      type: "pq",
      // sighashAmount: 0,  // use 0 for asset-wrapped inputs
    },
  ],
  outputs: [{ address: "tnc1p...", value: 50000000 }],
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

`pqAuthScriptSighash` computes the generic witness-v1 sighash by default. The
strict families use a different preimage (the witness version byte is written
before `authType`, and the scriptCode is always `OP_TRUE`); a v1-style
signature is **not** valid for them:

```javascript
import { strictAuthScriptSighash } from "@neuraiproject/neurai-sign-esp32";

// Strict PQ v2 (pq1z…) or strict ECDSA v3 (nq1r…) input
const h = strictAuthScriptSighash({ tx, inputIndex: 0, amount, witnessVersion: 2 });
// witness: [authType, sig||hashType, pubkey, 0x51] (v2: authType 0x01 + 0x05||pq_pubkey,
//          v3: authType 0x02 + compressed secp256k1 pubkey)
```

The current firmware signs witness v1 only (`sign_tx`) and, with uNeurai >=
0.2.0, strict ECDSA v3 inputs through `sign_psbt`; the strict sighash is here so
hosts can verify or build strict spends (and for future firmware).

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
   derived `tnc1p…` address.
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
- `dist/index.d.ts` / `dist/react-native.d.ts`: public types (ESM)
- `dist/index.d.cts`: the same types for `require` (CommonJS)

`npm run test:types` compiles the consumers in `types-test/` (ESM, CommonJS,
browser and React Native) against the built declarations in NodeNext, Node16
and Bundler. `npm run test:package` packs the tarball, installs it in a clean
project and checks runtime and types there, with TypeScript 5.3 too (the
oldest release the declarations support).

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

| network | key_type | Internal `NetworkType` | Coin type | Address prefix | neurai-key 5 name |
|---|---|---|---|---|---|
| mainnet | legacy | `xna` | 1900 | `N…` (P2PKH) | `xna-legacy` |
| testnet | legacy | `xna-test` | 1 | `t…` (P2PKH) | `xna-legacy-test` |
| mainnet | pq | `xna-pq` | 1900 | `nc1p…` (AuthScript v1) | `xna-authscript` |
| testnet | pq | `xna-pq-test` | 1 | `tnc1p…` (AuthScript v1) | `xna-authscript-test` |

`xna-legacy` / `xna-legacy-test` (coin type 0) remain available for the legacy
coin-type-0 derivation and are unrelated to `key_type: "legacy"` (neurai-key 5
calls the mainnet one `xna-old-legacy`). Use
`resolveNetwork(network, keyType)` to map the two axes to a `NetworkType`.

### Naming differences with `@neuraiproject/neurai-key` 5

This package's `NetworkType` names predate neurai-key 5 and keep their meaning.
Three of them are spelled like key-5 networks that mean something else:

| name | here | in neurai-key 5 |
|---|---|---|
| `xna` | Legacy P2PKH, coin type 1900 | strict ECDSA witness v3 (`nq1r…`) |
| `xna-legacy` | Legacy P2PKH, coin type 0 | Legacy P2PKH, coin type 1900 |
| `xna-pq` | AuthScript v1 with a PQ key (`nc1p…`) | strict PQ witness v2 (`pq1z…`) |

- `getNetwork()` also accepts the key-5 names that are unambiguous here:
  `xna-old-legacy` (= `xna-legacy`), `xna-authscript` / `xna-authscript-test`
  (= `xna-pq` / `xna-pq-test`).
- `fromNeuraiKeyNetwork(name)` translates a key-5 name with key-5 semantics
  (`"xna-legacy"` → `"xna"`, …) and throws a descriptive error for the key-5
  families the device flows do not produce (`xna`/`xna-test`: strict ECDSA,
  `xna-pq`/`xna-pq-test`: strict PQ).
- The DePIN identity is always Legacy P2PKH (`m/44'/1900'/100'/0/0`, or
  `m/44'/1'/100'/0/0` on testnet), i.e. neurai-key 5 `xna-legacy` /
  `xna-legacy-test`; the node's DePIN messaging does not accept witness
  addresses.

## Address types

| Family | Witness | HRP (main / test) | scriptPubKey | authType | witnessScript | neurai-key 5 |
|---|---|---|---|---|---|---|
| Legacy P2PKH | — | Base58 `N…` / `t…` | `76a914…88ac` | — | — | `xna-legacy`, `xna-old-legacy` |
| Generic AuthScript | v1 | `nc` / `tnc` → `nc1p…` | `51 20 <C>` | any | any | `xna-authscript` |
| Strict PQ (ML-DSA-44) | v2 | `pq` / `tpq` → `pq1z…` | `52 20 <C>` | `0x01` | `0x51` (fixed) | `xna-pq` |
| Strict ECDSA (secp256k1) | v3 | `nq` / `tnq` → `nq1r…` | `53 20 <C>` | `0x02` | `0x51` (fixed) | `xna` |

`C = taggedHash("NeuraiAuthScript", witnessVersion || auth_descriptor || SHA256(witnessScript))`.

- `decodeAddress()` follows the node: Bech32m first (any case, only these
  HRP/version pairs), Base58 otherwise. `nq1p…`/`tnq1p…` (the old witness-v1
  encoding) is rejected with a hint to use `nc1p…`/`tnc1p…`. The result keeps
  `type: "pq"` for every Bech32m address (as before) and adds `family`
  (`"authscript"` | `"pq"` | `"ecdsa"`), `witnessVersion` and `network`.
- `encodeDestinationScript()` emits `OP_1`/`OP_2`/`OP_3 0x20 <C>`.
- **Activation:** the strict families (v2/v3) are active only on regtest for
  now. Before activation the node refuses `pq1…`/`nq1…` addresses because an
  `OP_2`/`OP_3` output is anyone-can-spend there. The library cannot know the
  activation state of the target chain: do not pay to v2/v3 addresses where
  they are not active.
- PSBT inputs: P2PKH, or strict ECDSA v3 prevouts (the finalizer builds the
  witness `[0x02, sig, pubkey, 0x51]`; needs firmware with uNeurai >= 0.2.0).
  Generic v1 and strict v2 inputs cannot go through a PSBT.

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
returns only the public key plus `auth_type` / `witness_script` (the library
derives the address) and signing uses `sign_tx` (raw transaction) instead of
`sign_psbt`. `sign_tx` signs generic AuthScript v1 inputs only.

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
| `depinSignAuth(command)` | Sign a protocol-2 authentication preimage (`request`/`get`/`clear`) from STRUCTURED fields: the device rebuilds `DEPIN-REQ|…`/`DEPIN-GET|…`/`DEPIN-CLEAR|…` and validates it against the session. Session-gated, permission-checked |
| `depinSignDigest(digestHex)` | Sign a tx sighash with the DePIN key (account 100') → `{ signature, pubkey }`; physical confirmation, **not** session-gated, for the pubkey-reveal burn. Never used by the DePIN messaging adapter |
| `depinSessionStatus()` | Check whether the cached/`setDepinSessionKey` key still names a live session → `{ active, token?, expires_in_s? }` (proto v2) |
| `getDepinSessionKey()` / `setDepinSessionKey(key)` | Read / restore the per-session capability key (persist it in the OS keystore across restarts) |
| `depinSessionEnd()` | End the DePIN session (also revoked on lock / disconnect / timeout) |
| `signTransaction(opts)` | Build + sign + finalize in one call; auto-routes legacy (PSBT) vs PQ (`sign_tx`) by device mode |
| `signPqTransaction(opts)` | Spend from a PQ address: build raw tx + sign via `sign_tx` (used internally by `signTransaction` in PQ mode) |

### Post-Quantum helpers

| Function | Description |
|---|---|
| `isWitnessAddress(addr)` | True for valid `nc1p…`/`pq1z…`/`nq1r…` (and testnet) AuthScript addresses |
| `isPQAddress(addr)` | Deprecated alias of `isWitnessAddress` (true for every AuthScript family, not only ML-DSA keys) |
| `getAddressFamily(addr)` | `"legacy"` \| `"authscript"` \| `"pq"` \| `"ecdsa"` |
| `decodeAddress(addr)` | Decode any address (`{ type, family, witnessVersion, network, commitment \| hash, … }`) |
| `encodeDestinationScript(addr)` | Output scriptPubKey for any supported address |
| `publicKeyToAddress(pubkeyHex, { network, keyType, witnessVersion? })` | Derive an address from a public key + mode (`pq`: v1 `nc1p…` by default, `witnessVersion: 2` for `pq1z…`) |
| `pqAddressFromPublicKey(pubkey, params)` | PQ address in the family of `params` (`getPQNetworkParams(network, 1 \| 2)`) |
| `ecdsaAddressFromPublicKey(pubkey33, network)` | Strict ECDSA v3 address (`nq1r…`/`tnq1r…`) |
| `authScriptCommitment(opts)` / `pqCommitment` / `ecdsaCommitment` | Versioned AuthScript commitments |
| `normalizeDeviceAuthScriptAddress(addr)` | Re-encode a pre-0.2.0 firmware `nq1p…`/`tnq1p…` address as `nc1p…`/`tnc1p…` |
| `resolveNetwork(network, keyType)` | Map the two axes to a `NetworkType` |
| `fromNeuraiKeyNetwork(name)` | Translate a neurai-key 5 network name to a `NetworkType` |
| `buildUnsignedPQTransaction(opts)` | Build the unsigned raw tx + per-input metadata for `sign_tx` (witness v1 prevouts only) |
| `extractPQWitness(signedTxHex, index?)` | Decode the AuthScript witness (`authType`, `signature`, `pubkey`, `witnessScript`) |
| `pqAuthScriptSighash(opts)` | Recompute the AuthScript sighash (to verify device signatures); witness v1 by default, `witnessVersion: 2 \| 3` for strict |
| `strictAuthScriptSighash(opts)` | Strict v2 / v3 sighash (`… locktime \|\| witnessVersion \|\| authType \|\| hashType`) |

### `buildPSBT(options)`

Build an unsigned PSBT for P2PKH (and strict ECDSA v3) inputs. Outputs may pay
to any Neurai address type. Returns base64 string.

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


## Exact amounts (0.6.1)

`IUTXO.satoshis`, `IPQUTXO.satoshis`, output `value`, PQ `amount` and
`sighashAmount` accept `bigint`, integer strings, or safe integer numbers. These
are **raw protocol units**, not decimal XNA or asset units. Values must be
non-negative and no greater than `2100000000000000000n`. Already unsafe numbers
are rejected; converting a rounded number to bigint cannot restore its digits.

```ts
const output = { address: destination, value: 10000000000000001n };
// The same exact amount can be passed as value: '10000000000000001'.
```

Both high-level builders sum funds, calculate change and subtract fees in bigint.
`feeRate` accepts a number or decimal string in satoshis per byte. Fractional
rates are multiplied exactly and rounded upward to a whole satoshi once.

Asset transactions prepared externally should use `buildPSBTFromRawTransaction`
(legacy) or `signPqRawTransaction` (PQ). Their asset payload quantities remain
encoded in the transaction bytes at scale 10^8, independent of asset divisibility.
The high-level address/value output builders construct XNA payment outputs;
they do not create asset transfer payloads. For asset-wrapped PQ inputs, pass
`amount: 0` to the raw signing API, or `sighashAmount: 0` when using the builder.
An asset quantity must never count toward XNA funding: an explicit zero prevout
value contributes zero to fees and payment funding, so separate XNA inputs are
required.

Display metadata uses decimal **strings** for large asset quantities and fees:

```ts
const display = buildAssetTransferDisplayMetadata({
  assetName: 'LARGE',
  assetAmount: '100000000.00000001',
  destinationAddress: destination,
  feeAmount: '0.00000249',
});
```

Plain strings retain their formatting. Invalid amounts, excess decimals and
unsafe large fractional numbers are rejected instead of silently rounded.
Direct signing calls validate display amounts too.

Before handing `sign_tx` to a transport, the library encodes safe raw amounts as
JSON numbers and larger ones as integer strings. Custom transports must preserve
those strings. The reviewed firmware reads `amount` using ArduinoJson
`as<unsigned long long>()`, which supports exact integer strings. Its local
ArduinoJson parser was checked on the host up to MAX_MONEY; this does not replace
an on-device signing and display check of the firmware installed on your ESP32.
No global bigint JSON serializer is required.

## Upgrading to 0.7.0

0.7.0 follows the address types of the Neurai node (Neurai-DePIN) and
`@neuraiproject/neurai-key` 5.

Breaking changes:

- **PQ addresses are encoded as `nc1p…` / `tnc1p…`.** `neuraiPQMainnet` /
  `neuraiPQTestnet` (and `getPQNetworkParams`) use the HRPs `nc` / `tnc`, so
  `publicKeyToAddress(…, { keyType: "pq" })`, `pqAddressFromPublicKey` and
  `getAddress()` return `nc1p…` / `tnc1p…`. The scriptPubKey (`5120<C>`) and the
  commitment did not change: funds on an old `nq1p…` / `tnq1p…` address are
  reachable through the re-encoded address.
- **`nq1…` / `tnq1…` is the strict ECDSA family now.** `decodeAddress` rejects
  the old witness-v1 `nq1p…` / `tnq1p…` form (with a hint), like the node, and
  so do `encodeDestinationScript`, `buildPSBT` and `buildUnsignedPQTransaction`.
- `isPQAddress` validates the address (Bech32m checksum, canonical HRP/version
  pair) instead of matching the `nq1` / `tnq1` prefix, and is true for every
  AuthScript family. It is deprecated in favour of `isWitnessAddress` /
  `getAddressFamily`. Base58 addresses that start with `NQ1…` are no longer
  misclassified.
- `buildPSBT` checks that an AuthScript destination belongs to the PSBT's chain
  (a testnet address in an `xna` PSBT throws) and estimates AuthScript outputs
  at 43 bytes.
- `pqAuthScriptSighash` throws for a sighash type other than `SIGHASH_ALL` and
  for version-3 transactions (it used to return a hash the device and node would
  not agree with); `buildUnsignedPQTransaction` and `signPqRawTransaction`
  reject strict v2/v3 prevouts and version-3 transactions.

Type declarations: `require` now gets CommonJS declarations
(`dist/index.d.cts`). Up to 0.6.1 it got the ESM `dist/index.d.ts`, and a
CommonJS project compiled with `moduleResolution` `node16` failed with TS1471.
bitcoinjs-lib only ships ESM declarations, so `dist/index.d.cts` imports its
types with a `resolution-mode` attribute: the declarations need TypeScript 5.3
or later.

Additions: `strictAuthScriptSighash` and `pqAuthScriptSighash({ witnessVersion })`,
`AUTHSCRIPT_FAMILIES`, `isWitnessAddress`, `getAddressFamily`,
`ecdsaAddressFromPublicKey`, `authScriptCommitment`, `ecdsaCommitment`,
`normalizeDeviceAuthScriptAddress`, `fromNeuraiKeyNetwork`, the strict PQ
params `neuraiPQStrictMainnet` / `neuraiPQStrictTestnet`, v3 PSBT finalization,
and the snake_case `auth_type` / `witness_script` fields of `get_address`, which
are now read (they used to be ignored).

### Testing against a node

`npm test` runs the unit tests (vectors from a Neurai-DePIN regtest node are in
`src/pq-address.fixtures.ts`). `src/node-regtest.integration.test.ts` is an
opt-in end-to-end check: set `NEURAI_REGTEST_CLI` to the `neurai-cli` command of
a regtest node that knows the `nc` / `pq` / `nq` families and it funds v1, v2
and v3 addresses derived by the library, signs spends with software keys
standing in for the device, and checks them with `testmempoolaccept`.

