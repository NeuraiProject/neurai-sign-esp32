# neurai-sign-esp32

Create and sign Neurai (XNA) transactions via ESP32 hardware wallet.

This library handles the full PSBT workflow against a NeuraiHW device:
build an unsigned PSBT, send it over USB Serial for signing, receive
the signed PSBT back, finalize it, and extract the raw transaction hex
ready for broadcast.

Uses [bitcoinjs-lib](https://www.npmjs.com/package/bitcoinjs-lib) v7 for
PSBT construction and the Web Serial API for device communication.

##

EXPERIMENTAL.

Only XNA (native coin) transfers are supported for now.
Asset transfers will be added in a future version.

## Install

```
npm i @neuraiproject/neurai-sign-esp32
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

### Get BIP32 extended public key

```javascript
// Request the account xpub (user must press Confirm on device)
const bip32 = await device.getBip32Pubkey();
console.log(bip32.bip32_pubkey);       // "xpub6..."
console.log(bip32.master_fingerprint); // "a1b2c3d4"
console.log(bip32.path);              // "m/44'/1900'/0'"
```

### Check Web Serial API support

```javascript
import { NeuraiESP32 } from "@neuraiproject/neurai-sign-esp32";

if (!NeuraiESP32.isSupported()) {
  console.log("Web Serial API not supported. Use Chrome, Edge, or Opera.");
}
```

## UTXO requirements

Each UTXO requires the `rawTxHex` field — the full raw hex of the previous
transaction. This is needed because P2PKH inputs use `nonWitnessUtxo` in the
PSBT spec. You can get it from your Neurai node:

```javascript
const rawTxHex = await rpc("getrawtransaction", [txid]);
```

## Networks

Supported network types:

| Network | Coin type | Address prefix |
|---|---|---|
| `xna` | 1900 | N (mainnet, recommended) |
| `xna-test` | 1 | testnet |
| `xna-legacy` | 0 | N (legacy mainnet) |
| `xna-legacy-test` | 1 | testnet legacy |

## Chunked serial writes (important)

The ESP32 CDC serial buffer can lose data when the host sends a large payload
in a single write. This is a known issue with USB CDC on ESP32-S3 — the
firmware's `Serial.read()` loop cannot drain the buffer fast enough if the
host flushes several kilobytes at once.

This library works around the problem by splitting every outgoing message into
**32-byte chunks** with a **4 ms pause** between each one. This matches the
approach used in the reference web wallet (`NeuraiHWSerial.writeChunked`).

The newline terminator (`\n`) is sent separately after all chunks, so the
firmware only processes the command once the full JSON has arrived.

If you build your own serial transport, make sure to replicate this chunked
write strategy — otherwise `sign_psbt` commands (which carry large base64
payloads) will fail silently or produce corrupted data on the device.

## Device protocol

The library communicates with NeuraiHW firmware over USB Serial (115200 baud)
using JSON messages. Supported commands:

| Command | Confirmation | Timeout |
|---|---|---|
| `info` | None | 5s |
| `get_address` | Physical button | 30s |
| `get_bip32_pubkey` | Physical button | 30s |
| `sign_psbt` | Physical button + TX review | 60s |

## API

### `NeuraiESP32`

Main class for device interaction.

| Method | Description |
|---|---|
| `connect()` | Open USB Serial connection (browser dialog) |
| `disconnect()` | Close connection |
| `getInfo()` | Get device info (no confirmation) |
| `getAddress()` | Get address + pubkey (requires confirmation) |
| `getBip32Pubkey()` | Get account xpub (requires confirmation) |
| `signPsbt(base64)` | Sign a PSBT (requires confirmation) |
| `signTransaction(opts)` | Build + sign + finalize in one call |

### `buildPSBT(options)`

Build an unsigned PSBT for P2PKH. Returns base64 string.

### `finalizePSBT(base64, network)`

Finalize a signed PSBT. Returns `{ txHex, txId }`.

### `validatePSBT(base64, network)`

Check if a PSBT base64 string is parseable. Returns boolean.

[Check the TypeScript definitions](./dist/index.d.ts) for all the details.

## Browser support

Requires Web Serial API: Chrome 89+, Edge 89+, Opera 75+.
Firefox and Safari are not supported.
