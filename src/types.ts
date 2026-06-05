/**
 * Types for neurai-sign-esp32
 */

// ─── UTXO ────────────────────────────────────────────────────────────────────

export interface IUTXO {
  /** Transaction ID */
  txid: string;
  /** Output index in the transaction */
  vout: number;
  /** ScriptPubKey hex */
  scriptPubKey: string;
  /** Value in satoshis */
  satoshis: number;
  /** Full raw transaction hex (required for P2PKH nonWitnessUtxo) */
  rawTxHex: string;
}

// ─── Transaction outputs ─────────────────────────────────────────────────────

export interface ITxOutput {
  /** Destination address */
  address: string;
  /** Value in satoshis */
  value: number;
}

// ─── PSBT build options ──────────────────────────────────────────────────────

export interface IBuildPSBTOptions {
  /** Network: 'xna' | 'xna-test' | 'xna-legacy' | 'xna-legacy-test' */
  network: NetworkType;
  /** UTXOs to spend */
  utxos: IUTXO[];
  /** Destination outputs (excluding change) */
  outputs: ITxOutput[];
  /** Change address (device address) */
  changeAddress: string;
  /** Compressed public key hex (from device) */
  pubkey: string;
  /** Master fingerprint hex (from device info) */
  masterFingerprint: string;
  /** BIP44 derivation path, e.g. "m/44'/1900'/0'/0/0" */
  derivationPath: string;
  /** Fee rate in satoshis per byte (default: 1024) */
  feeRate?: number;
}

export interface IPSBTInputMetadata {
  txid: string;
  vout: number;
  sequence?: number;
  rawTxHex: string;
  pubkey?: string;
  masterFingerprint?: string;
  derivationPath?: string;
  sighashType?: number;
}

export interface IAssetTransferDisplayMetadata {
  kind: "asset_transfer";
  assetName: string;
  assetAmount: string;
  destinationAddress: string;
  destinationCount?: number;
  changeAddress?: string;
  changeCount?: number;
  inputAddresses?: string[];
  feeAmount?: string;
  baseCurrency?: string;
}

export type ISigningDisplayMetadata = IAssetTransferDisplayMetadata;

export interface IBuildPSBTFromRawOptions {
  network: NetworkType;
  rawUnsignedTransaction: string;
  inputs: IPSBTInputMetadata[];
  display?: ISigningDisplayMetadata;
}

export interface IBuildAssetTransferDisplayMetadataOptions {
  assetName: string;
  assetAmount: number | string;
  destinationAddress: string;
  destinationCount?: number;
  changeAddress?: string;
  changeCount?: number;
  inputAddresses?: string[];
  feeAmount?: number | string;
  baseCurrency?: string;
}

// ─── Device responses ────────────────────────────────────────────────────────

export interface IDeviceInfo {
  status: string;
  device: string;
  version: string;
  chip: string;
  network: string;
  /**
   * Key/signature scheme the device operates in. Devices/firmware predating PQ
   * support omit this field; the library then assumes `"legacy"`.
   */
  key_type?: KeyType;
  coin_type: number;
  master_fingerprint: string;
  path: string;
  address: string;
  pubkey: string;
}

export interface IAddressResponse {
  status: string;
  /** Address type: legacy P2PKH or PQ AuthScript. */
  type?: KeyType;
  /**
   * Neurai address. In PQ mode the device returns only `pubkey`; the library
   * derives this address from the pubkey + mode and fills it in.
   */
  address: string;
  /** Compressed secp256k1 pubkey (33B, legacy) or raw ML-DSA-44 pubkey (1312B, PQ), hex. */
  pubkey: string;
  path: string;
  // ── PQ-only (present when type === "pq") ──
  /** AuthScript auth type (1 = PQ). */
  authType?: number;
  /** witnessScript hex (phase 1: "51" = OP_TRUE). */
  witnessScript?: string;
  /** 32-byte AuthScript commitment (hex), derived by the library. */
  commitment?: string;
  /** auth_descriptor (hex), derived by the library. */
  authDescriptor?: string;
}

/**
 * A UTXO locked to the device's PQ (AuthScript) address. No derivation path is
 * needed: it belongs to the device's single address (see docs §2).
 */
export interface IPQUTXO {
  txid: string;
  vout: number;
  /** Prevout value in satoshis. */
  satoshis: number;
  /** Prevout scriptPubKey hex ("5120<commitment>"). */
  scriptPubKey: string;
  type: "pq";
  /** Override for the sighash amount (use 0 for asset-wrapped outputs). */
  sighashAmount?: number;
}

export interface IBip32PubkeyResponse {
  status: string;
  bip32_pubkey: string;
  master_fingerprint: string;
  path: string;
}

export interface ISignPsbtResponse {
  status: string;
  psbt: string;
  signed_inputs: number;
}

export interface ISignMessageResponse {
  status: string;
  /** Base64-encoded recoverable signature (65 bytes) */
  signature: string;
  /** Address that signed the message */
  address: string;
  /** The original message that was signed */
  message: string;
}

export interface IErrorResponse {
  status: "error";
  message: string;
}

export interface IProcessingResponse {
  status: "processing";
  stage: string;
}

export type DeviceResponse =
  | IDeviceInfo
  | IAddressResponse
  | IBip32PubkeyResponse
  | ISignPsbtResponse
  | ISignTxResponse
  | ISignMessageResponse
  | IErrorResponse
  | IProcessingResponse;

// ─── Serial connection options ───────────────────────────────────────────────

export interface ISerialOptions {
  /** Baud rate (default: 115200) */
  baudRate?: number;
  /** USB vendor/product filters for port selection */
  filters?: SerialPortFilter[];
}

// ─── Network type ────────────────────────────────────────────────────────────

/**
 * Public API model: two orthogonal axes.
 * - `Network`  — the chain network (mainnet / testnet).
 * - `KeyType`  — the key/signature scheme the device operates in
 *   (`legacy` = ECDSA/secp256k1 P2PKH, `pq` = ML-DSA-44 AuthScript).
 *
 * The device declares both via `info` (`network` + `key_type`); the library
 * routes accordingly. See docs/pq-protocol-design.md.
 */
export type Network = "mainnet" | "testnet";
export type KeyType = "legacy" | "pq";

/**
 * Internal resolved identifier used to pick bitcoinjs-lib params / HRP / coin
 * type. Not part of the primary public surface — prefer (Network, KeyType).
 * `xna-legacy` / `xna-legacy-test` are the legacy coin-type-0 networks kept for
 * backward compatibility and are unrelated to `KeyType: "legacy"`.
 */
export type NetworkType =
  | "xna"
  | "xna-test"
  | "xna-legacy"
  | "xna-legacy-test"
  | "xna-pq"
  | "xna-pq-test";

// ─── Sign result (after finalization) ────────────────────────────────────────

export interface ISignResult {
  /** Signed PSBT in base64 (legacy/ECDSA flow only; absent for the PQ flow). */
  signedPsbtBase64?: string;
  /** Finalized raw transaction hex, ready to broadcast */
  txHex: string;
  /** Transaction ID */
  txId: string;
  /** Number of inputs signed by the device */
  signedInputs: number;
}

// ─── sign_tx (PQ) device response ────────────────────────────────────────────

export interface ISignTxResponse {
  status: string;
  /** Fully-signed raw transaction hex, ready to broadcast. */
  tx: string;
  /** Transaction id (hex). */
  txid?: string;
  /** Number of inputs signed by the device. */
  signed_inputs: number;
}
