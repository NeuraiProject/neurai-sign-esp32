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
  pubkey: string;
  masterFingerprint: string;
  derivationPath: string;
}

export interface IBuildPSBTFromRawOptions {
  network: NetworkType;
  rawUnsignedTransaction: string;
  inputs: IPSBTInputMetadata[];
}

// ─── Device responses ────────────────────────────────────────────────────────

export interface IDeviceInfo {
  status: string;
  device: string;
  version: string;
  chip: string;
  network: string;
  coin_type: number;
  master_fingerprint: string;
  path: string;
  address: string;
  pubkey: string;
}

export interface IAddressResponse {
  status: string;
  address: string;
  pubkey: string;
  path: string;
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

export type NetworkType = "xna" | "xna-test" | "xna-legacy" | "xna-legacy-test";

// ─── Sign result (after finalization) ────────────────────────────────────────

export interface ISignResult {
  /** Signed PSBT in base64 */
  signedPsbtBase64: string;
  /** Finalized raw transaction hex, ready to broadcast */
  txHex: string;
  /** Transaction ID */
  txId: string;
  /** Number of inputs signed by the device */
  signedInputs: number;
}
