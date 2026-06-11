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

/**
 * Lightweight device handshake returned by `ping` / `device_info`. Safe to poll:
 * it requires NO on-device confirmation and returns nothing that identifies the
 * wallet (no fingerprint, address, pubkey or network). Use it to detect/enumerate
 * a NeuraiHW device; use {@link IDeviceInfo} (via `getInfo`, behind on-device
 * approval) for the actual wallet data.
 */
export interface IPingResponse {
  status: string;
  device: string;
  /** Protocol/app version (matches `info`'s `version`). */
  version: string;
  /** Firmware version (ping-only; not returned by `info`). */
  firmware_version: string;
  chip: string;
}

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

// ─── Host-initiated device provisioning (setup_seed) ─────────────────────────

/**
 * Options for {@link NeuraiESP32.setupSeed}: provision an UNCONFIGURED device
 * with a host-held mnemonic. The firmware only accepts the command while no
 * encrypted seed is stored; the owner must physically approve on the device
 * (a summary is shown — never the words) and then creates the PIN ON the
 * device. The PIN never travels over USB.
 */
export interface ISetupSeedOptions {
  /** 12 or 24 BIP39 words, space-separated. Validated again on-device. */
  mnemonic: string;
  /** Chain network. REQUIRED by the firmware (no defaults). */
  network: Network;
  /** Key scheme. REQUIRED by the firmware. `pq` is testnet-only. */
  keyType: KeyType;
}

/**
 * Successful `setup_seed` reply: the owner approved on the device and is now
 * creating the PIN there. Poll {@link NeuraiESP32.getDeviceState} (or use
 * {@link NeuraiESP32.waitUntilReady}) to detect completion — the protocol has
 * no push events.
 */
export interface ISetupSeedResponse {
  status: string;
  /** Always `"pin_required"`: the owner must finish the PIN on the device. */
  state: "pin_required";
}

/**
 * Coarse device state derived from the `ping` gate errors:
 * - `ready`        — keys derived; normal commands work.
 * - `locked`       — an encrypted seed is stored but the PIN has not been
 *                    entered yet (ask the user to unlock on the device).
 * - `unconfigured` — no seed stored; `setup_seed` (or the on-device wizard)
 *                    is the way forward.
 */
export type DeviceState = "ready" | "locked" | "unconfigured";

export interface IErrorResponse {
  status: "error";
  message: string;
}

export interface IProcessingResponse {
  status: "processing";
  stage: string;
}

export type DeviceResponse =
  | IPingResponse
  | IDeviceInfo
  | IAddressResponse
  | IBip32PubkeyResponse
  | ISignPsbtResponse
  | ISignTxResponse
  | ISignMessageResponse
  | ISetupSeedResponse
  | IErrorResponse
  | IProcessingResponse;

// ─── Transport abstraction ───────────────────────────────────────────────────

/**
 * Message-level transport consumed by {@link NeuraiESP32}. This is the only
 * surface the device class depends on, so any platform (Web Serial, React
 * Native USB, a test double…) can drive a NeuraiHW device by implementing it.
 *
 * The default implementation, `SerialConnection`, speaks the NeuraiHW JSON
 * protocol over the Web Serial API. `SerialProtocol` provides the same logic on
 * top of a byte-level {@link IByteChannel}, so most platforms only need to
 * implement the much smaller `IByteChannel`.
 */
export interface INeuraiTransport {
  /** True while the underlying connection is open and writable. */
  readonly connected: boolean;
  /** Open the connection (may prompt the user to pick a port/device). */
  open(): Promise<void>;
  /** Close the connection and release resources. */
  close(): Promise<void>;
  /** Send a command and resolve with the first response. */
  sendCommand(command: Record<string, unknown>, timeoutMs?: number): Promise<DeviceResponse>;
  /** Like {@link sendCommand}, but skips `processing` heartbeats until a final response. */
  sendCommandFinal(command: Record<string, unknown>, timeoutMs?: number): Promise<DeviceResponse>;
  /** Like {@link sendCommandFinal}, but resets the timeout window on every heartbeat. */
  sendCommandHeartbeat(
    command: Record<string, unknown>,
    perResponseTimeoutMs?: number,
    maxTotalMs?: number
  ): Promise<DeviceResponse>;
}

/**
 * Byte-level, platform-specific channel to the device. Implement this to add a
 * new transport (e.g. an Android USB-serial native module): everything above it
 * — the chunked-write firmware workaround, line buffering, JSON parsing, the
 * response queue and timeouts — is handled by {@link SerialProtocol} and shared
 * across platforms.
 *
 * Implementations MUST deliver inbound bytes verbatim to the handler registered
 * via {@link onData}; they MUST NOT assume message boundaries (the protocol
 * layer reassembles newline-terminated JSON lines itself).
 */
export interface IByteChannel {
  /** True while the channel is open. */
  readonly isOpen: boolean;
  /**
   * Register the handler that receives inbound byte chunks. Called once, before
   * {@link open}. Chunks may split or coalesce device messages arbitrarily.
   */
  onData(handler: (chunk: Uint8Array) => void): void;
  /** Open the channel (may prompt the user). */
  open(): Promise<void>;
  /** Write a chunk of bytes to the device. */
  write(data: Uint8Array): Promise<void>;
  /** Close the channel and release resources. */
  close(): Promise<void>;
}

// ─── Serial connection options ───────────────────────────────────────────────

export interface ISerialOptions {
  /** Baud rate (default: 115200) */
  baudRate?: number;
  /** USB vendor/product filters for port selection */
  filters?: SerialPortFilter[];
  /**
   * Pre-built transport to drive the device. When provided, it is used as-is
   * and `baudRate`/`filters` are ignored (those configure the default Web Serial
   * transport). Use this to run the library outside the browser — e.g. over an
   * Android USB-serial channel in React Native. See `IByteChannel` /
   * `SerialProtocol`.
   */
  transport?: INeuraiTransport;
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
