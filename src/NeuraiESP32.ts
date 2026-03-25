/**
 * NeuraiESP32 — Main class for interacting with a NeuraiHW hardware wallet.
 *
 * Orchestrates:
 * - USB Serial connection via Web Serial API
 * - Device info, address, and BIP32 pubkey retrieval
 * - PSBT creation, signing, and finalization
 *
 * Usage:
 * ```ts
 * const device = new NeuraiESP32();
 * await device.connect();
 * const info = await device.getInfo();
 * const { address, pubkey } = await device.getAddress();
 * const result = await device.signTransaction({ utxos, outputs, changeAddress: address });
 * console.log(result.txHex); // ready to broadcast
 * await device.disconnect();
 * ```
 */

import { SerialConnection } from "./serial.js";
import { buildPSBT, finalizeSignedPSBT } from "./psbt.js";
import type {
  DeviceResponse,
  IAddressResponse,
  IBip32PubkeyResponse,
  IDeviceInfo,
  IErrorResponse,
  ISerialOptions,
  ISignPsbtResponse,
  ISignResult,
  IUTXO,
  ITxOutput,
  NetworkType,
} from "./types.js";

export class NeuraiESP32 {
  private serial: SerialConnection;
  private deviceInfo: IDeviceInfo | null = null;

  constructor(options?: ISerialOptions) {
    this.serial = new SerialConnection(options);
  }

  /**
   * Check if Web Serial API is supported in this browser.
   */
  static isSupported(): boolean {
    return SerialConnection.isSupported();
  }

  /**
   * Whether the device is currently connected.
   */
  get connected(): boolean {
    return this.serial.connected;
  }

  /**
   * Cached device info from the last getInfo() call.
   */
  get info(): IDeviceInfo | null {
    return this.deviceInfo;
  }

  // ─── Connection ─────────────────────────────────────────────────────────

  /**
   * Connect to the ESP32 hardware wallet.
   * Opens the browser port selection dialog.
   */
  async connect(): Promise<void> {
    await this.serial.open();
  }

  /**
   * Disconnect from the device.
   */
  async disconnect(): Promise<void> {
    this.deviceInfo = null;
    await this.serial.close();
  }

  // ─── Device commands ────────────────────────────────────────────────────

  /**
   * Get device information (no user confirmation needed).
   * Returns device name, version, network, address, pubkey, etc.
   */
  async getInfo(): Promise<IDeviceInfo> {
    const response = await this.serial.sendCommand(
      { action: "info" },
      5000
    );

    this.assertSuccess(response);
    this.deviceInfo = response as IDeviceInfo;
    return this.deviceInfo;
  }

  /**
   * Request the device address and public key.
   * Requires user physical confirmation on the device (30s timeout).
   */
  async getAddress(): Promise<IAddressResponse> {
    const response = await this.serial.sendCommand(
      { action: "get_address" },
      35000
    );

    this.assertSuccess(response);
    return response as IAddressResponse;
  }

  /**
   * Request the BIP32 account extended public key (xpub).
   * Requires user physical confirmation on the device (30s timeout).
   */
  async getBip32Pubkey(): Promise<IBip32PubkeyResponse> {
    const response = await this.serial.sendCommand(
      { action: "get_bip32_pubkey" },
      35000
    );

    this.assertSuccess(response);
    return response as IBip32PubkeyResponse;
  }

  /**
   * Send a raw PSBT (base64) to the device for signing.
   * Requires user physical confirmation on the device (60s timeout).
   *
   * Use this if you build the PSBT yourself.
   */
  async signPsbt(psbtBase64: string): Promise<ISignPsbtResponse> {
    const response = await this.serial.sendCommandFinal(
      { action: "sign_psbt", psbt: psbtBase64 },
      65000
    );

    this.assertSuccess(response);
    return response as ISignPsbtResponse;
  }

  // ─── High-level transaction flow ────────────────────────────────────────

  /**
   * Build, sign, and finalize a transaction in one call.
   *
   * This is the main method for sending XNA. It:
   * 1. Builds an unsigned PSBT from the provided UTXOs and outputs
   * 2. Sends it to the ESP32 for signing (user confirms on device)
   * 3. Finalizes the signed PSBT and extracts the raw transaction
   *
   * @param options.network - Network type (default: uses device info)
   * @param options.utxos - UTXOs to spend (must include rawTxHex)
   * @param options.outputs - Destination outputs [{address, value}]
   * @param options.changeAddress - Address for change (typically device address)
   * @param options.pubkey - Compressed public key hex (from getAddress)
   * @param options.masterFingerprint - From getInfo().master_fingerprint
   * @param options.derivationPath - From getAddress().path
   * @param options.feeRate - Fee rate in sat/byte (default: 1024)
   * @returns ISignResult with txHex ready to broadcast
   */
  async signTransaction(options: {
    network?: NetworkType;
    utxos: IUTXO[];
    outputs: ITxOutput[];
    changeAddress: string;
    pubkey?: string;
    masterFingerprint?: string;
    derivationPath?: string;
    feeRate?: number;
  }): Promise<ISignResult> {
    // Use cached device info if available for defaults
    const info = this.deviceInfo;

    const network =
      options.network ?? this.inferNetworkType(info);
    const pubkey =
      options.pubkey ?? info?.pubkey;
    const masterFingerprint =
      options.masterFingerprint ?? info?.master_fingerprint;
    const derivationPath =
      options.derivationPath ?? info?.path;

    if (!pubkey) {
      throw new Error(
        "pubkey required. Call getInfo() first or provide it explicitly."
      );
    }
    if (!masterFingerprint) {
      throw new Error(
        "masterFingerprint required. Call getInfo() first or provide it explicitly."
      );
    }
    if (!derivationPath) {
      throw new Error(
        "derivationPath required. Call getInfo() first or provide it explicitly."
      );
    }

    // 1. Build unsigned PSBT
    const psbtBase64 = buildPSBT({
      network,
      utxos: options.utxos,
      outputs: options.outputs,
      changeAddress: options.changeAddress,
      pubkey,
      masterFingerprint,
      derivationPath,
      feeRate: options.feeRate,
    });

    // 2. Send to ESP32 for signing
    const signResponse = await this.signPsbt(psbtBase64);

    // 3. Finalize and extract raw transaction
    const { txHex, txId } = finalizeSignedPSBT(
      psbtBase64,
      signResponse.psbt,
      network
    );

    return {
      signedPsbtBase64: signResponse.psbt,
      txHex,
      txId,
      signedInputs: signResponse.signed_inputs,
    };
  }

  // ─── Private helpers ────────────────────────────────────────────────────

  private assertSuccess(response: DeviceResponse): void {
    if (response.status === "error") {
      throw new Error(
        `Device error: ${(response as IErrorResponse).message}`
      );
    }
  }

  /**
   * Infer the NetworkType from cached device info.
   */
  private inferNetworkType(info: IDeviceInfo | null): NetworkType {
    if (!info) {
      return "xna"; // default
    }

    const networkName = info.network?.toLowerCase() ?? "";
    const coinType = info.coin_type;

    if (networkName.includes("test")) {
      return coinType === 1900 ? "xna-test" : "xna-legacy-test";
    }
    if (networkName.includes("legacy") || coinType === 0) {
      return "xna-legacy";
    }
    return "xna";
  }
}
