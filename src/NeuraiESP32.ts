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
  ISigningDisplayMetadata,
  ISignMessageResponse,
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

  static isSupported(): boolean {
    return SerialConnection.isSupported();
  }

  get connected(): boolean {
    return this.serial.connected;
  }

  get info(): IDeviceInfo | null {
    return this.deviceInfo;
  }

  async connect(): Promise<void> {
    await this.serial.open();
  }

  async disconnect(): Promise<void> {
    this.deviceInfo = null;
    await this.serial.close();
  }

  async getInfo(): Promise<IDeviceInfo> {
    const response = await this.serial.sendCommand(
      { action: "info" },
      5000
    );

    this.assertSuccess(response);
    this.deviceInfo = response as IDeviceInfo;
    return this.deviceInfo;
  }

  async getAddress(): Promise<IAddressResponse> {
    const response = await this.serial.sendCommand(
      { action: "get_address" },
      35000
    );

    this.assertSuccess(response);
    return response as IAddressResponse;
  }

  async getBip32Pubkey(): Promise<IBip32PubkeyResponse> {
    const response = await this.serial.sendCommand(
      { action: "get_bip32_pubkey" },
      35000
    );

    this.assertSuccess(response);
    return response as IBip32PubkeyResponse;
  }

  async signMessage(message: string): Promise<ISignMessageResponse> {
    const response = await this.serial.sendCommand(
      { action: "sign_message", message },
      35000
    );

    this.assertSuccess(response);
    return response as ISignMessageResponse;
  }

  async signPsbt(
    psbtBase64: string,
    display?: ISigningDisplayMetadata
  ): Promise<ISignPsbtResponse> {
    const response = await this.serial.sendCommandFinal(
      {
        action: "sign_psbt",
        psbt: psbtBase64,
        ...(display ? { display } : {}),
      },
      120000
    );

    this.assertSuccess(response);
    return response as ISignPsbtResponse;
  }

  async signTransaction(options: {
    network?: NetworkType;
    utxos: IUTXO[];
    outputs: ITxOutput[];
    changeAddress: string;
    pubkey?: string;
    masterFingerprint?: string;
    derivationPath?: string;
    feeRate?: number;
    display?: ISigningDisplayMetadata;
  }): Promise<ISignResult> {
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

    const signResponse = await this.signPsbt(psbtBase64, options.display);

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

  private assertSuccess(response: DeviceResponse): void {
    if (response.status === "error") {
      throw new Error(
        `Device error: ${(response as IErrorResponse).message}`
      );
    }
  }

  private inferNetworkType(info: IDeviceInfo | null): NetworkType {
    if (!info) {
      return "xna";
    }

    const name = (info.network ?? "").toLowerCase();
    if (name.includes("legacy") && name.includes("test")) return "xna-legacy-test";
    if (name.includes("legacy")) return "xna-legacy";
    if (name.includes("test")) return "xna-test";
    return "xna";
  }
}
