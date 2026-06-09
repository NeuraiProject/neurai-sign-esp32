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
import {
  DEFAULT_WITNESS_SCRIPT_HEX,
  pqAuthDescriptor,
  pqCommitment,
  publicKeyToAddress,
} from "./pq-address.js";
import { buildUnsignedPQTransaction, parseSignedPQTransaction } from "./pq-tx.js";
import type {
  DeviceResponse,
  IAddressResponse,
  IBip32PubkeyResponse,
  IDeviceInfo,
  IErrorResponse,
  INeuraiTransport,
  IPingResponse,
  IPQUTXO,
  ISerialOptions,
  ISigningDisplayMetadata,
  ISignMessageResponse,
  ISignPsbtResponse,
  ISignResult,
  ISignTxResponse,
  IUTXO,
  ITxOutput,
  KeyType,
  Network,
  NetworkType,
} from "./types.js";

export class NeuraiESP32 {
  private serial: INeuraiTransport;
  private deviceInfo: IDeviceInfo | null = null;

  /**
   * @param options Pass `{ transport }` to drive the device over a custom
   * transport (e.g. React Native / Android USB). Without it, the default Web
   * Serial transport is used and `baudRate`/`filters` configure it.
   */
  constructor(options?: ISerialOptions) {
    this.serial = options?.transport ?? new SerialConnection(options);
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

  /**
   * Detect the device without prompting the owner. `ping` (alias `device_info`)
   * answers immediately, requires NO on-device confirmation and returns nothing
   * that identifies the wallet (no fingerprint, address, pubkey or network) — so
   * it is safe to poll. Use this to enumerate/handshake a NeuraiHW device; use
   * {@link getInfo} (behind on-device approval) for the actual wallet data.
   *
   * Throws on firmware too old to know `ping` (it replies `Unknown action`);
   * callers that must support such firmware can catch and fall back to `getInfo`.
   */
  async ping(): Promise<IPingResponse> {
    // `ping` replies instantly (no user approval), so a short timeout is enough.
    const response = await this.serial.sendCommand({ action: "ping" }, 5000);

    this.assertSuccess(response);
    return response as IPingResponse;
  }

  /**
   * Read the device's wallet info (network, key_type, master fingerprint, address,
   * pubkey). As of the consent-model firmware this REQUIRES on-device approval and
   * the device waits up to 30 s for it, so the timeout must accommodate that wait —
   * do not use `getInfo` merely to detect the device; use {@link ping} for that.
   */
  async getInfo(): Promise<IDeviceInfo> {
    const response = await this.serial.sendCommand(
      { action: "info" },
      35000
    );

    this.assertSuccess(response);
    this.deviceInfo = response as IDeviceInfo;
    return this.deviceInfo;
  }

  /**
   * Retrieve the device's address (requires physical confirmation).
   *
   * The device exposes only the public key of its single address; this method
   * derives the corresponding Neurai address from that pubkey + the device mode
   * (legacy P2PKH or PQ AuthScript) and fills it in, so consumers always get a
   * ready-to-use `address`. See docs/pq-protocol-design.md §3.
   */
  async getAddress(): Promise<IAddressResponse> {
    const response = await this.serial.sendCommand(
      { action: "get_address" },
      35000
    );

    this.assertSuccess(response);
    const res = response as IAddressResponse;

    const keyType: KeyType =
      res.type ??
      (res.path?.startsWith("m_pq")
        ? "pq"
        : this.deviceInfo?.key_type ?? "legacy");
    const network = this.networkAxis(res.path);
    res.type = keyType;

    if (keyType === "pq") {
      const witnessScript = res.witnessScript ?? DEFAULT_WITNESS_SCRIPT_HEX;
      res.witnessScript = witnessScript;
      res.authType = res.authType ?? 1;
      res.commitment = pqCommitment(res.pubkey, witnessScript).toString("hex");
      res.authDescriptor = pqAuthDescriptor(res.pubkey).toString("hex");
      res.address =
        res.address ||
        publicKeyToAddress(res.pubkey, { network, keyType, witnessScript });
    } else {
      res.address =
        res.address || publicKeyToAddress(res.pubkey, { network, keyType });
    }

    return res;
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

  /**
   * Unified signing entry point. Routes by the device key type (legacy ECDSA
   * via PSBT/`sign_psbt`, or PQ ML-DSA via a raw transaction/`sign_tx`).
   * `keyType` can be forced; otherwise it is taken from `info().key_type`.
   * See docs/pq-protocol-design.md.
   */
  async signTransaction(options: {
    network?: NetworkType;
    keyType?: KeyType;
    utxos: (IUTXO | IPQUTXO)[];
    outputs: ITxOutput[];
    changeAddress?: string;
    pubkey?: string;
    masterFingerprint?: string;
    derivationPath?: string;
    feeRate?: number;
    display?: ISigningDisplayMetadata;
  }): Promise<ISignResult> {
    const keyType = options.keyType ?? this.deviceInfo?.key_type ?? "legacy";

    if (keyType === "pq") {
      return this.signPqTransaction({
        utxos: options.utxos as IPQUTXO[],
        outputs: options.outputs,
        changeAddress: options.changeAddress,
        feeRate: options.feeRate,
        display: options.display,
      });
    }

    const info = this.deviceInfo;

    const network =
      options.network ?? this.inferNetworkType(info);
    const pubkey =
      options.pubkey ?? info?.pubkey;
    const masterFingerprint =
      options.masterFingerprint ?? info?.master_fingerprint;
    const derivationPath =
      options.derivationPath ?? info?.path;
    const changeAddress = options.changeAddress ?? info?.address;

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
    if (!changeAddress) {
      throw new Error(
        "changeAddress required. Call getInfo()/getAddress() first or provide it explicitly."
      );
    }

    const psbtBase64 = buildPSBT({
      network,
      utxos: options.utxos as IUTXO[],
      outputs: options.outputs,
      changeAddress,
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

  /**
   * Sign a transaction that spends from the device's PQ (AuthScript) address.
   *
   * Builds an unsigned raw transaction (PSBT cannot carry ML-DSA-44 / witness v1
   * AuthScript), sends it with per-input metadata via the `sign_tx` action, and
   * returns the fully-signed transaction the device produces. The timeout window
   * resets on each `processing` heartbeat (ML-DSA signing is slow).
   * Change defaults to the device's own single address.
   */
  async signPqTransaction(options: {
    utxos: IPQUTXO[];
    outputs: ITxOutput[];
    changeAddress?: string;
    feeRate?: number;
    display?: ISigningDisplayMetadata;
  }): Promise<ISignResult> {
    const changeAddress = options.changeAddress ?? this.deviceInfo?.address;
    if (!changeAddress) {
      throw new Error(
        "changeAddress required. Call getAddress() first or provide it explicitly."
      );
    }

    const { rawTxHex, inputs } = buildUnsignedPQTransaction({
      utxos: options.utxos,
      outputs: options.outputs,
      changeAddress,
      feeRate: options.feeRate,
    });

    return this.signPqRawTransaction({
      txHex: rawTxHex,
      inputs,
      display: options.display,
    });
  }

  /**
   * Sign an already-built unsigned raw transaction via the `sign_tx` action.
   * Use this when the host has its own transaction builder (e.g. the wallet
   * already created the exact tx the user reviewed) and only needs the device's
   * PQ signatures. `inputs` carries per-input metadata: the input index, the
   * prevout `amount` (0 for asset-wrapped inputs) and optionally the prevout
   * `script_pub_key` for verification.
   */
  async signPqRawTransaction(options: {
    txHex: string;
    inputs: { index: number; amount: number; script_pub_key?: string }[];
    display?: ISigningDisplayMetadata;
  }): Promise<ISignResult> {
    const response = await this.serial.sendCommandHeartbeat(
      {
        action: "sign_tx",
        tx: options.txHex,
        inputs: options.inputs,
        ...(options.display ? { display: options.display } : {}),
      },
      30000,
      600000
    );

    this.assertSuccess(response);
    const signed = response as ISignTxResponse;

    if (!signed.tx) {
      throw new Error("Device did not return a signed transaction");
    }

    const { txHex, txId } = parseSignedPQTransaction(signed.tx);

    return {
      txHex,
      txId,
      signedInputs: signed.signed_inputs,
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
    const derivationPath = (info.path ?? "").trim();
    if (name.includes("legacy") && name.includes("test")) return "xna-legacy-test";
    if (name.includes("legacy")) return "xna-legacy";
    if (name.includes("test")) return "xna-test";
    if (info.coin_type === 1 || derivationPath.includes("/1'/")) return "xna-test";
    return "xna";
  }

  /**
   * Resolve the public `Network` axis (mainnet/testnet), preferring the device
   * info when present and otherwise inferring from a derivation path
   * (testnet coin type is 1, e.g. ".../1'/...").
   */
  private networkAxis(path?: string): Network {
    const info = this.deviceInfo;
    if (info?.network) {
      return info.network.toLowerCase().includes("test") ? "testnet" : "mainnet";
    }
    if (path && /\/1'\//.test(path)) return "testnet";
    return "mainnet";
  }
}
