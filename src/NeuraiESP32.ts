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
import { Buffer } from "buffer";
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
  DeviceState,
  IAddressResponse,
  IBip32PubkeyResponse,
  IDepinDecryptResponse,
  IDepinIdentityResponse,
  IDepinSessionResponse,
  IDepinSessionStatusResponse,
  IDepinSignDigestResponse,
  IDepinSignResponse,
  IDeviceInfo,
  IErrorResponse,
  INeuraiTransport,
  IPingResponse,
  IPQUTXO,
  ISerialOptions,
  ISetupSeedOptions,
  ISetupSeedResponse,
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
  private pingInfo: IPingResponse | null = null;
  private depinCapabilityHandshake: Promise<IPingResponse | null> | null = null;
  // Per-session capability key (proto v2): cached from depinSessionBegin and
  // auto-attached to every session-scoped command so callers don't thread it.
  // Persist it across process restarts with get/setDepinSessionKey (store it in
  // the OS keystore, never plain prefs or logs).
  private depinSessionKey: string | null = null;

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
    this.pingInfo = null;
    this.depinCapabilityHandshake = null;
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
    this.pingInfo = response as IPingResponse;
    return this.pingInfo;
  }

  /**
   * Coarse device state, derived from `ping` and the firmware's gate errors:
   * `ready` (keys derived, normal commands work), `locked` (encrypted seed
   * stored, PIN not entered yet — ask the user to unlock on the device) or
   * `unconfigured` (no seed stored — {@link setupSeed} or the on-device wizard
   * applies). Safe to poll; never prompts on the device.
   *
   * Firmware predating the security layer answers `ping` successfully in every
   * state, so it reports `ready`.
   */
  async getDeviceState(): Promise<DeviceState> {
    const response = await this.serial.sendCommand({ action: "ping" }, 5000);
    if (response.status !== "error") {
      return "ready";
    }
    const message = ((response as IErrorResponse).message ?? "").toLowerCase();
    if (message.includes("locked")) return "locked";
    if (message.includes("not configured")) return "unconfigured";
    throw new Error(`Device error: ${(response as IErrorResponse).message}`);
  }

  /**
   * Provision an UNCONFIGURED device with a host-held mnemonic (`setup_seed`).
   *
   * The firmware only accepts this while **no encrypted seed is stored** (first
   * boot, dev-fallback mode, or after a wipe + reboot); on a configured device
   * it errors without prompting. The owner must physically approve a summary on
   * the device (word count + network + key type — the words are NEVER shown)
   * within 60 s, and then creates the PIN **on the device**: the PIN never
   * travels over USB. The seed transits the host and the USB link in plaintext
   * by design (this host generated it) — on-device entry remains the more
   * private path.
   *
   * Resolves with `{ state: "pin_required" }` once the owner approves. The
   * protocol has no push events, so detect completion by polling — see
   * {@link waitUntilReady}. If the owner cancels the PIN entry afterwards, the
   * device stays unconfigured and `setupSeed` can simply be called again.
   */
  async setupSeed(options: ISetupSeedOptions): Promise<ISetupSeedResponse> {
    // Client-side pre-checks for fast feedback; the device re-validates
    // everything (including the BIP39 checksum) authoritatively.
    const words = options.mnemonic.trim().split(/\s+/).filter(Boolean);
    if (words.length !== 12 && words.length !== 24) {
      throw new Error("Mnemonic must be 12 or 24 words");
    }
    if (options.keyType === "pq" && options.network !== "testnet") {
      throw new Error("PQ key type requires testnet");
    }

    // 60 s on-device approval window + margin.
    const response = await this.serial.sendCommand(
      {
        action: "setup_seed",
        mnemonic: words.join(" "),
        network: options.network,
        key_type: options.keyType,
      },
      70000
    );

    this.assertSuccess(response);
    return response as ISetupSeedResponse;
  }

  /**
   * Poll {@link getDeviceState} until the device reports `ready` — i.e. the
   * owner finished creating the PIN after {@link setupSeed} (or unlocked the
   * device) and the keys are derived. Resolves with the final state; throws on
   * timeout.
   */
  async waitUntilReady(options?: {
    /** Polling interval in ms (default 2000). */
    pollMs?: number;
    /** Give up after this long (default 300000 = 5 min). */
    timeoutMs?: number;
  }): Promise<DeviceState> {
    const pollMs = options?.pollMs ?? 2000;
    const timeoutMs = options?.timeoutMs ?? 300000;
    const start = Date.now();

    for (;;) {
      const state = await this.getDeviceState();
      if (state === "ready") return state;
      if (Date.now() - start > timeoutMs) {
        throw new Error(`Timed out waiting for device (last state: ${state})`);
      }
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
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

  // ─── DePIN chat identity (hw-depin-protocol) ───────────────────────────────
  // The device holds a dedicated DePIN chat identity (BIP44 account 100') so a
  // wallet can chat over DePIN without ever exposing its mnemonic. All calls
  // below require the device unlocked (PIN entered on-device) and, except the
  // session opener, an active session. Feature-detect with `ping().capabilities`
  // ("depin_identity" for identity+session, "depin_message" for sign/decrypt).

  /**
   * Open a DePIN chat session on a channel token. Prompts the owner for ONE
   * physical approval; while active the device reveals its DePIN identity and
   * auto-signs/decrypts on that channel without a per-message prompt, bounded by
   * an idle timeout, a hard cap, and a per-minute rate limit. The session is
   * revoked on timeout, device lock, or USB disconnect.
   *
   * @param token Channel token (soulbound `&…` asset name) to scope the session.
   * @param options `ttlMinutes` idle window (1–60, default 15); `ratePerMin`
   *   in-session sign/decrypt cap (default 100).
   */
  async depinSessionBegin(
    token: string,
    options?: { ttlMinutes?: number; ratePerMin?: number }
  ): Promise<IDepinSessionResponse> {
    const command: Record<string, unknown> = {
      action: "depin_session_begin",
      token,
    };
    if (options?.ttlMinutes !== undefined) command.ttl_minutes = options.ttlMinutes;
    if (options?.ratePerMin !== undefined) command.rate_per_min = options.ratePerMin;

    // Waits on a physical approval (up to ~30 s), like getInfo/getAddress.
    const response = await this.serial.sendCommand(command, 35000);
    this.assertSuccess(response);
    const session = response as IDepinSessionResponse;
    // Cache the capability key (proto v2) so it rides subsequent ops; undefined
    // on proto-v1 firmware, which simply doesn't require it.
    this.depinSessionKey = session.session_key ?? null;
    return session;
  }

  /** The capability key cached from the last {@link depinSessionBegin} (or null). */
  getDepinSessionKey(): string | null {
    return this.depinSessionKey;
  }

  /**
   * Restore a capability key saved from a previous run (e.g. from the OS
   * keystore) so a fresh instance can resume a session without re-prompting.
   * Pair with {@link depinSessionStatus} to confirm it is still valid.
   */
  setDepinSessionKey(key: string | null): void {
    this.depinSessionKey = key;
  }

  /** Session-key field spread into session-scoped commands (empty on proto v1). */
  private depinSessionFields(): Record<string, unknown> {
    return this.depinSessionKey ? { session_key: this.depinSessionKey } : {};
  }

  /**
   * Read the device's DePIN chat identity (address + compressed pubkey + BIP44
   * path). Requires an active session; no per-call prompt. This is the fix for
   * the hardware-wallet DePIN spinner: instead of deriving the identity from a
   * mnemonic the device doesn't expose, the wallet obtains it from the device.
   */
  async getDepinIdentity(): Promise<IDepinIdentityResponse> {
    const response = await this.serial.sendCommand(
      { action: "get_depin_identity", ...this.depinSessionFields() },
      10000
    );
    this.assertSuccess(response);
    return response as IDepinIdentityResponse;
  }

  /**
   * Sign a DePIN chat message on the device. The host performs the recipient
   * public-key ECIES encryption and passes the resulting fields; the device
   * assembles the canonical CDepinMessage preimage and returns the DER
   * signature. `sender` MUST equal the device's DePIN address and `token` the
   * active session channel (the device rejects otherwise). Requires an active
   * session and the `depin_message` capability.
   *
   * @param params.messageType 1 = direct (DATA), 2 = group (BROADCAST).
   * @param params.encryptedPayload Hex ECIES payload built host-side.
   */
  async depinSign(params: {
    token: string;
    sender: string;
    timestamp: number;
    messageType: number;
    encryptedPayload: string;
  }): Promise<IDepinSignResponse> {
    const response = await this.serial.sendCommand(
      {
        action: "depin_sign",
        token: params.token,
        sender: params.sender,
        timestamp: params.timestamp,
        message_type: params.messageType,
        encrypted_payload: params.encryptedPayload,
        ...this.depinSessionFields(),
      },
      35000
    );
    this.assertSuccess(response);
    return response as IDepinSignResponse;
  }

  /**
   * Decrypt a full serialized CDepinMessage addressed to this device, returning
   * the plaintext base64-encoded. GCM-authenticated; the sender's signature is
   * verified host-side (it needs the sender's on-chain pubkey). Returns a
   * `not_for_us` device error if this identity is not among the recipients.
   * Requires an active session and the `depin_message` capability.
   *
   * The library negotiates `depin_bulk_decrypt_b64` on first use. On firmware
   * that advertises it, valid hex input is sent as Base64 to avoid hex's 2x
   * expansion; older firmware continues to receive the legacy hex field.
   *
   * @param depinMessageHex Hex of the complete serialized CDepinMessage.
   */
  async depinDecrypt(depinMessageHex: string): Promise<IDepinDecryptResponse> {
    const response = await this.serial.sendCommand(
      {
        action: "depin_decrypt",
        ...(await this.depinDecryptWirePayload(
          "depin_message",
          "depin_message_b64",
          depinMessageHex
        )),
        ...this.depinSessionFields(),
      },
      35000
    );
    this.assertSuccess(response);
    return response as IDepinDecryptResponse;
  }

  /**
   * Decrypt a BARE ECIES payload — the `encrypted_payload_hex` a DePIN server
   * returns per message (and the format of privacy-wrapped `{ encrypted }`
   * server responses) — without the surrounding CDepinMessage framing. Use this
   * when you have the decomposed server item rather than a full serialized
   * message (the common case for a chat client). Returns the plaintext
   * base64-encoded, or a `not_for_us` device error if not a recipient.
   * Requires an active session and the `depin_message` capability.
   * On firmware supporting `depin_bulk_decrypt_b64`, valid hex input is sent
   * in Base64 and checked against `depin_max_decrypt_bytes` before USB I/O.
   */
  async depinDecryptPayload(encryptedPayloadHex: string): Promise<IDepinDecryptResponse> {
    const response = await this.serial.sendCommand(
      {
        action: "depin_decrypt_payload",
        ...(await this.depinDecryptWirePayload(
          "encrypted_payload",
          "encrypted_payload_b64",
          encryptedPayloadHex
        )),
        ...this.depinSessionFields(),
      },
      35000
    );
    this.assertSuccess(response);
    return response as IDepinDecryptResponse;
  }

  /**
   * Return the safest encoding the connected firmware has explicitly
   * advertised. The one-time, confirmation-free ping keeps the public DePIN
   * API backwards compatible: old firmware still gets its original hex field.
   */
  private async getDepinBulkCapability(): Promise<IPingResponse | null> {
    if (this.pingInfo) return this.pingInfo;
    if (!this.depinCapabilityHandshake) {
      this.depinCapabilityHandshake = this.ping().catch(() => null);
    }
    return this.depinCapabilityHandshake;
  }

  /**
   * Build the decrypt field for the negotiated firmware. Invalid hex is left
   * untouched so existing callers receive the firmware's normal validation
   * error instead of a new client-side parsing error.
   */
  private async depinDecryptWirePayload(
    hexField: string,
    base64Field: string,
    hexPayload: string
  ): Promise<Record<string, string>> {
    const capability = await this.getDepinBulkCapability();
    const maxBytes = capability?.depin_max_decrypt_bytes;
    const supportsBase64 =
      capability?.capabilities?.includes("depin_bulk_decrypt_b64") === true &&
      Number.isSafeInteger(maxBytes) &&
      (maxBytes as number) > 0;

    // Preserve the legacy firmware validation path for malformed hex.
    if (!/^[0-9a-fA-F]*$/.test(hexPayload) || hexPayload.length % 2 !== 0) {
      return { [hexField]: hexPayload };
    }

    const bytes = Buffer.from(hexPayload, "hex");
    if (supportsBase64) {
      if (bytes.length > (maxBytes as number)) {
        throw new RangeError(
          `DePIN decrypt payload is ${bytes.length} bytes; this device accepts at most ${maxBytes} bytes. Paginate the response before decrypting it.`
        );
      }
      return { [base64Field]: bytes.toString("base64") };
    }

    // A 48 KiB serial line leaves roughly 24 KiB for hex before JSON framing.
    // Do not send a known-unsafe legacy request that could destabilize a device.
    const legacyMaxBytes = 24 * 1024 - 256;
    if (bytes.length > legacyMaxBytes) {
      throw new RangeError(
        `DePIN decrypt payload is ${bytes.length} bytes and exceeds the ${legacyMaxBytes}-byte legacy hex transport limit. Update the firmware or paginate the response.`
      );
    }
    return { [hexField]: hexPayload };
  }

  /**
   * Sign a 32-byte digest with the DePIN key (account 100'). The device ALWAYS
   * asks for an explicit physical confirmation — this signature can move the
   * DePIN address's XNA. Used to spend from the DePIN address, notably the
   * pubkey-reveal burn that publishes the account-100 pubkey on-chain (so other
   * chat members can encrypt group messages to this identity). The host builds
   * the transaction, computes each input's legacy sighash, calls this per input,
   * and assembles the P2PKH scriptSig from `signature` (append the sighash-type
   * byte) + `pubkey`. Requires the device unlocked; not session-gated.
   *
   * @param digestHex 32-byte digest (the tx sighash), hex.
   */
  async depinSignDigest(digestHex: string): Promise<IDepinSignDigestResponse> {
    const response = await this.serial.sendCommand(
      { action: "depin_sign_digest", digest: digestHex },
      35000
    );
    this.assertSuccess(response);
    return response as IDepinSignDigestResponse;
  }

  /**
   * End the current DePIN session: auto-sign/decrypt stops and the identity is
   * no longer revealed until a new {@link depinSessionBegin} approval. Safe to
   * call with no active session. On proto-v2 firmware only the holder of the
   * capability key can end the session; this attaches the cached key, then
   * forgets it locally regardless of the outcome.
   */
  async depinSessionEnd(): Promise<void> {
    const response = await this.serial.sendCommand(
      { action: "depin_session_end", ...this.depinSessionFields() },
      10000
    );
    this.depinSessionKey = null;
    this.assertSuccess(response);
  }

  /**
   * Ask the device whether the cached (or {@link setDepinSessionKey}-restored)
   * capability key still names a live session — proto v2, gated by
   * `depin_session_key`. Lets a host that persisted its key skip re-prompting
   * the user after a restart while the device is still in DePIN mode. Without a
   * valid key the device replies `{ active: false }` and reveals nothing, so it
   * is not an information leak. Clears the cached key when the session is gone.
   */
  async depinSessionStatus(): Promise<IDepinSessionStatusResponse> {
    const response = await this.serial.sendCommand(
      { action: "depin_session_status", ...this.depinSessionFields() },
      10000
    );
    this.assertSuccess(response);
    const status = response as IDepinSessionStatusResponse;
    if (!status.active) this.depinSessionKey = null;
    return status;
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
