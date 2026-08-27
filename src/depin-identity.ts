/**
 * ESP32 → DePIN identity adapter (protocol 2).
 *
 * Turns a NeuraiHW device into an identity usable by
 * `@neuraiproject/neurai-depin-msg` >= 3.1.0 without the private key ever
 * leaving the chip. The interface is STRUCTURAL: this module has no runtime
 * dependency on depin-msg; it just returns an object with the shape those
 * flows consume (`address`, `publicKey`, `signMessage`, `signDigest`,
 * `openReply`).
 *
 * Two rules shape the whole design:
 *
 *  1. **Never `depinSignDigest`.** That command signs an arbitrary 32-byte
 *     hash — possibly a transaction sighash — so it is deliberately outside
 *     the session and always asks for a physical confirmation. Automating it
 *     would turn a messaging session into a universal signing capability.
 *     Authentication goes through `depin_sign_auth` (structured, the device
 *     rebuilds the preimage) and publishing through `depin_sign`.
 *  2. **A session authorises only what the owner approved.** Permissions are
 *     independent (`receive`, `publish`, `admin`); a read session cannot
 *     publish in the owner's name nor purge the pool. The adapter enforces the
 *     matrix locally *before* talking to the device, and the firmware enforces
 *     it authoritatively.
 *
 * The device returns DER signatures; the protocol needs recoverable 65-byte
 * ones for authentication, so this module normalises to low-s and derives the
 * recovery id by trying all four candidates against the pubkey the device
 * itself declared. Every signature is verified here before it is handed back.
 */

import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import ecc from "@bitcoinerlab/secp256k1";
import * as varuint from "varuint-bitcoin";
import type { NeuraiESP32 } from "./NeuraiESP32.js";
import { getNetwork } from "./networks.js";
import type {
  DepinSessionPermission,
  DepinSignAuthCommand,
  IDepinIdentityResponse,
  IDepinSessionStatusResponse,
} from "./types.js";

export type DepinAdapterNetwork = "mainnet" | "test";

/** Stable, machine-readable failures of the adapter. */
export type DepinDeviceIdentityErrorCode =
  | "UNSUPPORTED_PROTOCOL"
  | "MISSING_CAPABILITY"
  | "SESSION_REQUIRED"
  | "SESSION_DECLINED"
  | "SESSION_EXPIRED"
  | "SESSION_TOKEN_MISMATCH"
  | "SESSION_PERMISSION_MISMATCH"
  | "SESSION_PERMISSION_INSUFFICIENT"
  | "SESSION_TIME_BUDGET_INSUFFICIENT"
  | "IDENTITY_NETWORK_MISMATCH"
  | "IDENTITY_PATH_MISMATCH"
  | "IDENTITY_KEY_MISMATCH"
  | "SIGNING_CONTEXT_REQUIRED"
  | "INVALID_DEVICE_SIGNATURE"
  | "NOT_FOR_THIS_IDENTITY"
  | "DECRYPT_AUTH_FAILED"
  | "PAYLOAD_TOO_LARGE"
  | "DEVICE_DISCONNECTED";

export class DepinDeviceIdentityError extends Error {
  readonly code: DepinDeviceIdentityErrorCode;
  readonly cause?: unknown;

  constructor(code: DepinDeviceIdentityErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = "DepinDeviceIdentityError";
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

/** Structured contexts mirrored from depin-msg (no runtime dependency). */
export type DepinAuthSigningContext =
  | {
      kind: "request";
      type: "receive" | "admin";
      token: string;
      address: string;
      timestampMs: number;
    }
  | { kind: "get"; token: string; address: string; challenge: string }
  | { kind: "clear"; scope: string; address: string; challenge: string };

export interface DepinMessageSigningContext {
  kind: "message";
  token: string;
  senderAddress: string;
  timestamp: number;
  messageType: number;
  encryptedPayloadHex: string;
}

export interface IDepinIdentityAdapterOptions {
  /** Channel the session is opened for; checked by exact equality. */
  token: string;
  /** Network the application expects; a mismatch fails before signing. */
  expectedNetwork: DepinAdapterNetwork;
  /**
   * Permissions to request. Default `["receive"]` — never `admin` implicitly.
   * A chat client typically wants `["receive", "publish"]`; purging uses a
   * separate `["admin"]` session.
   */
  sessionPermissions?: DepinSessionPermission[];
  ttlMinutes?: number;
  ratePerMin?: number;
  /** Open a session automatically when none is active. Default true. */
  autoSession?: boolean;
}

export interface IDepinDeviceIdentity {
  readonly address: string;
  readonly publicKey: string;
  readonly network: DepinAdapterNetwork;
  readonly permissions: readonly DepinSessionPermission[];
  readonly maxDecryptBytes: number | null;
  signMessage(preimage: string, context?: DepinAuthSigningContext): Promise<string>;
  signDigest(digest: Uint8Array, context?: DepinMessageSigningContext): Promise<Uint8Array>;
  openReply(encryptedHex: string): Promise<Uint8Array>;
  session: {
    ensure(options?: { minRemainingSeconds?: number }): Promise<void>;
    status(): Promise<IDepinSessionStatusResponse>;
    end(): Promise<void>;
  };
}

const REQUIRED_CAPABILITIES = [
  "depin_identity",
  "depin_message",
  "depin_auth_sign",
  "depin_session_key",
  "depin_session_permissions",
] as const;

const PERMISSION_ORDER: DepinSessionPermission[] = ["receive", "publish", "admin"];

const NEURAI_MESSAGE_MAGIC = "Neurai Signed Message:\n";
const SECP256K1_ORDER = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);
const SECP256K1_HALF_ORDER = SECP256K1_ORDER / 2n;
const DEPIN_IDENTITY_PATHS: Readonly<Record<DepinAdapterNetwork, string>> = {
  mainnet: "m/44'/1900'/100'/0/0",
  test: "m/44'/1'/100'/0/0",
};

// ---------------------------------------------------------------------------
// Signed-message envelope and DER → recoverable conversion
// ---------------------------------------------------------------------------

function serializeVarString(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  // CompactSize must be canonical. Today's longest DePIN preimage is 233 bytes
  // (DEPIN-CLEAR with a 121-byte name) so a single byte suffices, but the
  // limit is not baked in: 253+ correctly switches to the 0xfd prefix.
  return Buffer.concat([Buffer.from(varuint.encode(bytes.length).buffer), bytes]);
}

/**
 * SHA256d(ser_string(magic) ‖ ser_string(message)) — the exact digest the
 * firmware must rebuild for DEPIN-REQ / DEPIN-GET / DEPIN-CLEAR.
 */
export function neuraiSignedMessageDigest(message: string): Buffer {
  return Buffer.from(
    bitcoin.crypto.hash256(
      Buffer.concat([serializeVarString(NEURAI_MESSAGE_MAGIC), serializeVarString(message)])
    )
  );
}

function derToCompactLowS(derHex: string): Buffer {
  if (
    typeof derHex !== "string" ||
    derHex.length === 0 ||
    derHex.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(derHex)
  ) {
    throw new DepinDeviceIdentityError(
      "INVALID_DEVICE_SIGNATURE",
      "The device returned a signature that is not canonical lowercase DER hex"
    );
  }
  let signature: Buffer;
  try {
    signature = Buffer.from(bitcoin.script.signature.decode(
      Buffer.concat([Buffer.from(derHex, "hex"), Buffer.from([0x01])])
    ).signature);
  } catch (error) {
    throw new DepinDeviceIdentityError(
      "INVALID_DEVICE_SIGNATURE",
      "The device returned a signature that is not canonical DER",
      error
    );
  }
  if (signature.length !== 64) {
    throw new DepinDeviceIdentityError(
      "INVALID_DEVICE_SIGNATURE",
      `Compact signature must be 64 bytes; got ${signature.length}`
    );
  }
  const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  if (s === 0n || s >= SECP256K1_ORDER) {
    throw new DepinDeviceIdentityError(
      "INVALID_DEVICE_SIGNATURE",
      "The device returned a signature with an invalid s scalar"
    );
  }
  if (s > SECP256K1_HALF_ORDER) {
    const normalized = Buffer.from((SECP256K1_ORDER - s).toString(16).padStart(64, "0"), "hex");
    normalized.copy(signature, 32);
  }
  return signature;
}

function compactToDer(compact: Buffer): Buffer {
  const encoded = Buffer.from(bitcoin.script.signature.encode(compact, 0x01));
  return encoded.subarray(0, encoded.length - 1);
}

function assertOperationCount(value: unknown): void {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new DepinDeviceIdentityError(
      "INVALID_DEVICE_SIGNATURE",
      "The device returned an invalid operation counter"
    );
  }
}

function decodeCanonicalBase64(value: string): Buffer {
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw new DepinDeviceIdentityError(
      "DECRYPT_AUTH_FAILED",
      "The device returned malformed Base64 plaintext"
    );
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    throw new DepinDeviceIdentityError(
      "DECRYPT_AUTH_FAILED",
      "The device returned non-canonical Base64 plaintext"
    );
  }
  return decoded;
}

/**
 * Derives the recoverable Base64 signature the protocol expects from the DER
 * the device returned, by trying every recovery id against the declared
 * pubkey. Fails closed when none matches — that means the device signed with
 * another key or another digest.
 */
export function derSignatureToRecoverable(
  derHex: string,
  digest: Buffer,
  expectedPubkeyHex: string
): string {
  const compact = derToCompactLowS(derHex);
  const expected = expectedPubkeyHex.toLowerCase();

  for (let recoveryId = 0; recoveryId < 4; recoveryId += 1) {
    let recovered: Uint8Array | null = null;
    try {
      recovered = ecc.recover(digest, compact, recoveryId as 0 | 1 | 2 | 3, true);
    } catch {
      continue;
    }
    if (recovered && Buffer.from(recovered).toString("hex") === expected) {
      const header = 27 + recoveryId + 4; // compressed key
      return Buffer.concat([Buffer.from([header]), compact]).toString("base64");
    }
  }

  throw new DepinDeviceIdentityError(
    "INVALID_DEVICE_SIGNATURE",
    "Could not recover the device's public key from its signature: it signed a different digest or with a different key"
  );
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

function canonicalizePermissions(
  permissions: readonly DepinSessionPermission[] | undefined,
  context: string
): DepinSessionPermission[] {
  const list = permissions ?? ["receive"];
  if (!Array.isArray(list) || list.length === 0) {
    throw new DepinDeviceIdentityError(
      "SESSION_PERMISSION_MISMATCH",
      `${context}: permissions must be a non-empty array`
    );
  }
  const seen = new Set<DepinSessionPermission>();
  for (const permission of list) {
    if (!PERMISSION_ORDER.includes(permission as DepinSessionPermission)) {
      throw new DepinDeviceIdentityError(
        "SESSION_PERMISSION_MISMATCH",
        `${context}: unknown permission ${JSON.stringify(permission)}`
      );
    }
    if (seen.has(permission as DepinSessionPermission)) {
      throw new DepinDeviceIdentityError(
        "SESSION_PERMISSION_MISMATCH",
        `${context}: duplicate permission ${permission}`
      );
    }
    seen.add(permission as DepinSessionPermission);
  }
  return PERMISSION_ORDER.filter((permission) => seen.has(permission));
}

function samePermissions(
  a: readonly DepinSessionPermission[],
  b: readonly DepinSessionPermission[]
): boolean {
  return a.length === b.length && a.every((permission, index) => permission === b[index]);
}

/** The normative matrix: which permission each device operation requires. */
function requiredPermission(
  command: DepinSignAuthCommand | { operation: "publish" }
): DepinSessionPermission {
  switch (command.operation) {
    case "request":
      return command.type === "admin" ? "admin" : "receive";
    case "get":
      return "receive";
    case "clear":
      return "admin";
    case "publish":
      return "publish";
  }
}

function authPreimageFor(command: DepinSignAuthCommand): string {
  switch (command.operation) {
    case "request":
      return `DEPIN-REQ|${command.type}|${command.token}|${command.address}|${command.timestamp_ms}`;
    case "get":
      return `DEPIN-GET|${command.token}|${command.address}|${command.challenge}`;
    case "clear":
      return `DEPIN-CLEAR|${command.scope}|${command.address}|${command.challenge}`;
  }
}

function messageDigestFor(context: DepinMessageSigningContext): Buffer {
  if (
    !Number.isSafeInteger(context.timestamp) ||
    context.timestamp < 0 ||
    !Number.isInteger(context.messageType) ||
    (context.messageType !== 0x01 && context.messageType !== 0x02) ||
    typeof context.encryptedPayloadHex !== "string" ||
    context.encryptedPayloadHex.length === 0 ||
    context.encryptedPayloadHex.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(context.encryptedPayloadHex)
  ) {
    throw new DepinDeviceIdentityError(
      "SIGNING_CONTEXT_REQUIRED",
      "The message signing context contains non-canonical fields"
    );
  }
  const timestamp = Buffer.alloc(8);
  timestamp.writeBigInt64LE(BigInt(context.timestamp));
  const payload = Buffer.from(context.encryptedPayloadHex, "hex");
  return Buffer.from(
    bitcoin.crypto.hash256(
      Buffer.concat([
        serializeVarString(context.token),
        serializeVarString(context.senderAddress),
        timestamp,
        Buffer.from([context.messageType]),
        Buffer.from(varuint.encode(payload.length).buffer),
        payload,
      ])
    )
  );
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/**
 * Builds a DePIN identity backed by the device. Opens (or reuses) a session
 * for `options.token` with the requested permissions, validates the announced
 * identity against `expectedNetwork`, and returns the capability callbacks.
 */
export async function createDepinDeviceIdentity(
  device: NeuraiESP32,
  options: IDepinIdentityAdapterOptions
): Promise<IDepinDeviceIdentity> {
  if (!options || typeof options.token !== "string" || options.token.length === 0) {
    throw new DepinDeviceIdentityError("SESSION_REQUIRED", "options.token is required");
  }
  if (options.expectedNetwork !== "mainnet" && options.expectedNetwork !== "test") {
    throw new DepinDeviceIdentityError(
      "IDENTITY_NETWORK_MISMATCH",
      "options.expectedNetwork must be 'mainnet' or 'test'"
    );
  }

  // Frozen copy: later decisions never read a caller-mutable array.
  const expectedPermissions = Object.freeze(
    canonicalizePermissions(options.sessionPermissions, "options.sessionPermissions")
  );
  const autoSession = options.autoSession !== false;

  let identity: IDepinIdentityResponse | null = null;
  let maxDecryptBytes: number | null = null;
  let ensureInFlight: Promise<void> | null = null;
  let requestedMinimumSeconds = 0;

  async function negotiate(): Promise<void> {
    const ping = await device.ping();
    if (ping.protocol_version !== 2) {
      throw new DepinDeviceIdentityError(
        "UNSUPPORTED_PROTOCOL",
        `This adapter requires DePIN protocol 2; the device announces ${JSON.stringify(ping.protocol_version)}`
      );
    }
    const capabilities = ping.capabilities ?? [];
    for (const capability of REQUIRED_CAPABILITIES) {
      if (!capabilities.includes(capability)) {
        throw new DepinDeviceIdentityError(
          "MISSING_CAPABILITY",
          `Firmware does not advertise the ${capability} capability; refusing to downgrade`
        );
      }
    }
    const limit = (ping as { depin_max_decrypt_bytes?: number }).depin_max_decrypt_bytes;
    maxDecryptBytes = Number.isSafeInteger(limit) && (limit as number) > 0 ? (limit as number) : null;
  }

  async function validateIdentity(): Promise<IDepinIdentityResponse> {
    const announced = await device.getDepinIdentity();
    if (announced.protocol_version !== 2) {
      throw new DepinDeviceIdentityError(
        "UNSUPPORTED_PROTOCOL",
        `The DePIN identity announces protocol ${JSON.stringify(announced.protocol_version)}, expected 2`
      );
    }
    let network: DepinAdapterNetwork;
    if (announced.network === "xna") {
      network = "mainnet";
    } else if (announced.network === "xna-test") {
      network = "test";
    } else {
      throw new DepinDeviceIdentityError(
        "IDENTITY_NETWORK_MISMATCH",
        `Device identity announced an unknown network ${JSON.stringify(announced.network)}`
      );
    }
    if (network !== options.expectedNetwork) {
      throw new DepinDeviceIdentityError(
        "IDENTITY_NETWORK_MISMATCH",
        `Device identity is on ${network}, the application expects ${options.expectedNetwork}`
      );
    }
    const expectedPath = DEPIN_IDENTITY_PATHS[options.expectedNetwork];
    if (announced.path !== expectedPath) {
      throw new DepinDeviceIdentityError(
        "IDENTITY_PATH_MISMATCH",
        `Device identity uses ${JSON.stringify(announced.path)}, expected ${expectedPath}`
      );
    }
    if (typeof announced.pubkey !== "string" || announced.pubkey.length !== 66) {
      throw new DepinDeviceIdentityError(
        "IDENTITY_KEY_MISMATCH",
        "Device DePIN pubkey must be a 33-byte compressed SEC1 key"
      );
    }
    const pubkey = Buffer.from(announced.pubkey, "hex");
    if (!ecc.isPoint(pubkey) || !ecc.isPointCompressed(pubkey)) {
      throw new DepinDeviceIdentityError(
        "IDENTITY_KEY_MISMATCH",
        "Device DePIN pubkey is not a valid compressed secp256k1 point"
      );
    }
    // The address must be the P2PKH of that key on the expected network.
    const derived = bitcoin.payments.p2pkh({
      pubkey,
      network: getNetwork(options.expectedNetwork === "mainnet" ? "xna" : "xna-test"),
    }).address;
    if (derived !== announced.address) {
      throw new DepinDeviceIdentityError(
        "IDENTITY_KEY_MISMATCH",
        "Device DePIN address does not match its announced public key"
      );
    }
    return announced;
  }

  function assertSessionUsable(status: IDepinSessionStatusResponse): DepinSessionPermission[] {
    if (!status.active) {
      throw new DepinDeviceIdentityError("SESSION_EXPIRED", "The DePIN session is no longer active");
    }
    if (status.token !== options.token) {
      throw new DepinDeviceIdentityError(
        "SESSION_TOKEN_MISMATCH",
        `The active session is bound to ${JSON.stringify(status.token)}, not ${JSON.stringify(options.token)}`
      );
    }
    if (!Array.isArray(status.permissions)) {
      throw new DepinDeviceIdentityError(
        "SESSION_PERMISSION_MISMATCH",
        "Firmware advertises depin_session_permissions but the status omits them"
      );
    }
    if (!Number.isSafeInteger(status.expires_in_s) || status.expires_in_s < 0) {
      throw new DepinDeviceIdentityError(
        "SESSION_EXPIRED",
        "An active DePIN session must report a non-negative integer expires_in_s"
      );
    }
    return canonicalizePermissions(status.permissions, "session status");
  }

  async function closeSession(): Promise<void> {
    // Identity data is session-bound and must not remain usable once revocation
    // starts, even if the device cannot confirm the close. The capability key
    // itself is retained by NeuraiESP32 on failure so revocation can be retried.
    identity = null;
    await device.depinSessionEnd();
  }

  async function rejectOpenedSession(error: unknown): Promise<never> {
    identity = null;
    if (device.getDepinSessionKey()) {
      try {
        await device.depinSessionEnd();
      } catch (closeError) {
        throw new DepinDeviceIdentityError(
          "DEVICE_DISCONNECTED",
          "The new DePIN session was invalid and could not be revoked; its capability key was retained",
          { validationError: error, closeError }
        );
      }
    }
    throw error;
  }

  async function ensureOnce(minRemaining: number): Promise<void> {
    await negotiate();

    let needsNewSession = true;
    if (device.getDepinSessionKey()) {
      let status: IDepinSessionStatusResponse;
      try {
        status = await device.depinSessionStatus();
      } catch (error) {
        identity = null;
        throw new DepinDeviceIdentityError(
          "DEVICE_DISCONNECTED",
          "Could not read the DePIN session status from the device",
          error
        );
      }

      if (status.active) {
        const granted = assertSessionUsableSafely(status);
        const budgetOk =
          typeof status.expires_in_s === "number" && status.expires_in_s >= minRemaining;

        if (granted && samePermissions(granted, expectedPermissions) && budgetOk) {
          needsNewSession = false;
        } else {
          if (!autoSession) {
            if (!granted || !samePermissions(granted, expectedPermissions)) {
              assertSessionUsable(status);
            }
            throw new DepinDeviceIdentityError(
              "SESSION_TIME_BUDGET_INSUFFICIENT",
              `The active session has ${status.expires_in_s}s left, below the ${minRemaining}s budget`
            );
          }
          await closeSession();
        }
      } else {
        identity = null;
      }
    }

    if (!needsNewSession) {
      if (!identity) {
        try {
          identity = await validateIdentity();
        } catch (error) {
          if (autoSession) await rejectOpenedSession(error);
          throw error;
        }
      }
      return;
    }

    if (!autoSession) {
      throw new DepinDeviceIdentityError(
        "SESSION_REQUIRED",
        "No active DePIN session and autoSession is disabled; open one explicitly"
      );
    }

    let opened;
    try {
      opened = await device.depinSessionBegin(options.token, {
        ttlMinutes: options.ttlMinutes,
        ratePerMin: options.ratePerMin,
        // Intentionally pending the coordinated firmware change: current
        // NeuraiESP32 versions do not serialize this field yet.
        permissions: expectedPermissions as unknown as DepinSessionPermission[],
      } as never);
    } catch (error) {
      throw new DepinDeviceIdentityError(
        "SESSION_DECLINED",
        "The device did not approve the DePIN session",
        error
      );
    }

    try {
      if (opened.token !== options.token) {
        throw new DepinDeviceIdentityError(
          "SESSION_TOKEN_MISMATCH",
          "The device opened a session for a different token"
        );
      }
      if (!device.getDepinSessionKey()) {
        throw new DepinDeviceIdentityError(
          "MISSING_CAPABILITY",
          "The device did not return a session capability key"
        );
      }

      const status = await device.depinSessionStatus();
      const granted = assertSessionUsable(status);
      if (!samePermissions(granted, expectedPermissions)) {
        throw new DepinDeviceIdentityError(
          "SESSION_PERMISSION_MISMATCH",
          `Requested [${expectedPermissions.join(", ")}] but the device granted [${granted.join(", ")}]`
        );
      }
      if ((status.expires_in_s as number) < minRemaining) {
        throw new DepinDeviceIdentityError(
          "SESSION_TIME_BUDGET_INSUFFICIENT",
          `A new session only offers ${status.expires_in_s}s, below the ${minRemaining}s budget; raise ttlMinutes or lower the budget`
        );
      }

      identity = await validateIdentity();
    } catch (error) {
      await rejectOpenedSession(error);
    }
  }

  async function ensure(ensureOptions?: { minRemainingSeconds?: number }): Promise<void> {
    const minRemaining = ensureOptions?.minRemainingSeconds ?? 0;
    if (
      (!Number.isInteger(minRemaining) || minRemaining < 0)
    ) {
      throw new DepinDeviceIdentityError(
        "SESSION_TIME_BUDGET_INSUFFICIENT",
        "minRemainingSeconds must be a non-negative integer"
      );
    }

    requestedMinimumSeconds = Math.max(requestedMinimumSeconds, minRemaining);
    if (!ensureInFlight) {
      ensureInFlight = (async () => {
        let satisfiedMinimum = -1;
        try {
          while (satisfiedMinimum < requestedMinimumSeconds) {
            const target = requestedMinimumSeconds;
            await ensureOnce(target);
            satisfiedMinimum = target;
          }
        } finally {
          ensureInFlight = null;
          requestedMinimumSeconds = 0;
        }
      })();
    }
    await ensureInFlight;
  }

  /** Same checks as assertSessionUsable but returns null instead of throwing. */
  function assertSessionUsableSafely(
    status: IDepinSessionStatusResponse
  ): DepinSessionPermission[] | null {
    try {
      return assertSessionUsable(status);
    } catch {
      return null;
    }
  }

  function assertPermission(
    command: DepinSignAuthCommand | { operation: "publish" }
  ): void {
    const needed = requiredPermission(command);
    if (!expectedPermissions.includes(needed)) {
      throw new DepinDeviceIdentityError(
        "SESSION_PERMISSION_INSUFFICIENT",
        `This operation needs the ${needed} permission; the session holds [${expectedPermissions.join(", ")}]`
      );
    }
  }

  function requireIdentity(): IDepinIdentityResponse {
    if (!identity) {
      throw new DepinDeviceIdentityError(
        "SESSION_REQUIRED",
        "Call session.ensure() before using the identity"
      );
    }
    return identity;
  }

  function authCommandFor(context: DepinAuthSigningContext): DepinSignAuthCommand {
    const address = requireIdentity().address;
    switch (context.kind) {
      case "request":
        if (context.token !== options.token) {
          throw new DepinDeviceIdentityError(
            "SESSION_TOKEN_MISMATCH",
            "The signing context token does not equal the session token"
          );
        }
        if (context.address !== address) {
          throw new DepinDeviceIdentityError(
            "NOT_FOR_THIS_IDENTITY",
            "The signing context names a different address than the device identity"
          );
        }
        return {
          operation: "request",
          type: context.type,
          token: context.token,
          address,
          timestamp_ms: context.timestampMs,
        };
      case "get":
        if (context.token !== options.token) {
          throw new DepinDeviceIdentityError(
            "SESSION_TOKEN_MISMATCH",
            "The signing context token does not equal the session token"
          );
        }
        if (context.address !== address) {
          throw new DepinDeviceIdentityError(
            "NOT_FOR_THIS_IDENTITY",
            "The signing context names a different address than the device identity"
          );
        }
        return {
          operation: "get",
          token: context.token,
          address,
          challenge: context.challenge,
        };
      case "clear":
        if (context.scope !== options.token) {
          throw new DepinDeviceIdentityError(
            "SESSION_TOKEN_MISMATCH",
            "The signing context scope does not equal the session token"
          );
        }
        if (context.address !== address) {
          throw new DepinDeviceIdentityError(
            "NOT_FOR_THIS_IDENTITY",
            "The signing context names a different address than the device identity"
          );
        }
        return {
          operation: "clear",
          scope: context.scope,
          address,
          challenge: context.challenge,
        };
      default: {
        const exhaustive: never = context;
        throw new DepinDeviceIdentityError(
          "SIGNING_CONTEXT_REQUIRED",
          `Unknown signing context ${JSON.stringify(exhaustive)}`
        );
      }
    }
  }

  const adapter: IDepinDeviceIdentity = {
    get address() {
      return requireIdentity().address;
    },
    get publicKey() {
      return requireIdentity().pubkey;
    },
    network: options.expectedNetwork,
    permissions: expectedPermissions,
    get maxDecryptBytes() {
      return maxDecryptBytes;
    },

    async signMessage(preimage, context) {
      if (!context) {
        // Without context the device would need a free hash, which is exactly
        // the primitive this adapter refuses to automate.
        throw new DepinDeviceIdentityError(
          "SIGNING_CONTEXT_REQUIRED",
          "A hardware identity needs the structured signing context (depin-msg >= 3.1.0)"
        );
      }
      const preliminaryCommand: DepinSignAuthCommand =
        context.kind === "request"
          ? {
              operation: "request",
              type: context.type,
              token: context.token,
              address: context.address,
              timestamp_ms: context.timestampMs,
            }
          : context.kind === "get"
            ? {
                operation: "get",
                token: context.token,
                address: context.address,
                challenge: context.challenge,
              }
            : {
                operation: "clear",
                scope: context.scope,
                address: context.address,
                challenge: context.challenge,
              };
      assertPermission(preliminaryCommand);
      const contextScope =
        preliminaryCommand.operation === "clear"
          ? preliminaryCommand.scope
          : preliminaryCommand.token;
      if (contextScope !== options.token) {
        throw new DepinDeviceIdentityError(
          "SESSION_TOKEN_MISMATCH",
          "The signing context token or scope does not equal the session token"
        );
      }
      if (authPreimageFor(preliminaryCommand) !== preimage) {
        throw new DepinDeviceIdentityError(
          "SIGNING_CONTEXT_REQUIRED",
          "The structured signing context does not rebuild the caller's authentication preimage"
        );
      }
      await ensure();
      const command = authCommandFor(context);
      if (authPreimageFor(command) !== preimage) {
        throw new DepinDeviceIdentityError(
          "SIGNING_CONTEXT_REQUIRED",
          "The structured signing context does not rebuild the caller's authentication preimage"
        );
      }

      let response;
      try {
        response = await device.depinSignAuth(command);
      } catch (error) {
        identity = null;
        throw error;
      }
      const declared = requireIdentity().pubkey.toLowerCase();
      if (
        typeof response.pubkey !== "string" ||
        !/^(?:02|03)[0-9a-f]{64}$/.test(response.pubkey) ||
        response.pubkey !== declared
      ) {
        throw new DepinDeviceIdentityError(
          "IDENTITY_KEY_MISMATCH",
          "The device signed with a key other than its announced DePIN identity"
        );
      }
      assertOperationCount(response.op_count);
      // Verify against the preimage the CALLER built, not the context: that is
      // what the node will check.
      const digest = neuraiSignedMessageDigest(preimage);
      return derSignatureToRecoverable(response.signature, digest, declared);
    },

    async signDigest(digest, context) {
      if (!context) {
        throw new DepinDeviceIdentityError(
          "SIGNING_CONTEXT_REQUIRED",
          "Publishing needs the structured message context (depin-msg >= 3.1.0)"
        );
      }
      assertPermission({ operation: "publish" });
      if (context.kind !== "message" || context.token !== options.token) {
        throw new DepinDeviceIdentityError(
          "SESSION_TOKEN_MISMATCH",
          "The message context token does not equal the session token"
        );
      }
      if (!(digest instanceof Uint8Array) || digest.length !== 32) {
        throw new DepinDeviceIdentityError(
          "SIGNING_CONTEXT_REQUIRED",
          "The message digest must be exactly 32 bytes"
        );
      }
      const rebuiltDigest = messageDigestFor(context);
      if (!rebuiltDigest.equals(Buffer.from(digest))) {
        throw new DepinDeviceIdentityError(
          "SIGNING_CONTEXT_REQUIRED",
          "The structured message context does not rebuild the caller's digest"
        );
      }
      await ensure();
      const address = requireIdentity().address;
      if (context.senderAddress !== address) {
        throw new DepinDeviceIdentityError(
          "NOT_FOR_THIS_IDENTITY",
          "The message context names a different sender than the device identity"
        );
      }

      let response;
      try {
        response = await device.depinSign({
          token: context.token,
          sender: address,
          timestamp: context.timestamp,
          messageType: context.messageType,
          encryptedPayload: context.encryptedPayloadHex,
        });
      } catch (error) {
        identity = null;
        throw error;
      }

      // The device rebuilt the preimage itself; check its DER against the
      // digest depin-msg computed, so a divergence fails here and not at the
      // node. `verify` needs the compact form.
      const compact = derToCompactLowS(response.signature);
      assertOperationCount(response.op_count);
      const pubkey = Buffer.from(requireIdentity().pubkey, "hex");
      if (!ecc.verify(Buffer.from(digest), pubkey, compact)) {
        throw new DepinDeviceIdentityError(
          "INVALID_DEVICE_SIGNATURE",
          "The device's message signature does not verify against the digest built by the host"
        );
      }
      return Uint8Array.from(compactToDer(compact));
    },

    async openReply(encryptedHex) {
      if (typeof encryptedHex !== "string" || !/^[0-9a-f]*$/.test(encryptedHex) ||
          encryptedHex.length % 2 !== 0 || encryptedHex.length === 0) {
        throw new DepinDeviceIdentityError(
          "DECRYPT_AUTH_FAILED",
          "The envelope to decrypt must be non-empty canonical hex"
        );
      }
      if (maxDecryptBytes !== null && encryptedHex.length / 2 > maxDecryptBytes) {
        throw new DepinDeviceIdentityError(
          "PAYLOAD_TOO_LARGE",
          `The envelope is ${encryptedHex.length / 2} bytes; this device accepts at most ${maxDecryptBytes}. Lower the page size and request a fresh challenge.`
        );
      }
      await ensure();
      requireIdentity();

      let response;
      try {
        response = await device.depinDecryptPayload(encryptedHex);
      } catch (error) {
        identity = null;
        if (/not[_ ]for|not encrypted|recipient/i.test(String((error as Error)?.message ?? error))) {
          throw new DepinDeviceIdentityError(
            "NOT_FOR_THIS_IDENTITY",
            "The envelope is not addressed to this device identity",
            error
          );
        }
        throw new DepinDeviceIdentityError(
          "DECRYPT_AUTH_FAILED",
          "The device could not open the envelope for this identity",
          error
        );
      }
      if (typeof response.plaintext_b64 !== "string") {
        throw new DepinDeviceIdentityError(
          "DECRYPT_AUTH_FAILED",
          "The device returned no plaintext for the envelope"
        );
      }
      assertOperationCount(response.op_count);
      return Uint8Array.from(decodeCanonicalBase64(response.plaintext_b64));
    },

    session: {
      ensure,
      status: () => device.depinSessionStatus(),
      end: async () => {
        await closeSession();
      },
    },
  };

  await ensure();
  return adapter;
}
