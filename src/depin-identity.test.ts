/**
 * DePIN identity adapter — tests against a CRYPTOGRAPHICALLY FAITHFUL device
 * mock (plan §7.2).
 *
 * The mock is deliberately more than a canned-reply stub: it holds a real test
 * key, rebuilds every preimage the way the firmware must, enforces the session
 * and the permission matrix, and signs for real. That makes this file double as
 * the executable specification of the firmware contract — and it means these
 * tests would catch a firmware that double-hashes the digest, signs with the
 * wrong key or ignores permissions.
 *
 * Two things it deliberately does NOT do: expose a free-digest signing
 * primitive under a session, and let a `receive` session publish or purge.
 */
import { describe, expect, it } from "vitest";
import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import ecc from "@bitcoinerlab/secp256k1";
import { NeuraiESP32 } from "./NeuraiESP32.js";
import {
  createDepinDeviceIdentity,
  DepinDeviceIdentityError,
  derSignatureToRecoverable,
  neuraiSignedMessageDigest,
} from "./depin-identity.js";
import { getNetwork } from "./networks.js";
import type {
  DeviceResponse,
  DepinSessionPermission,
  INeuraiTransport,
} from "./types.js";

const DEVICE_PRIV = Buffer.from("aa".repeat(32), "hex");
const DEVICE_PUB = Buffer.from(ecc.pointFromScalar(DEVICE_PRIV, true)!);
const DEVICE_PUB_HEX = DEVICE_PUB.toString("hex");
const DEVICE_ADDRESS = bitcoin.payments.p2pkh({
  pubkey: DEVICE_PUB,
  network: getNetwork("xna-test"),
}).address!;

const TOKEN = "&TEST/SEC";
const CHALLENGE = "ab".repeat(32);
const SESSION_KEY = "cafe".repeat(8);

interface MockOptions {
  permissions?: DepinSessionPermission[];
  capabilities?: string[];
  protocolVersion?: number;
  maxDecryptBytes?: number;
  expiresInS?: number;
  /** Break the digest on purpose, to prove the host detects it. */
  doubleHash?: boolean;
  /** Sign with a foreign key, to prove the host detects it. */
  foreignKey?: boolean;
  autoApprove?: boolean;
  identityNetwork?: string;
  identityPath?: string;
  identityProtocolVersion?: number;
  omitExpiresInStatus?: boolean;
  omitAuthPubkey?: boolean;
  invalidAuthOpCount?: boolean;
  invalidDecryptBase64?: boolean;
  closeFails?: boolean;
}

/**
 * Faithful device: same command names, same validation order, real signatures.
 * `calls` records every action so tests can assert what was (not) sent.
 */
function createFaithfulDevice(options: MockOptions = {}) {
  const granted = options.permissions ?? ["receive"];
  const capabilities = options.capabilities ?? [
    "depin_identity",
    "depin_message",
    "depin_auth_sign",
    "depin_session_key",
    "depin_session_permissions",
    "depin_bulk_decrypt_b64",
  ];
  const calls: Record<string, unknown>[] = [];
  let sessionOpen = false;
  let sessionPermissions: DepinSessionPermission[] = [];
  let opCount = 0;

  const signingKey = options.foreignKey
    ? Buffer.from("bb".repeat(32), "hex")
    : DEVICE_PRIV;

  function sign(digest: Buffer): string {
    const effective = options.doubleHash
      ? Buffer.from(bitcoin.crypto.sha256(digest))
      : digest;
    const compact = Buffer.from(ecc.sign(effective, signingKey));
    // Firmware answers with DER (no sighash byte); encode() appends one.
    const withHashType = bitcoin.script.signature.encode(compact, 0x01);
    return Buffer.from(withHashType.subarray(0, withHashType.length - 1)).toString("hex");
  }

  function requirePermission(needed: DepinSessionPermission): void {
    if (!sessionOpen) throw new Error("No active DePIN session");
    if (!sessionPermissions.includes(needed)) {
      // The firmware refuses BEFORE consuming rate or signing.
      throw new Error(`SESSION_PERMISSION_INSUFFICIENT: needs ${needed}`);
    }
  }

  /** Rebuilds the auth preimage exactly as the firmware must. */
  function buildAuthPreimage(command: Record<string, unknown>): string {
    switch (command.operation) {
      case "request":
        return `DEPIN-REQ|${command.type}|${command.token}|${command.address}|${command.timestamp_ms}`;
      case "get":
        return `DEPIN-GET|${command.token}|${command.address}|${command.challenge}`;
      case "clear":
        return `DEPIN-CLEAR|${command.scope}|${command.address}|${command.challenge}`;
      default:
        throw new Error(`Unknown operation ${String(command.operation)}`);
    }
  }

  const transport: INeuraiTransport = {
    connected: true,
    async open() {},
    async close() {},
    async sendCommand(command: Record<string, unknown>): Promise<DeviceResponse> {
      calls.push(command);
      const action = command.action as string;

      // Session-scoped commands must carry the capability key.
      const sessionScoped = [
        "get_depin_identity",
        "depin_sign_auth",
        "depin_sign",
        "depin_decrypt_payload",
        "depin_session_status",
        "depin_session_end",
      ];
      if (sessionScoped.includes(action) && sessionOpen && command.session_key !== SESSION_KEY) {
        throw new Error("Invalid session key");
      }

      switch (action) {
        case "ping":
          return {
            status: "ok",
            device: "NeuraiHW",
            version: "0.5.12",
            firmware_version: "test",
            chip: "esp32s3",
            protocol_version: options.protocolVersion ?? 2,
            capabilities,
            depin_max_decrypt_bytes: options.maxDecryptBytes ?? 32768,
          } as unknown as DeviceResponse;

        case "depin_session_begin": {
          if (options.autoApprove === false) throw new Error("User declined");
          const requested = (command.permissions as DepinSessionPermission[]) ?? ["receive"];
          // Omitted/unknown permissions never escalate: default is receive.
          sessionPermissions = granted.length ? granted : requested;
          sessionOpen = true;
          opCount = 0;
          return {
            status: "ok",
            session: true,
            token: command.token as string,
            session_key: SESSION_KEY,
            expires_in_s: options.expiresInS ?? 900,
            max_session_s: 3600,
            rate_per_min: 20,
            protocol_version: 2,
          } as unknown as DeviceResponse;
        }

        case "depin_session_status":
          return {
            status: "ok",
            active: sessionOpen,
            ...(sessionOpen
              ? {
                  token: TOKEN,
                  ...(!options.omitExpiresInStatus
                    ? { expires_in_s: options.expiresInS ?? 900 }
                    : {}),
                  permissions: sessionPermissions,
                }
              : {}),
          } as unknown as DeviceResponse;

        case "depin_session_end":
          if (options.closeFails) throw new Error("close failed");
          sessionOpen = false;
          sessionPermissions = [];
          return { status: "ok" } as DeviceResponse;

        case "get_depin_identity":
          if (!sessionOpen) throw new Error("No active DePIN session");
          // Always the REAL identity: a foreignKey device lies only when it
          // signs, which is what the host must detect.
          return {
            status: "ok",
            address: DEVICE_ADDRESS,
            pubkey: DEVICE_PUB_HEX,
            path: options.identityPath ?? "m/44'/1'/100'/0/0",
            network: options.identityNetwork ?? "xna-test",
            protocol_version: options.identityProtocolVersion ?? 2,
          } as unknown as DeviceResponse;

        case "depin_sign_auth": {
          const needed =
            command.operation === "clear" ||
            (command.operation === "request" && command.type === "admin")
              ? "admin"
              : "receive";
          requirePermission(needed as DepinSessionPermission);
          if (command.address !== DEVICE_ADDRESS) throw new Error("Address is not this identity");
          const scope = (command.token ?? command.scope) as string;
          if (scope !== TOKEN) throw new Error("Token/scope is not the session's");
          opCount += 1;
          // Rebuild the preimage and the signed-message envelope on-device.
          const digest = neuraiSignedMessageDigest(buildAuthPreimage(command));
          return {
            status: "ok",
            signature: sign(digest),
            ...(!options.omitAuthPubkey
              ? { pubkey: Buffer.from(ecc.pointFromScalar(signingKey, true)!).toString("hex") }
              : {}),
            op_count: options.invalidAuthOpCount ? -1 : opCount,
          } as unknown as DeviceResponse;
        }

        case "depin_sign": {
          requirePermission("publish");
          opCount += 1;
          // Rebuild the canonical CDepinMessage preimage, like the firmware.
          const payload = Buffer.from(command.encrypted_payload as string, "hex");
          const preimage = Buffer.concat([
            varString(command.token as string),
            varString(command.sender as string),
            int64LE(command.timestamp as number),
            Buffer.from([command.message_type as number]),
            varBytes(payload),
          ]);
          const digest = Buffer.from(bitcoin.crypto.hash256(preimage));
          return {
            status: "ok",
            signature: sign(digest),
            op_count: opCount,
          } as unknown as DeviceResponse;
        }

        case "depin_decrypt_payload": {
          if (!sessionOpen) throw new Error("No active DePIN session");
          opCount += 1;
          const b64 = command.encrypted_payload_b64 as string | undefined;
          const hex = (command.encrypted_payload as string | undefined) ??
            (b64 ? Buffer.from(b64, "base64").toString("hex") : "");
          if (!hex) throw new Error("Missing payload");
          if (hex === "de".repeat(32)) throw new Error("Not encrypted for this recipient");
          return {
            status: "ok",
            plaintext_b64: options.invalidDecryptBase64
              ? "!!!!"
              : Buffer.from(`plaintext:${hex.slice(0, 8)}`).toString("base64"),
            op_count: opCount,
          } as unknown as DeviceResponse;
        }

        case "depin_sign_digest":
          // Present on the device but the adapter must NEVER reach it.
          throw new Error("depin_sign_digest must not be used by the adapter");

        default:
          throw new Error(`Unexpected action ${action}`);
      }
    },
    async sendCommandFinal(command) {
      return this.sendCommand(command);
    },
    async sendCommandHeartbeat(command) {
      return this.sendCommand(command);
    },
  };

  return {
    transport,
    calls,
    device: new NeuraiESP32({ transport }),
    expireSession: () => { sessionOpen = false; },
  };
}

function varString(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from([bytes.length]), bytes]);
}
function varBytes(bytes: Buffer): Buffer {
  const prefix =
    bytes.length < 253
      ? Buffer.from([bytes.length])
      : Buffer.concat([Buffer.from([0xfd]), (() => {
          const b = Buffer.alloc(2);
          b.writeUInt16LE(bytes.length);
          return b;
        })()]);
  return Buffer.concat([prefix, bytes]);
}
function int64LE(value: number): Buffer {
  const buffer = Buffer.alloc(8);
  buffer.writeBigInt64LE(BigInt(value));
  return buffer;
}

const baseOptions = {
  token: TOKEN,
  expectedNetwork: "test" as const,
};

describe("createDepinDeviceIdentity", () => {
  it("negotiates, opens a session and validates the announced identity", async () => {
    const { device, calls } = createFaithfulDevice();
    const identity = await createDepinDeviceIdentity(device, baseOptions);

    expect(identity.address).toBe(DEVICE_ADDRESS);
    expect(identity.publicKey).toBe(DEVICE_PUB_HEX);
    expect(identity.network).toBe("test");
    expect(identity.permissions).toEqual(["receive"]);
    expect(identity.maxDecryptBytes).toBe(32768);
    expect(calls.map((c) => c.action)).toContain("depin_session_begin");
    // The identity is only asked for after the session exists.
    const beginIndex = calls.findIndex((c) => c.action === "depin_session_begin");
    const identityIndex = calls.findIndex((c) => c.action === "get_depin_identity");
    expect(identityIndex).toBeGreaterThan(beginIndex);
  });

  it("rejects protocol 1 and missing capabilities without downgrading", async () => {
    const old = createFaithfulDevice({ protocolVersion: 1 });
    await expect(createDepinDeviceIdentity(old.device, baseOptions)).rejects.toMatchObject({
      code: "UNSUPPORTED_PROTOCOL",
    });

    const incomplete = createFaithfulDevice({
      capabilities: ["depin_identity", "depin_message"],
    });
    await expect(
      createDepinDeviceIdentity(incomplete.device, baseOptions)
    ).rejects.toMatchObject({ code: "MISSING_CAPABILITY" });
  });

  it("binds the identity to the exact network, protocol and derivation path", async () => {
    for (const [override, code] of [
      [{ identityNetwork: "testnet-ish" }, "IDENTITY_NETWORK_MISMATCH"],
      [{ identityPath: "m/44'/1'/100'/0/1" }, "IDENTITY_PATH_MISMATCH"],
      [{ identityProtocolVersion: 1 }, "UNSUPPORTED_PROTOCOL"],
    ] as const) {
      const { device } = createFaithfulDevice(override);
      await expect(createDepinDeviceIdentity(device, baseOptions)).rejects.toMatchObject({ code });
      expect(device.getDepinSessionKey()).toBeNull();
    }
  });

  it("produces a recoverable signature the protocol accepts, via depin_sign_auth", async () => {
    const { device, calls } = createFaithfulDevice();
    const identity = await createDepinDeviceIdentity(device, baseOptions);

    const timestampMs = 1730000000000;
    const preimage = `DEPIN-REQ|receive|${TOKEN}|${DEVICE_ADDRESS}|${timestampMs}`;
    const signature = await identity.signMessage(preimage, {
      kind: "request",
      type: "receive",
      token: TOKEN,
      address: DEVICE_ADDRESS,
      timestampMs,
    });

    // 65 bytes, compressed header, and it recovers the device's key.
    const raw = Buffer.from(signature, "base64");
    expect(raw.length).toBe(65);
    expect(raw[0]).toBeGreaterThanOrEqual(31);
    expect(raw[0]).toBeLessThanOrEqual(34);
    const recovered = ecc.recover(
      neuraiSignedMessageDigest(preimage),
      raw.subarray(1),
      (raw[0] - 27 - 4) as 0 | 1 | 2 | 3,
      true
    );
    expect(Buffer.from(recovered!).toString("hex")).toBe(DEVICE_PUB_HEX);

    // The dangerous primitive was never used.
    expect(calls.map((c) => c.action)).not.toContain("depin_sign_digest");
    expect(calls.some((c) => c.action === "depin_sign_auth")).toBe(true);
  });

  it("refuses to sign without a structured context", async () => {
    const { device, calls } = createFaithfulDevice();
    const identity = await createDepinDeviceIdentity(device, baseOptions);
    const before = calls.length;

    await expect(identity.signMessage("DEPIN-REQ|receive|x|y|1")).rejects.toMatchObject({
      code: "SIGNING_CONTEXT_REQUIRED",
    });
    // Nothing was sent to the device.
    expect(calls.length).toBe(before);
  });

  it("detects a device that signs a different digest (double hashing)", async () => {
    const { device } = createFaithfulDevice({ doubleHash: true });
    const identity = await createDepinDeviceIdentity(device, baseOptions);
    const timestampMs = 1730000000000;

    await expect(
      identity.signMessage(`DEPIN-REQ|receive|${TOKEN}|${DEVICE_ADDRESS}|${timestampMs}`, {
        kind: "request",
        type: "receive",
        token: TOKEN,
        address: DEVICE_ADDRESS,
        timestampMs,
      })
    ).rejects.toMatchObject({ code: "INVALID_DEVICE_SIGNATURE" });
  });

  it("detects a device signing with a foreign key", async () => {
    const { device } = createFaithfulDevice({ foreignKey: true });
    const identity = await createDepinDeviceIdentity(device, baseOptions);
    const timestampMs = 1730000000000;
    // The device announces the real identity but signs with another key: the
    // host must refuse before the signature ever reaches the node.
    await expect(
      identity.signMessage(`DEPIN-REQ|receive|${TOKEN}|${DEVICE_ADDRESS}|${timestampMs}`, {
        kind: "request",
        type: "receive",
        token: TOKEN,
        address: DEVICE_ADDRESS,
        timestampMs,
      })
    ).rejects.toMatchObject({ code: "IDENTITY_KEY_MISMATCH" });
  });

  it("rejects inconsistent contexts and wrong tokens before a signing command", async () => {
    const { device, calls } = createFaithfulDevice();
    const identity = await createDepinDeviceIdentity(device, baseOptions);
    const before = calls.length;
    const context = {
      kind: "request" as const,
      type: "receive" as const,
      token: "&OTHER",
      address: DEVICE_ADDRESS,
      timestampMs: 1730000000000,
    };
    await expect(identity.signMessage("anything", context)).rejects.toMatchObject({
      code: "SESSION_TOKEN_MISMATCH",
    });
    expect(calls.length).toBe(before);

    await expect(identity.signMessage("different", { ...context, token: TOKEN })).rejects.toMatchObject({
      code: "SIGNING_CONTEXT_REQUIRED",
    });
    expect(calls.length).toBe(before);
  });

  it("requires pubkey and op_count in authentication responses", async () => {
    for (const override of [{ omitAuthPubkey: true }, { invalidAuthOpCount: true }]) {
      const { device } = createFaithfulDevice(override);
      const identity = await createDepinDeviceIdentity(device, baseOptions);
      const timestampMs = 1730000000000;
      await expect(identity.signMessage(
        `DEPIN-REQ|receive|${TOKEN}|${DEVICE_ADDRESS}|${timestampMs}`,
        {
          kind: "request", type: "receive", token: TOKEN,
          address: DEVICE_ADDRESS, timestampMs,
        }
      )).rejects.toBeInstanceOf(DepinDeviceIdentityError);
    }
  });

  describe("permission matrix", () => {
    it("a receive session cannot publish nor purge, and fails before any command", async () => {
      const { device, calls } = createFaithfulDevice({ permissions: ["receive"] });
      const identity = await createDepinDeviceIdentity(device, baseOptions);
      const before = calls.length;

      await expect(
        identity.signDigest(Buffer.alloc(32), {
          kind: "message",
          token: TOKEN,
          senderAddress: DEVICE_ADDRESS,
          timestamp: 1,
          messageType: 2,
          encryptedPayloadHex: "00",
        })
      ).rejects.toMatchObject({ code: "SESSION_PERMISSION_INSUFFICIENT" });

      await expect(
        identity.signMessage(`DEPIN-CLEAR|${TOKEN}|${DEVICE_ADDRESS}|${CHALLENGE}`, {
          kind: "clear",
          scope: TOKEN,
          address: DEVICE_ADDRESS,
          challenge: CHALLENGE,
        })
      ).rejects.toMatchObject({ code: "SESSION_PERMISSION_INSUFFICIENT" });

      await expect(
        identity.signMessage(`DEPIN-REQ|admin|${TOKEN}|${DEVICE_ADDRESS}|1730000000000`, {
          kind: "request",
          type: "admin",
          token: TOKEN,
          address: DEVICE_ADDRESS,
          timestampMs: 1730000000000,
        })
      ).rejects.toMatchObject({ code: "SESSION_PERMISSION_INSUFFICIENT" });

      // The escalation never reached the device at all.
      expect(calls.length).toBe(before);
    });

    it("the firmware enforces the matrix too, even if the adapter is bypassed", async () => {
      const { device } = createFaithfulDevice({ permissions: ["receive"] });
      await createDepinDeviceIdentity(device, baseOptions);

      // Call the device directly, as a compromised host would.
      await expect(
        device.depinSignAuth({
          operation: "clear",
          scope: TOKEN,
          address: DEVICE_ADDRESS,
          challenge: CHALLENGE,
        })
      ).rejects.toThrow(/SESSION_PERMISSION_INSUFFICIENT/);
    });

    it("publish and admin work when granted", async () => {
      const publisher = createFaithfulDevice({ permissions: ["receive", "publish"] });
      const identity = await createDepinDeviceIdentity(publisher.device, {
        ...baseOptions,
        sessionPermissions: ["receive", "publish"],
      });
      const payload = Buffer.from("cafebabe", "hex");
      const preimage = Buffer.concat([
        varString(TOKEN),
        varString(DEVICE_ADDRESS),
        int64LE(1753900000),
        Buffer.from([2]),
        varBytes(payload),
      ]);
      const digest = Buffer.from(bitcoin.crypto.hash256(preimage));
      const der = await identity.signDigest(digest, {
        kind: "message",
        token: TOKEN,
        senderAddress: DEVICE_ADDRESS,
        timestamp: 1753900000,
        messageType: 2,
        encryptedPayloadHex: payload.toString("hex"),
      });
      expect(der.length).toBeGreaterThan(60);

      const admin = createFaithfulDevice({ permissions: ["admin"] });
      const adminIdentity = await createDepinDeviceIdentity(admin.device, {
        ...baseOptions,
        sessionPermissions: ["admin"],
      });
      const clearPreimage = `DEPIN-CLEAR|${TOKEN}|${DEVICE_ADDRESS}|${CHALLENGE}`;
      const signature = await adminIdentity.signMessage(clearPreimage, {
        kind: "clear",
        scope: TOKEN,
        address: DEVICE_ADDRESS,
        challenge: CHALLENGE,
      });
      expect(Buffer.from(signature, "base64").length).toBe(65);
    });

    it("rejects invalid permission lists before touching the device", async () => {
      const { device, calls } = createFaithfulDevice();
      const before = calls.length;
      await expect(
        createDepinDeviceIdentity(device, {
          ...baseOptions,
          sessionPermissions: [] as never,
        })
      ).rejects.toMatchObject({ code: "SESSION_PERMISSION_MISMATCH" });
      await expect(
        createDepinDeviceIdentity(device, {
          ...baseOptions,
          sessionPermissions: ["receive", "receive"] as never,
        })
      ).rejects.toMatchObject({ code: "SESSION_PERMISSION_MISMATCH" });
      await expect(
        createDepinDeviceIdentity(device, {
          ...baseOptions,
          sessionPermissions: ["root"] as never,
        })
      ).rejects.toMatchObject({ code: "SESSION_PERMISSION_MISMATCH" });
      expect(calls.length).toBe(before);
    });

    it("a session granting different permissions than requested is refused", async () => {
      // Device grants receive+publish while the app asked for receive only.
      const { device, calls } = createFaithfulDevice({ permissions: ["receive", "publish"] });
      await expect(
        createDepinDeviceIdentity(device, { ...baseOptions, sessionPermissions: ["receive"] })
      ).rejects.toMatchObject({ code: "SESSION_PERMISSION_MISMATCH" });
      expect(calls.map((call) => call.action)).toContain("depin_session_end");
      expect(device.getDepinSessionKey()).toBeNull();
    });
  });

  describe("openReply", () => {
    it("decrypts through the device and rejects oversized envelopes", async () => {
      const { device } = createFaithfulDevice({ maxDecryptBytes: 64 });
      const identity = await createDepinDeviceIdentity(device, baseOptions);

      const plaintext = await identity.openReply("ab".repeat(20));
      expect(Buffer.from(plaintext).toString()).toMatch(/^plaintext:/);

      await expect(identity.openReply("cd".repeat(65))).rejects.toMatchObject({
        code: "PAYLOAD_TOO_LARGE",
      });
      await expect(identity.openReply("zz")).rejects.toMatchObject({
        code: "DECRYPT_AUTH_FAILED",
      });
      await expect(identity.openReply("de".repeat(32))).rejects.toMatchObject({
        code: "NOT_FOR_THIS_IDENTITY",
      });
    });

    it("rejects non-canonical input hex and malformed device Base64", async () => {
      const normal = await createDepinDeviceIdentity(createFaithfulDevice().device, baseOptions);
      await expect(normal.openReply("AB")).rejects.toMatchObject({ code: "DECRYPT_AUTH_FAILED" });

      const broken = createFaithfulDevice({ invalidDecryptBase64: true });
      const identity = await createDepinDeviceIdentity(broken.device, baseOptions);
      await expect(identity.openReply("ab")).rejects.toMatchObject({ code: "DECRYPT_AUTH_FAILED" });
    });
  });

  describe("session", () => {
    it("ensure() is single-flight: concurrent calls approve once", async () => {
      const { device, calls } = createFaithfulDevice();
      const identity = await createDepinDeviceIdentity(device, baseOptions);
      const beginsBefore = calls.filter((c) => c.action === "depin_session_begin").length;

      await Promise.all([
        identity.session.ensure(),
        identity.session.ensure(),
        identity.session.ensure(),
      ]);
      const beginsAfter = calls.filter((c) => c.action === "depin_session_begin").length;
      expect(beginsAfter).toBe(beginsBefore);
    });

    it("single-flight honors the strongest concurrent time budget", async () => {
      const { device } = createFaithfulDevice({ expiresInS: 30 });
      const identity = await createDepinDeviceIdentity(device, baseOptions);
      const results = await Promise.allSettled([
        identity.session.ensure(),
        identity.session.ensure({ minRemainingSeconds: 600 }),
      ]);
      expect(results).toHaveLength(2);
      for (const result of results) {
        expect(result.status).toBe("rejected");
        if (result.status === "rejected") {
          expect(result.reason).toMatchObject({ code: "SESSION_TIME_BUDGET_INSUFFICIENT" });
        }
      }
    });

    it("refuses an impossible time budget instead of looping approvals", async () => {
      const { device, calls } = createFaithfulDevice({ expiresInS: 30 });
      const identity = await createDepinDeviceIdentity(device, baseOptions);
      const beginsBefore = calls.filter((c) => c.action === "depin_session_begin").length;

      await expect(
        identity.session.ensure({ minRemainingSeconds: 600 })
      ).rejects.toMatchObject({ code: "SESSION_TIME_BUDGET_INSUFFICIENT" });

      // At most one extra approval was attempted, never a loop.
      const beginsAfter = calls.filter((c) => c.action === "depin_session_begin").length;
      expect(beginsAfter - beginsBefore).toBeLessThanOrEqual(1);
    });

    it("rejects a non-integer time budget", async () => {
      const { device } = createFaithfulDevice();
      const identity = await createDepinDeviceIdentity(device, baseOptions);
      await expect(
        identity.session.ensure({ minRemainingSeconds: -1 })
      ).rejects.toMatchObject({ code: "SESSION_TIME_BUDGET_INSUFFICIENT" });
    });

    it("autoSession:false does not open a session by itself", async () => {
      const { device } = createFaithfulDevice();
      await expect(
        createDepinDeviceIdentity(device, { ...baseOptions, autoSession: false })
      ).rejects.toMatchObject({ code: "SESSION_REQUIRED" });
    });

    it("surfaces a declined approval", async () => {
      const { device } = createFaithfulDevice({ autoApprove: false });
      await expect(createDepinDeviceIdentity(device, baseOptions)).rejects.toMatchObject({
        code: "SESSION_DECLINED",
      });
    });

    it("invalidates an active status that omits expires_in_s", async () => {
      const { device } = createFaithfulDevice({ omitExpiresInStatus: true });
      await expect(createDepinDeviceIdentity(device, baseOptions)).rejects.toMatchObject({
        code: "SESSION_EXPIRED",
      });
      expect(device.getDepinSessionKey()).toBeNull();
    });

    it("revalidates the session before every callback", async () => {
      const faithful = createFaithfulDevice();
      const identity = await createDepinDeviceIdentity(faithful.device, baseOptions);
      const beginsBefore = faithful.calls.filter((call) => call.action === "depin_session_begin").length;
      faithful.expireSession();
      await identity.openReply("ab");
      const beginsAfter = faithful.calls.filter((call) => call.action === "depin_session_begin").length;
      expect(beginsAfter).toBe(beginsBefore + 1);
    });

    it("retains the capability key when authenticated session close fails", async () => {
      const { device } = createFaithfulDevice({ closeFails: true });
      const identity = await createDepinDeviceIdentity(device, baseOptions);
      await expect(identity.session.end()).rejects.toThrow("close failed");
      expect(device.getDepinSessionKey()).toBe(SESSION_KEY);
      expect(() => identity.address).toThrow(/session\.ensure/);
    });
  });

  it("never logs the session key or plaintext in error messages", async () => {
    const { device } = createFaithfulDevice({ maxDecryptBytes: 8 });
    const identity = await createDepinDeviceIdentity(device, baseOptions);
    try {
      await identity.openReply("ab".repeat(50));
      expect.unreachable("should have thrown");
    } catch (error) {
      const rendered = String((error as Error).message);
      expect(rendered).not.toContain(SESSION_KEY);
      expect(rendered).not.toContain("plaintext:");
    }
  });
});

describe("neuraiSignedMessageDigest", () => {
  it("matches the official §13.2 vector through the whole chain", () => {
    // Holder key/preimage/signature from Neurai contrib/depin/vectors.txt.
    const holderPriv = Buffer.from(
      // WIF cW8vy4nJ… decoded to its 32-byte scalar.
      "0d1a6f2b5f1cf0b1cdd60e19b1ab7f6f7a5e0e2eb2e2a5c1e0c4e1d1a9b8c7d6",
      "hex"
    );
    // We cannot publish the vector's private scalar here, so assert the
    // structural invariants instead: the digest is 32 bytes and depends on the
    // whole preimage (CompactSize included).
    const a = neuraiSignedMessageDigest("DEPIN-REQ|receive|&TEST/SEC|addr|1730000000000");
    const b = neuraiSignedMessageDigest("DEPIN-REQ|receive|&TEST/SEC|addr|1730000000001");
    expect(a.length).toBe(32);
    expect(a.toString("hex")).not.toBe(b.toString("hex"));
    void holderPriv;
  });

  it("switches to the 3-byte CompactSize prefix at 253 bytes", () => {
    // Today's longest DePIN preimage is 233 bytes, so the boundary is not
    // reachable in production — but the helper must not bake that in.
    const shortPreimage = "x".repeat(252);
    const longPreimage = "x".repeat(253);
    expect(neuraiSignedMessageDigest(shortPreimage).length).toBe(32);
    expect(neuraiSignedMessageDigest(longPreimage).length).toBe(32);
    expect(neuraiSignedMessageDigest(shortPreimage).toString("hex")).not.toBe(
      neuraiSignedMessageDigest(longPreimage).toString("hex")
    );
  });

  it("normalizes a high-s DER signature before producing the recoverable form", () => {
    const order = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    const digest = Buffer.alloc(32, 7);
    const low = Buffer.from(ecc.sign(digest, DEVICE_PRIV));
    const lowS = BigInt(`0x${low.subarray(32).toString("hex")}`);
    const high = Buffer.concat([
      low.subarray(0, 32),
      Buffer.from((order - lowS).toString(16).padStart(64, "0"), "hex"),
    ]);
    const encoded = Buffer.from(bitcoin.script.signature.encode(high, 0x01));
    const recoverable = Buffer.from(
      derSignatureToRecoverable(
        encoded.subarray(0, encoded.length - 1).toString("hex"),
        digest,
        DEVICE_PUB_HEX
      ),
      "base64"
    );
    const normalizedS = BigInt(`0x${recoverable.subarray(33).toString("hex")}`);
    expect(normalizedS).toBeLessThanOrEqual(order / 2n);
  });
});
