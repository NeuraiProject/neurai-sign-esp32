/**
 * End-to-end integration WITHOUT hardware (plan §7.3): the adapter drives the
 * real `neurai-depin-msg` protocol-2 flows against a fake pool whose replies
 * are legitimately signed, while the "device" is the faithful mock.
 *
 * This is where the two halves meet: depin-msg builds the preimages and passes
 * the structured contexts, the adapter turns them into device commands, the
 * mock rebuilds and signs them, and depin-msg's own verification decides.
 * Nothing here fabricates a signature or bypasses a check.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { Buffer } from "buffer";
import * as bitcoin from "bitcoinjs-lib";
import ecc from "@bitcoinerlab/secp256k1";
import {
  buildDepinReplyPreimage,
  buildDepinMessageForPool,
  clearDepinMessages,
  deserializeEciesMessage,
  eciesDecrypt,
  eciesEncrypt,
  listDepinSectionsPrivate,
  receiveDepinMessages,
  requestDepinChallenge,
  submitDepinMessage,
  parseDepinMessage,
  serializeEciesMessage,
  signRecoverableMessage,
  verifyRecoverableMessage,
  buildDepinRequestPreimage,
  buildDepinGetPreimage,
} from "@neuraiproject/neurai-depin-msg";
import { NeuraiESP32 } from "./NeuraiESP32.js";
import { createDepinDeviceIdentity } from "./depin-identity.js";
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

// The fake pool: we own its key, so its envelopes are genuinely signed.
const POOL_PRIV = Buffer.from("66".repeat(32), "hex");
const POOL_PUB_HEX = Buffer.from(ecc.pointFromScalar(POOL_PRIV, true)!).toString("hex");

const TOKEN = "&TEST/SEC";
const CHALLENGE = "ab".repeat(32);
const NEXT_CHALLENGE = "cd".repeat(32);
const SESSION_KEY = "cafe".repeat(8);

function compactSize(length: number): Buffer {
  if (length < 253) return Buffer.from([length]);
  const result = Buffer.alloc(3);
  result[0] = 0xfd;
  result.writeUInt16LE(length, 1);
  return result;
}

function varBytes(bytes: Buffer): Buffer {
  return Buffer.concat([compactSize(bytes.length), bytes]);
}

function varString(value: string): Buffer {
  return varBytes(Buffer.from(value, "utf8"));
}

function plainReply(method: string, token: string, body: unknown) {
  const bodyHex = Buffer.from(JSON.stringify(body), "utf8").toString("hex");
  return {
    body: bodyHex,
    poolsig: signRecoverableMessage(
      buildDepinReplyPreimage({ method, token, address: "", challenge: "", replyHex: bodyHex }),
      POOL_PRIV.toString("hex")
    ),
  };
}

function deviceMock(permissions: DepinSessionPermission[]) {
  let sessionOpen = false;
  let opCount = 0;

  function derSign(digest: Buffer): string {
    const compact = Buffer.from(ecc.sign(digest, DEVICE_PRIV));
    const withHashType = bitcoin.script.signature.encode(compact, 0x01);
    return Buffer.from(withHashType.subarray(0, withHashType.length - 1)).toString("hex");
  }
  function signedMessageDigest(message: string): Buffer {
    const varString = (value: string) => {
      const bytes = Buffer.from(value, "utf8");
      return Buffer.concat([Buffer.from([bytes.length]), bytes]);
    };
    return Buffer.from(
      bitcoin.crypto.hash256(
        Buffer.concat([varString("Neurai Signed Message:\n"), varString(message)])
      )
    );
  }

  const transport: INeuraiTransport = {
    connected: true,
    async open() {},
    async close() {},
    async sendCommand(command: Record<string, unknown>): Promise<DeviceResponse> {
      switch (command.action) {
        case "ping":
          return {
            status: "ok", device: "NeuraiHW", version: "0.5.12",
            firmware_version: "t", chip: "esp32s3", protocol_version: 2,
            capabilities: [
              "depin_identity", "depin_message", "depin_auth_sign",
              "depin_session_key", "depin_session_permissions",
            ],
            depin_max_decrypt_bytes: 32768,
          } as unknown as DeviceResponse;
        case "depin_session_begin":
          sessionOpen = true;
          return {
            status: "ok", session: true, token: command.token as string,
            session_key: SESSION_KEY, expires_in_s: 900, max_session_s: 3600,
            rate_per_min: 20, protocol_version: 2,
          } as unknown as DeviceResponse;
        case "depin_session_status":
          return {
            status: "ok", active: sessionOpen,
            ...(sessionOpen ? { token: TOKEN, expires_in_s: 900, permissions } : {}),
          } as unknown as DeviceResponse;
        case "depin_session_end":
          sessionOpen = false;
          return { status: "ok" } as DeviceResponse;
        case "get_depin_identity":
          return {
            status: "ok", address: DEVICE_ADDRESS, pubkey: DEVICE_PUB_HEX,
            path: "m/44'/1'/100'/0/0", network: "xna-test", protocol_version: 2,
          } as unknown as DeviceResponse;
        case "depin_sign_auth": {
          const needed =
            command.operation === "clear" ||
            (command.operation === "request" && command.type === "admin")
              ? "admin" : "receive";
          if (!permissions.includes(needed as DepinSessionPermission)) {
            throw new Error(`SESSION_PERMISSION_INSUFFICIENT: ${needed}`);
          }
          const preimage =
            command.operation === "request"
              ? `DEPIN-REQ|${command.type}|${command.token}|${command.address}|${command.timestamp_ms}`
              : command.operation === "get"
                ? `DEPIN-GET|${command.token}|${command.address}|${command.challenge}`
                : `DEPIN-CLEAR|${command.scope}|${command.address}|${command.challenge}`;
          opCount += 1;
          return {
            status: "ok", signature: derSign(signedMessageDigest(preimage)),
            pubkey: DEVICE_PUB_HEX, op_count: opCount,
          } as unknown as DeviceResponse;
        }
        case "depin_sign": {
          if (!permissions.includes("publish")) {
            throw new Error("SESSION_PERMISSION_INSUFFICIENT: publish");
          }
          const timestamp = Buffer.alloc(8);
          timestamp.writeBigInt64LE(BigInt(command.timestamp as number));
          const payload = Buffer.from(command.encrypted_payload as string, "hex");
          const digest = Buffer.from(bitcoin.crypto.hash256(Buffer.concat([
            varString(command.token as string),
            varString(command.sender as string),
            timestamp,
            Buffer.from([command.message_type as number]),
            varBytes(payload),
          ])));
          opCount += 1;
          return {
            status: "ok", signature: derSign(digest), op_count: opCount,
          } as unknown as DeviceResponse;
        }
        case "depin_decrypt_payload": {
          const b64 = command.encrypted_payload_b64 as string | undefined;
          const hex = (command.encrypted_payload as string | undefined) ??
            (b64 ? Buffer.from(b64, "base64").toString("hex") : "");
          opCount += 1;
          // Real ECIES: decrypt with the device key, like the firmware.
          const { deserializeEciesMessage, eciesDecrypt } = eciesRuntime;
          const message = deserializeEciesMessage(Uint8Array.from(Buffer.from(hex, "hex")));
          const plaintext = await eciesDecrypt(message, Uint8Array.from(DEVICE_PRIV));
          if (plaintext === null) throw new Error("Not encrypted for this recipient");
          return {
            status: "ok",
            plaintext_b64: Buffer.from(plaintext).toString("base64"),
            op_count: opCount,
          } as unknown as DeviceResponse;
        }
        case "depin_sign_digest":
          throw new Error("the adapter must never use depin_sign_digest");
        default:
          throw new Error(`Unexpected action ${String(command.action)}`);
      }
    },
    async sendCommandFinal(c) { return this.sendCommand(c); },
    async sendCommandHeartbeat(c) { return this.sendCommand(c); },
  };
  return new NeuraiESP32({ transport });
}

// Loaded lazily so the mock can use the library's own ECIES primitives.
interface EciesRuntime {
  deserializeEciesMessage: (bytes: Uint8Array) => EciesMessageLike;
  eciesDecrypt: (message: EciesMessageLike, key: Uint8Array) => Promise<Uint8Array | null>;
}
type EciesMessageLike = Parameters<typeof eciesEncrypt> extends unknown
  ? Record<string, unknown>
  : never;
let eciesRuntime: EciesRuntime;

async function boundReply(
  method: string, token: string, address: string, challenge: string, result: unknown
) {
  const ecies = await eciesEncrypt(
    new TextEncoder().encode(JSON.stringify(result)),
    [Uint8Array.from(DEVICE_PUB)]
  );
  const encrypted = Buffer.from(serializeEciesMessage(ecies as never)).toString("hex");
  const poolsig = signRecoverableMessage(
    buildDepinReplyPreimage({ method, token, address, challenge, replyHex: encrypted }),
    POOL_PRIV.toString("hex")
  );
  return { encrypted, poolsig };
}

function rpcWith(responder: (method: string, params: unknown[]) => unknown) {
  const calls: { method: string; params: unknown[] }[] = [];
  return {
    calls,
    rpc: {
      call: async (method: string, params: unknown[]) => {
        calls.push({ method, params });
        return responder(method, params);
      },
    },
  };
}

describe("adapter × depin-msg (no hardware)", () => {
  beforeAll(async () => {
    const lib = await import("@neuraiproject/neurai-depin-msg");
    eciesRuntime = {
      deserializeEciesMessage: lib.deserializeEciesMessage as unknown as EciesRuntime["deserializeEciesMessage"],
      eciesDecrypt: lib.eciesDecrypt as unknown as EciesRuntime["eciesDecrypt"],
    };
  });

  it("runs challenge → receive → chaining with the device as the identity", async () => {
    const device = deviceMock(["receive"]);
    const identity = await createDepinDeviceIdentity(device, {
      token: TOKEN, expectedNetwork: "test",
    });

    const { rpc, calls } = rpcWith(async (method, params) => {
      if (method === "depinchallenge") {
        const [token, address, t, signature, type] = params as [
          string, string, number, string, string
        ];
        // The node's own check: the signed request must recover the holder key.
        expect(
          verifyRecoverableMessage(
            buildDepinRequestPreimage({ type: type as never, token, address, timestampMs: t }),
            signature,
            DEVICE_PUB_HEX
          )
        ).toBe(true);
        return boundReply("depinchallenge", token, address, "", {
          challenge: CHALLENGE, expires_in: 30, type: "receive",
        });
      }
      if (method === "depinreceivemsg") {
        const [token, address, challenge, signature] = params as [
          string, string, string, string
        ];
        expect(
          verifyRecoverableMessage(
            buildDepinGetPreimage({ token, address, challenge }), signature, DEVICE_PUB_HEX
          )
        ).toBe(true);
        return boundReply("depinreceivemsg", token, address, challenge, {
          messages: [], has_more: false,
          next_challenge: NEXT_CHALLENGE, next_expires_in: 300,
        });
      }
      throw new Error(`unexpected ${method}`);
    });

    const challenge = await requestDepinChallenge({
      rpc: rpc as never, identity: identity as never,
      token: TOKEN, poolPublicKey: POOL_PUB_HEX,
    });
    expect(challenge.challenge).toBe(CHALLENGE);

    const page = await receiveDepinMessages({
      rpc: rpc as never, identity: identity as never,
      token: TOKEN, challenge: challenge.challenge,
      poolPublicKey: POOL_PUB_HEX, network: "test",
    });
    expect(page.messages).toHaveLength(0);
    expect(page.nextChallenge).toBe(NEXT_CHALLENGE);

    // Chain without a new depinchallenge.
    const chained = await receiveDepinMessages({
      rpc: rpc as never, identity: identity as never,
      token: TOKEN, challenge: page.nextChallenge!,
      poolPublicKey: POOL_PUB_HEX, network: "test",
    });
    expect(chained.messages).toHaveLength(0);
    expect(calls.filter((c) => c.method === "depinchallenge")).toHaveLength(1);
  });

  it("publishes, submits, receives and decrypts through the device identity", async () => {
    const device = deviceMock(["receive", "publish"]);
    const identity = await createDepinDeviceIdentity(device, {
      token: TOKEN,
      expectedNetwork: "test",
      sessionPermissions: ["receive", "publish"],
    });
    let submittedHex = "";
    const { rpc } = rpcWith(async (method, params) => {
      if (method === "depingetancestorrecipients") {
        return plainReply(method, TOKEN, {
          token: TOKEN,
          stop_at: "&TEST",
          ancestors: [TOKEN, "&TEST"],
          recipients: [{ address: DEVICE_ADDRESS, pubkey: DEVICE_PUB_HEX }],
          returned: 1,
          max_results: 3,
          truncated: false,
          skipped_no_pubkey: 0,
          skipped_no_pubkey_complete: true,
          skipped_restricted: 0,
          skipped_restricted_complete: true,
        });
      }
      if (method === "depinsubmitmsg") {
        const envelope = params[0] as { encrypted: string };
        const opened = await eciesDecrypt(
          deserializeEciesMessage(Uint8Array.from(Buffer.from(envelope.encrypted, "hex"))) as never,
          Uint8Array.from(POOL_PRIV)
        );
        expect(opened).not.toBeNull();
        submittedHex = Buffer.from(opened!).toString("utf8");
        return boundReply(method, TOKEN, DEVICE_ADDRESS, "", {
          result: "success", hash: "ef".repeat(32), timestamp: 1753900001,
        });
      }
      if (method === "depinreceivemsg") {
        const parsed = await parseDepinMessage(submittedHex);
        return boundReply(method, TOKEN, DEVICE_ADDRESS, params[2] as string, {
          messages: [{
            hash: parsed.hash,
            token: parsed.token,
            sender: parsed.senderAddress,
            timestamp: parsed.timestamp,
            message_type: parsed.messageType,
            encrypted_payload_hex: parsed.encryptedPayloadHex,
            signature_hex: parsed.signatureHex,
          }],
          has_more: false,
          next_challenge: NEXT_CHALLENGE,
          next_expires_in: 300,
        });
      }
      throw new Error(`unexpected ${method}`);
    });

    const built = await buildDepinMessageForPool({
      rpc: rpc as never,
      identity: identity as never,
      token: TOKEN,
      poolRoot: "&TEST",
      maxRecipients: 2,
      poolPublicKey: POOL_PUB_HEX,
      network: "test",
      message: "hardware hello",
      messageType: "group",
      timestamp: 1753900000,
    });
    const receipt = await submitDepinMessage({
      rpc: rpc as never,
      identity: identity as never,
      messageHex: built.hex,
      poolPublicKey: POOL_PUB_HEX,
    });
    expect(receipt.result).toBe("success");

    const received = await receiveDepinMessages({
      rpc: rpc as never,
      identity: identity as never,
      token: TOKEN,
      challenge: CHALLENGE,
      poolPublicKey: POOL_PUB_HEX,
      network: "test",
      resolveSenderPubKey: async () => DEVICE_PUB_HEX,
    });
    expect(received.messages).toHaveLength(1);
    expect(received.messages[0]).toMatchObject({ ok: true, plaintext: "hardware hello" });
  });

  it("private section listing works through the device", async () => {
    const device = deviceMock(["receive"]);
    const identity = await createDepinDeviceIdentity(device, {
      token: TOKEN, expectedNetwork: "test",
    });
    const sections = [{ name: TOKEN, label: "Sec", depth: 1 }];
    const { rpc } = rpcWith(async (method, params) => {
      const [address, scope, challenge] = params as [string, string, string];
      return boundReply("depinlistsections", scope, address, challenge, {
        sections, next_challenge: NEXT_CHALLENGE, next_expires_in: 300,
      });
    });
    const result = await listDepinSectionsPrivate({
      rpc: rpc as never, identity: identity as never,
      scope: TOKEN, challenge: CHALLENGE, poolPublicKey: POOL_PUB_HEX,
    });
    expect(result.sections).toEqual(sections);
  });

  it("a receive-only device cannot purge, and the flow stops before the RPC", async () => {
    const device = deviceMock(["receive"]);
    const identity = await createDepinDeviceIdentity(device, {
      token: TOKEN, expectedNetwork: "test",
    });
    const { rpc, calls } = rpcWith(() => {
      throw new Error("the RPC must never be reached");
    });

    await expect(
      clearDepinMessages({
        rpc: rpc as never, identity: identity as never,
        scope: TOKEN, poolRoot: "&TEST", challenge: CHALLENGE,
        poolPublicKey: POOL_PUB_HEX, mode: "all",
      })
    ).rejects.toMatchObject({ code: "SESSION_PERMISSION_INSUFFICIENT" });
    expect(calls).toHaveLength(0);
  });

  it("an admin device can purge", async () => {
    const device = deviceMock(["admin"]);
    const identity = await createDepinDeviceIdentity(device, {
      token: TOKEN, expectedNetwork: "test", sessionPermissions: ["admin"],
    });
    const { rpc } = rpcWith(async (method, params) => {
      const [, address, challenge] = params as [string, string, string];
      return boundReply("depinclearmsg", TOKEN, address, challenge, {
        removed: 3, remaining: 0,
      });
    });
    const result = await clearDepinMessages({
      rpc: rpc as never, identity: identity as never,
      scope: TOKEN, poolRoot: "&TEST", challenge: CHALLENGE,
      poolPublicKey: POOL_PUB_HEX, mode: "all",
    });
    expect(result).toMatchObject({ removed: 3 });
  });

  it("a tampered reply is rejected before the device is asked to decrypt", async () => {
    const device = deviceMock(["receive"]);
    const identity = await createDepinDeviceIdentity(device, {
      token: TOKEN, expectedNetwork: "test",
    });
    let decryptCalls = 0;
    const spied = {
      ...identity,
      openReply: async (hex: string) => {
        decryptCalls += 1;
        return identity.openReply(hex);
      },
    };
    const { rpc } = rpcWith(async (method, params) => {
      const [token, address] = params as [string, string];
      const reply = await boundReply("depinchallenge", token, address, "", {
        challenge: CHALLENGE, expires_in: 30, type: "receive",
      });
      // A hostile proxy flips one byte of the envelope.
      const bytes = Buffer.from(reply.encrypted, "hex");
      bytes[bytes.length - 1] ^= 0x01;
      return { ...reply, encrypted: bytes.toString("hex") };
    });

    await expect(
      requestDepinChallenge({
        rpc: rpc as never, identity: spied as never,
        token: TOKEN, poolPublicKey: POOL_PUB_HEX,
      })
    ).rejects.toMatchObject({ code: "DEPIN_REPLY_AUTH" });
    expect(decryptCalls).toBe(0);
  });
});
