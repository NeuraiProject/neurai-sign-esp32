import { describe, expect, it } from "vitest";
import { NeuraiESP32 } from "./NeuraiESP32.js";
import type { DeviceResponse, INeuraiTransport } from "./types.js";

/**
 * Transport double: replies to each command from a scripted queue and records
 * what was sent, so the tests can assert the exact wire payloads. Mirrors the
 * helper in setup-seed.test.ts.
 */
function createMockTransport(replies: DeviceResponse[]) {
  const sent: Record<string, unknown>[] = [];
  const queue = [...replies];

  const transport: INeuraiTransport = {
    connected: true,
    async open() {},
    async close() {},
    async sendCommand(command) {
      sent.push(command);
      const next = queue.shift();
      if (!next) throw new Error("Mock transport: no scripted reply left");
      return next;
    },
    async sendCommandFinal(command) {
      return this.sendCommand(command);
    },
    async sendCommandHeartbeat(command) {
      return this.sendCommand(command);
    },
  };

  return { transport, sent };
}

const TOKEN = "&NEURAI.CHAT";
const ADDRESS = "n1depinaddressxxxxxxxxxxxxxxxxxxxxx";
const PUBKEY = "02" + "ab".repeat(32); // 33-byte compressed pubkey, hex

describe("depinSessionBegin", () => {
  it("sends only action+token when no options are given", async () => {
    const { transport, sent } = createMockTransport([
      {
        status: "success",
        session: true,
        token: TOKEN,
        expires_in_s: 900,
        max_session_s: 3600,
        rate_per_min: 100,
        protocol_version: 1,
      },
    ]);
    const device = new NeuraiESP32({ transport });

    const res = await device.depinSessionBegin(TOKEN);

    expect(res.session).toBe(true);
    expect(res.token).toBe(TOKEN);
    expect(res.rate_per_min).toBe(100);
    // No ttl_minutes / rate_per_min keys unless explicitly requested.
    expect(sent[0]).toEqual({ action: "depin_session_begin", token: TOKEN });
  });

  it("forwards ttlMinutes and ratePerMin as snake_case fields", async () => {
    const { transport, sent } = createMockTransport([
      {
        status: "success",
        session: true,
        token: TOKEN,
        expires_in_s: 300,
        max_session_s: 3600,
        rate_per_min: 30,
        protocol_version: 1,
      },
    ]);
    const device = new NeuraiESP32({ transport });

    await device.depinSessionBegin(TOKEN, { ttlMinutes: 5, ratePerMin: 30 });

    expect(sent[0]).toEqual({
      action: "depin_session_begin",
      token: TOKEN,
      ttl_minutes: 5,
      rate_per_min: 30,
    });
  });

  it("surfaces a declined approval as an error", async () => {
    const { transport } = createMockTransport([
      { status: "error", message: "user_declined" },
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(device.depinSessionBegin(TOKEN)).rejects.toThrow("user_declined");
  });
});

describe("getDepinIdentity", () => {
  it("sends get_depin_identity and returns the identity", async () => {
    const { transport, sent } = createMockTransport([
      {
        status: "success",
        address: ADDRESS,
        pubkey: PUBKEY,
        path: "m/44'/1'/100'/0/0",
        network: "xna-test",
        protocol_version: 1,
      },
    ]);
    const device = new NeuraiESP32({ transport });

    const id = await device.getDepinIdentity();

    expect(id.address).toBe(ADDRESS);
    expect(id.pubkey).toBe(PUBKEY);
    expect(id.path).toBe("m/44'/1'/100'/0/0");
    expect(id.network).toBe("xna-test");
    expect(sent[0]).toEqual({ action: "get_depin_identity" });
  });

  it("surfaces session_required when no session is open", async () => {
    const { transport } = createMockTransport([
      { status: "error", message: "session_required" },
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(device.getDepinIdentity()).rejects.toThrow("session_required");
  });
});

describe("depinSign", () => {
  it("maps the structured params to the exact wire fields", async () => {
    const { transport, sent } = createMockTransport([
      { status: "success", signature: "30440220deadbeef", op_count: 1 },
    ]);
    const device = new NeuraiESP32({ transport });

    const res = await device.depinSign({
      token: TOKEN,
      sender: ADDRESS,
      timestamp: 1_700_000_000,
      messageType: 1,
      encryptedPayload: "0badc0de",
    });

    expect(res.signature).toBe("30440220deadbeef");
    expect(res.op_count).toBe(1);
    expect(sent[0]).toEqual({
      action: "depin_sign",
      token: TOKEN,
      sender: ADDRESS,
      timestamp: 1_700_000_000,
      message_type: 1,
      encrypted_payload: "0badc0de",
    });
  });

  it("surfaces the rate limit as an error", async () => {
    const { transport } = createMockTransport([
      { status: "error", message: "rate_limited" },
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(
      device.depinSign({
        token: TOKEN,
        sender: ADDRESS,
        timestamp: 1,
        messageType: 2,
        encryptedPayload: "00",
      })
    ).rejects.toThrow("rate_limited");
  });

  it("surfaces a wrong sender/token scope rejection", async () => {
    const { transport } = createMockTransport([
      { status: "error", message: "wrong_sender" },
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(
      device.depinSign({
        token: TOKEN,
        sender: "someone-elses-address",
        timestamp: 1,
        messageType: 1,
        encryptedPayload: "00",
      })
    ).rejects.toThrow("wrong_sender");
  });
});

describe("depinDecrypt", () => {
  it("uses Base64 when the firmware advertises bulk DePIN decrypt", async () => {
    const { transport, sent } = createMockTransport([
      {
        status: "success",
        device: "NeuraiHW",
        version: "0.5.11",
        firmware_version: "0.5.11",
        chip: "ESP32",
        capabilities: ["depin_message", "depin_bulk_decrypt_b64"],
        depin_max_decrypt_bytes: 32768,
      },
      { status: "success", plaintext_b64: "aGVsbG8=", op_count: 2 },
    ]);
    const device = new NeuraiESP32({ transport });

    const res = await device.depinDecrypt("deadbeefcafe");

    expect(res.plaintext_b64).toBe("aGVsbG8=");
    expect(res.op_count).toBe(2);
    expect(sent[0]).toEqual({ action: "ping" });
    expect(sent[1]).toEqual({
      action: "depin_decrypt",
      depin_message_b64: "3q2+78r+",
    });
  });

  it("surfaces not_for_us when this identity is not a recipient", async () => {
    const { transport } = createMockTransport([
      {
        status: "success",
        device: "NeuraiHW",
        version: "0.5.10",
        firmware_version: "0.5.10",
        chip: "ESP32",
      },
      { status: "error", message: "not_for_us" },
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(device.depinDecrypt("00")).rejects.toThrow("not_for_us");
  });
});

describe("depinDecryptPayload", () => {
  it("uses Base64 and the advertised byte limit for a bare ECIES payload", async () => {
    const { transport, sent } = createMockTransport([
      {
        status: "success",
        device: "NeuraiHW",
        version: "0.5.11",
        firmware_version: "0.5.11",
        chip: "ESP32",
        capabilities: ["depin_message", "depin_bulk_decrypt_b64"],
        depin_max_decrypt_bytes: 32768,
      },
      { status: "success", plaintext_b64: "aGk=", op_count: 3 },
    ]);
    const device = new NeuraiESP32({ transport });

    const res = await device.depinDecryptPayload("cafebabe");

    expect(res.plaintext_b64).toBe("aGk=");
    expect(res.op_count).toBe(3);
    expect(sent[0]).toEqual({ action: "ping" });
    expect(sent[1]).toEqual({
      action: "depin_decrypt_payload",
      encrypted_payload_b64: "yv66vg==",
    });
  });

  it("rejects locally when the decoded payload exceeds the advertised limit", async () => {
    const { transport, sent } = createMockTransport([
      {
        status: "success",
        device: "NeuraiHW",
        version: "0.5.11",
        firmware_version: "0.5.11",
        chip: "ESP32",
        capabilities: ["depin_bulk_decrypt_b64"],
        depin_max_decrypt_bytes: 4,
      },
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(device.depinDecryptPayload("00".repeat(5))).rejects.toThrow(
      "accepts at most 4 bytes"
    );
    expect(sent).toEqual([{ action: "ping" }]);
  });

  it("keeps the hex field for firmware without the Base64 capability", async () => {
    const { transport, sent } = createMockTransport([
      {
        status: "success",
        device: "NeuraiHW",
        version: "0.5.10",
        firmware_version: "0.5.10",
        chip: "ESP32",
      },
      { status: "success", plaintext_b64: "aGk=", op_count: 3 },
    ]);
    const device = new NeuraiESP32({ transport });

    await device.depinDecryptPayload("cafebabe");

    expect(sent[1]).toEqual({
      action: "depin_decrypt_payload",
      encrypted_payload: "cafebabe",
    });
  });

  it("surfaces not_for_us when this identity is not a recipient", async () => {
    const { transport } = createMockTransport([
      {
        status: "success",
        device: "NeuraiHW",
        version: "0.5.10",
        firmware_version: "0.5.10",
        chip: "ESP32",
      },
      { status: "error", message: "not_for_us" },
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(device.depinDecryptPayload("00")).rejects.toThrow("not_for_us");
  });
});

describe("depinSignDigest", () => {
  it("sends the digest and returns the DER signature + pubkey", async () => {
    const { transport, sent } = createMockTransport([
      { status: "success", signature: "3044021f00", pubkey: PUBKEY },
    ]);
    const device = new NeuraiESP32({ transport });

    const res = await device.depinSignDigest("ab".repeat(32));

    expect(res.signature).toBe("3044021f00");
    expect(res.pubkey).toBe(PUBKEY);
    expect(sent[0]).toEqual({ action: "depin_sign_digest", digest: "ab".repeat(32) });
  });

  it("surfaces a declined confirmation", async () => {
    const { transport } = createMockTransport([
      { status: "error", message: "user_declined" },
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(device.depinSignDigest("00".repeat(32))).rejects.toThrow("user_declined");
  });
});

describe("depinSessionEnd", () => {
  it("sends depin_session_end and resolves on success", async () => {
    const { transport, sent } = createMockTransport([
      { status: "success" } as DeviceResponse,
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(device.depinSessionEnd()).resolves.toBeUndefined();
    expect(sent[0]).toEqual({ action: "depin_session_end" });
  });
});

describe("session capability key (proto v2)", () => {
  const SKEY = "00112233445566778899aabbccddeeff";
  const beginReply = {
    status: "success",
    session: true,
    token: TOKEN,
    session_key: SKEY,
    expires_in_s: 900,
    max_session_s: 3600,
    rate_per_min: 100,
    protocol_version: 2,
  };

  it("caches the key from begin and auto-attaches it to session ops", async () => {
    // depinSign and getDepinIdentity issue no internal ping, so the queue maps
    // 1:1 to the calls. depin_decrypt* attaches the same `session_key` spread.
    const { transport, sent } = createMockTransport([
      beginReply,
      { status: "success", signature: "30", op_count: 1 },
      { status: "success", address: ADDRESS, pubkey: PUBKEY, path: "m/44'/1'/100'/0/0", network: "xna-test", protocol_version: 2 },
    ]);
    const device = new NeuraiESP32({ transport });

    const begin = await device.depinSessionBegin(TOKEN);
    expect(begin.session_key).toBe(SKEY);
    expect(device.getDepinSessionKey()).toBe(SKEY);
    expect(sent[0].session_key).toBeUndefined(); // begin itself doesn't send it

    await device.depinSign({ token: TOKEN, sender: ADDRESS, timestamp: 1, messageType: 1, encryptedPayload: "00" });
    await device.getDepinIdentity();

    expect(sent[1].session_key).toBe(SKEY);
    expect(sent[2].session_key).toBe(SKEY);
  });

  it("does not attach a key when none is cached (proto v1 firmware)", async () => {
    const { transport, sent } = createMockTransport([
      { status: "success", address: ADDRESS, pubkey: PUBKEY, path: "m/44'/1'/100'/0/0", network: "xna-test", protocol_version: 1 },
    ]);
    const device = new NeuraiESP32({ transport });

    await device.getDepinIdentity();
    expect(sent[0]).toEqual({ action: "get_depin_identity" });
  });

  it("depinSessionStatus reports active and keeps the key", async () => {
    const { transport, sent } = createMockTransport([
      beginReply,
      { status: "success", active: true, token: TOKEN, expires_in_s: 800, permissions: ["receive"] },
    ]);
    const device = new NeuraiESP32({ transport });
    await device.depinSessionBegin(TOKEN);

    const st = await device.depinSessionStatus();
    expect(st.active).toBe(true);
    expect(st.token).toBe(TOKEN);
    expect(sent[1]).toEqual({ action: "depin_session_status", session_key: SKEY });
    expect(device.getDepinSessionKey()).toBe(SKEY);
  });

  it("depinSessionStatus clears the cached key when inactive", async () => {
    const { transport } = createMockTransport([
      beginReply,
      { status: "success", active: false },
    ]);
    const device = new NeuraiESP32({ transport });
    await device.depinSessionBegin(TOKEN);

    const st = await device.depinSessionStatus();
    expect(st.active).toBe(false);
    expect(device.getDepinSessionKey()).toBeNull();
  });

  it("setDepinSessionKey restores a persisted key for a fresh instance", async () => {
    const { transport, sent } = createMockTransport([
      { status: "success", active: true, token: TOKEN, expires_in_s: 500, permissions: ["receive"] },
    ]);
    const device = new NeuraiESP32({ transport });
    device.setDepinSessionKey(SKEY);

    await device.depinSessionStatus();
    expect(sent[0]).toEqual({ action: "depin_session_status", session_key: SKEY });
  });

  it("depinSessionEnd sends the key and forgets it locally", async () => {
    const { transport, sent } = createMockTransport([
      beginReply,
      { status: "success" } as DeviceResponse,
    ]);
    const device = new NeuraiESP32({ transport });
    await device.depinSessionBegin(TOKEN);

    await device.depinSessionEnd();
    expect(sent[1]).toEqual({ action: "depin_session_end", session_key: SKEY });
    expect(device.getDepinSessionKey()).toBeNull();
  });
});
