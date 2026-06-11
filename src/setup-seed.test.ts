import { describe, expect, it } from "vitest";
import { NeuraiESP32 } from "./NeuraiESP32.js";
import type { DeviceResponse, INeuraiTransport } from "./types.js";

const VALID_12 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/**
 * Transport double: replies to each command from a scripted queue and records
 * what was sent, so the tests can assert the exact wire payloads.
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

describe("setupSeed", () => {
  it("sends the setup_seed command and resolves on pin_required", async () => {
    const { transport, sent } = createMockTransport([
      { status: "success", state: "pin_required" },
    ]);
    const device = new NeuraiESP32({ transport });

    const result = await device.setupSeed({
      mnemonic: VALID_12,
      network: "testnet",
      keyType: "pq",
    });

    expect(result.state).toBe("pin_required");
    expect(sent[0]).toEqual({
      action: "setup_seed",
      mnemonic: VALID_12,
      network: "testnet",
      key_type: "pq",
    });
  });

  it("normalizes whitespace before sending", async () => {
    const { transport, sent } = createMockTransport([
      { status: "success", state: "pin_required" },
    ]);
    const device = new NeuraiESP32({ transport });

    await device.setupSeed({
      mnemonic: `  ${VALID_12.replace(/ /g, "   ")}\t`,
      network: "testnet",
      keyType: "legacy",
    });

    expect((sent[0] as { mnemonic: string }).mnemonic).toBe(VALID_12);
  });

  it("rejects word counts other than 12/24 without touching the device", async () => {
    const { transport, sent } = createMockTransport([]);
    const device = new NeuraiESP32({ transport });

    await expect(
      device.setupSeed({
        mnemonic: "one two three",
        network: "testnet",
        keyType: "legacy",
      })
    ).rejects.toThrow("12 or 24 words");
    expect(sent).toHaveLength(0);
  });

  it("rejects pq on mainnet without touching the device", async () => {
    const { transport, sent } = createMockTransport([]);
    const device = new NeuraiESP32({ transport });

    await expect(
      device.setupSeed({
        mnemonic: VALID_12,
        network: "mainnet",
        keyType: "pq",
      })
    ).rejects.toThrow("requires testnet");
    expect(sent).toHaveLength(0);
  });

  it("surfaces firmware errors (already configured, cancelled...)", async () => {
    const { transport } = createMockTransport([
      {
        status: "error",
        message: "Device already configured: wipe it on-device first",
      },
    ]);
    const device = new NeuraiESP32({ transport });

    await expect(
      device.setupSeed({
        mnemonic: VALID_12,
        network: "testnet",
        keyType: "legacy",
      })
    ).rejects.toThrow("already configured");
  });
});

describe("getDeviceState", () => {
  it("maps ping success to ready", async () => {
    const { transport } = createMockTransport([
      {
        status: "success",
        device: "NeuraiHW",
        version: "0.1.0",
        firmware_version: "1.1.0",
        chip: "ESP32-S3",
      },
    ]);
    const device = new NeuraiESP32({ transport });
    expect(await device.getDeviceState()).toBe("ready");
  });

  it("maps the gate errors to locked / unconfigured", async () => {
    const { transport } = createMockTransport([
      { status: "error", message: "Device locked: enter PIN on device" },
      {
        status: "error",
        message: "Device not configured: use setup_seed or set up on device",
      },
    ]);
    const device = new NeuraiESP32({ transport });
    expect(await device.getDeviceState()).toBe("locked");
    expect(await device.getDeviceState()).toBe("unconfigured");
  });

  it("rethrows unrelated errors", async () => {
    const { transport } = createMockTransport([
      { status: "error", message: "Unknown action" },
    ]);
    const device = new NeuraiESP32({ transport });
    await expect(device.getDeviceState()).rejects.toThrow("Unknown action");
  });
});

describe("waitUntilReady", () => {
  it("polls until the device reports ready", async () => {
    const { transport, sent } = createMockTransport([
      {
        status: "error",
        message: "Device not configured: use setup_seed or set up on device",
      },
      { status: "error", message: "Device not configured: use setup_seed or set up on device" },
      {
        status: "success",
        device: "NeuraiHW",
        version: "0.1.0",
        firmware_version: "1.1.0",
        chip: "ESP32-S3",
      },
    ]);
    const device = new NeuraiESP32({ transport });

    const state = await device.waitUntilReady({ pollMs: 1, timeoutMs: 1000 });
    expect(state).toBe("ready");
    expect(sent).toHaveLength(3);
  });

  it("throws on timeout with the last state", async () => {
    const lockedReply = {
      status: "error",
      message: "Device locked: enter PIN on device",
    } as DeviceResponse;
    const { transport } = createMockTransport(
      Array.from({ length: 50 }, () => lockedReply)
    );
    const device = new NeuraiESP32({ transport });

    await expect(
      device.waitUntilReady({ pollMs: 1, timeoutMs: 5 })
    ).rejects.toThrow("last state: locked");
  });
});
