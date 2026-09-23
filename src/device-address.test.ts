import { describe, expect, it } from "vitest";
import { NeuraiESP32 } from "./NeuraiESP32.js";
import type { DeviceResponse, INeuraiTransport } from "./types.js";
import {
  ORACLE_PQ_ADDRESS_TESTNET,
  ORACLE_PQ_ADDRESS_TESTNET_OLD,
  ORACLE_PQ_COMMITMENT_HEX,
  ORACLE_PQ_PUBKEY_HEX,
  ORACLE_PQ_V2_ADDRESS_TESTNET,
  ORACLE_PQ_V2_COMMITMENT_HEX,
} from "./pq-address.fixtures.js";

function deviceWith(replies: DeviceResponse[]) {
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
  return { device: new NeuraiESP32({ transport }), sent };
}

const PQ_PATH = "m_pq/100'/1'/0'/0'/0'";

describe("getAddress (PQ mode)", () => {
  it("reads the firmware's snake_case fields and derives the tnc1p… address", async () => {
    // Exactly what NeuraiHW Protocol.cpp handleGetAddress sends in PQ mode.
    const { device } = deviceWith([
      {
        status: "success",
        type: "pq",
        pubkey: ORACLE_PQ_PUBKEY_HEX,
        path: PQ_PATH,
        auth_type: 1,
        witness_script: "51",
      } as DeviceResponse,
    ]);
    const res = await device.getAddress();
    expect(res.address).toBe(ORACLE_PQ_ADDRESS_TESTNET);
    expect(res.authType).toBe(1);
    expect(res.witnessScript).toBe("51");
    expect(res.witnessVersion).toBe(1);
    expect(res.commitment).toBe(ORACLE_PQ_COMMITMENT_HEX);
  });

  it("uses a non-default witness_script sent in snake_case", async () => {
    const { device } = deviceWith([
      {
        status: "success",
        type: "pq",
        pubkey: ORACLE_PQ_PUBKEY_HEX,
        path: PQ_PATH,
        auth_type: 1,
        witness_script: "52",
      } as DeviceResponse,
    ]);
    const res = await device.getAddress();
    expect(res.witnessScript).toBe("52");
    expect(res.address).not.toBe(ORACLE_PQ_ADDRESS_TESTNET);
    expect(res.address.startsWith("tnc1p")).toBe(true);
  });

  it("still accepts camelCase fields", async () => {
    const { device } = deviceWith([
      {
        status: "success",
        type: "pq",
        pubkey: ORACLE_PQ_PUBKEY_HEX,
        path: PQ_PATH,
        authType: 1,
        witnessScript: "51",
      } as DeviceResponse,
    ]);
    expect((await device.getAddress()).address).toBe(ORACLE_PQ_ADDRESS_TESTNET);
  });

  it("derives the strict pq1z… address when the device reports witness_version 2", async () => {
    const { device } = deviceWith([
      {
        status: "success",
        type: "pq",
        pubkey: ORACLE_PQ_PUBKEY_HEX,
        path: PQ_PATH,
        auth_type: 1,
        witness_script: "51",
        witness_version: 2,
      } as DeviceResponse,
    ]);
    const res = await device.getAddress();
    expect(res.address).toBe(ORACLE_PQ_V2_ADDRESS_TESTNET);
    expect(res.commitment).toBe(ORACLE_PQ_V2_COMMITMENT_HEX);
  });

  it("rejects an unknown auth type", async () => {
    const { device } = deviceWith([
      { status: "success", type: "pq", pubkey: ORACLE_PQ_PUBKEY_HEX, path: PQ_PATH, auth_type: 2 } as DeviceResponse,
    ]);
    await expect(device.getAddress()).rejects.toThrow(/auth type 2/);
  });

  it("re-encodes an address reported by pre-0.2.0 firmware", async () => {
    const { device } = deviceWith([
      {
        status: "success",
        type: "pq",
        address: ORACLE_PQ_ADDRESS_TESTNET_OLD,
        pubkey: ORACLE_PQ_PUBKEY_HEX,
        path: PQ_PATH,
      } as DeviceResponse,
    ]);
    expect((await device.getAddress()).address).toBe(ORACLE_PQ_ADDRESS_TESTNET);
  });
});

describe("getInfo", () => {
  it("re-encodes the tnq1p… address of pre-0.2.0 PQ firmware", async () => {
    const { device } = deviceWith([
      {
        status: "success",
        device: "NeuraiHW",
        version: "1.0.0",
        chip: "ESP32-S3",
        network: "NeuraiTest",
        key_type: "pq",
        coin_type: 1,
        master_fingerprint: "deadbeef",
        path: PQ_PATH,
        address: ORACLE_PQ_ADDRESS_TESTNET_OLD,
        pubkey: ORACLE_PQ_PUBKEY_HEX,
      },
    ]);
    const info = await device.getInfo();
    expect(info.address).toBe(ORACLE_PQ_ADDRESS_TESTNET);
    expect(device.info?.address).toBe(ORACLE_PQ_ADDRESS_TESTNET);
  });

  it("leaves legacy addresses untouched", async () => {
    const { device } = deviceWith([
      {
        status: "success",
        device: "NeuraiHW",
        version: "1.0.0",
        chip: "ESP32-S3",
        network: "NeuraiTest",
        key_type: "legacy",
        coin_type: 1,
        master_fingerprint: "deadbeef",
        path: "m/44'/1'/0'/0/0",
        address: "tRATqx227pog5df6cWrgP9gecLr41mEw7u",
        pubkey: "03c686edd6a7df742a8bf13daf7d992c39ecc38ad2e503c67dc5c9177dc66db991",
      },
    ]);
    expect((await device.getInfo()).address).toBe("tRATqx227pog5df6cWrgP9gecLr41mEw7u");
  });
});

describe("signPqRawTransaction", () => {
  it("refuses strict prevouts before contacting the device", async () => {
    const { device, sent } = deviceWith([]);
    await expect(
      device.signPqRawTransaction({
        txHex: "02000000000000000000",
        inputs: [{ index: 0, amount: 1, script_pub_key: "5320" + "11".repeat(32) }],
      })
    ).rejects.toThrow(/witness v3 output/);
    expect(sent).toHaveLength(0);
  });
});
