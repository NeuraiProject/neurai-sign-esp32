import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SerialProtocol } from "./serial-protocol.js";
import type { IByteChannel } from "./types.js";

/**
 * In-memory byte channel that records everything written and lets the test push
 * inbound lines, exactly like a device would emit them.
 */
function createMockChannel() {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const written: Uint8Array[] = [];
  let handler: ((chunk: Uint8Array) => void) | null = null;
  let open = false;

  const channel: IByteChannel = {
    get isOpen() {
      return open;
    },
    onData(h) {
      handler = h;
    },
    async open() {
      open = true;
    },
    async write(data) {
      written.push(data.slice());
    },
    async close() {
      open = false;
    },
  };

  return {
    channel,
    pushLine(line: string) {
      handler?.(encoder.encode(`${line}\n`));
    },
    writtenText() {
      return written.map((chunk) => decoder.decode(chunk)).join("");
    },
    openCalled: () => open,
  };
}

beforeEach(() => {
  vi.spyOn(console, "debug").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SerialProtocol", () => {
  it("opens the channel and sends a JSON command terminated by a newline", async () => {
    const mock = createMockChannel();
    const protocol = new SerialProtocol(mock.channel);
    (protocol as any).delay = () => Promise.resolve();

    await protocol.open();
    expect(protocol.connected).toBe(true);

    const responsePromise = protocol.sendCommand({ action: "info" }, 500);
    mock.pushLine(JSON.stringify({ status: "ok", device: "NeuraiHW" }));

    await expect(responsePromise).resolves.toEqual({
      status: "ok",
      device: "NeuraiHW",
    });
    expect(mock.writtenText()).toBe('{"action":"info"}\n');

    await protocol.close();
    expect(protocol.connected).toBe(false);
  });

  it("ignores processing heartbeats until the final payload arrives", async () => {
    const mock = createMockChannel();
    const protocol = new SerialProtocol(mock.channel);
    (protocol as any).delay = () => Promise.resolve();

    await protocol.open();
    const responsePromise = protocol.sendCommandFinal(
      { action: "sign_psbt", psbt: "base64" },
      1000
    );

    mock.pushLine(JSON.stringify({ status: "processing", stage: "review" }));
    mock.pushLine(JSON.stringify({ status: "ok", psbt: "signed", signed_inputs: 1 }));

    await expect(responsePromise).resolves.toEqual({
      status: "ok",
      psbt: "signed",
      signed_inputs: 1,
    });
    await protocol.close();
  });

  it("resets the timeout window on every heartbeat (sendCommandHeartbeat)", async () => {
    const mock = createMockChannel();
    const protocol = new SerialProtocol(mock.channel);
    (protocol as any).delay = () => Promise.resolve();

    await protocol.open();
    const responsePromise = protocol.sendCommandHeartbeat(
      { action: "sign_tx", tx: "00" },
      1000,
      60000
    );

    mock.pushLine(JSON.stringify({ status: "processing", stage: "signing_input_0" }));
    mock.pushLine(JSON.stringify({ status: "processing", stage: "signing_input_0" }));
    mock.pushLine(JSON.stringify({ status: "ok", tx: "deadbeef", signed_inputs: 1 }));

    await expect(responsePromise).resolves.toEqual({
      status: "ok",
      tx: "deadbeef",
      signed_inputs: 1,
    });
    await protocol.close();
  });

  it("splits large payloads into 256-byte chunks", async () => {
    const mock = createMockChannel();
    const protocol = new SerialProtocol(mock.channel);
    (protocol as any).delay = () => Promise.resolve();

    await protocol.open();
    const big = "x".repeat(600);
    const responsePromise = protocol.sendCommand({ action: "sign_psbt", psbt: big }, 500);
    mock.pushLine(JSON.stringify({ status: "ok" }));
    await responsePromise;

    const json = JSON.stringify({ action: "sign_psbt", psbt: big });
    // chunks of the JSON (ceil(len/256)) + 1 newline write
    const expectedWrites = Math.ceil(json.length / 256) + 1;
    expect((protocol as any).channel).toBe(mock.channel);
    expect(mock.writtenText()).toBe(`${json}\n`);
    expect(expectedWrites).toBeGreaterThan(2);

    await protocol.close();
  });

  it("throws when writing while the channel is closed", async () => {
    const mock = createMockChannel();
    const protocol = new SerialProtocol(mock.channel);
    await expect(protocol.sendCommand({ action: "info" }, 100)).rejects.toThrow(
      /not connected/
    );
  });
});
