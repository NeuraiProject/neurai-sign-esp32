import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  NativeUsbByteChannel,
  base64ToBytes,
  bytesToBase64,
  type IUsbSerialDriver,
  type IUsbSerialPort,
} from "./react-native-usb.js";
import { SerialProtocol } from "../serial-protocol.js";

/** Fake native USB-serial module, à la react-native-usb-serialport-for-android. */
function createFakeUsbDriver() {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const written: Uint8Array[] = [];
  let receiveHandler: ((data: Uint8Array) => void) | null = null;
  let openCalls = 0;
  let closeCalls = 0;
  let removeCalls = 0;

  const port: IUsbSerialPort = {
    async write(data) {
      written.push(data.slice());
    },
    onReceive(handler) {
      receiveHandler = handler;
      return {
        remove() {
          removeCalls += 1;
          receiveHandler = null;
        },
      };
    },
    async close() {
      closeCalls += 1;
    },
  };

  const driver: IUsbSerialDriver = {
    async open() {
      openCalls += 1;
      return port;
    },
  };

  return {
    driver,
    pushLine(line: string) {
      receiveHandler?.(encoder.encode(`${line}\n`));
    },
    writtenText: () => written.map((c) => decoder.decode(c)).join(""),
    stats: () => ({ openCalls, closeCalls, removeCalls, subscribed: receiveHandler !== null }),
  };
}

beforeEach(() => {
  vi.spyOn(console, "debug").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("NativeUsbByteChannel", () => {
  it("opens via the driver and reports isOpen", async () => {
    const fake = createFakeUsbDriver();
    const channel = new NativeUsbByteChannel(fake.driver);
    expect(channel.isOpen).toBe(false);

    channel.onData(() => {});
    await channel.open();

    expect(channel.isOpen).toBe(true);
    expect(fake.stats().openCalls).toBe(1);
    expect(fake.stats().subscribed).toBe(true);
  });

  it("drives a full command/response round-trip through SerialProtocol", async () => {
    const fake = createFakeUsbDriver();
    const channel = new NativeUsbByteChannel(fake.driver, { baudRate: 115200 });
    const protocol = new SerialProtocol(channel);
    (protocol as any).delay = () => Promise.resolve();

    await protocol.open();
    const responsePromise = protocol.sendCommand({ action: "info" }, 500);
    fake.pushLine(JSON.stringify({ status: "ok", device: "NeuraiHW" }));

    await expect(responsePromise).resolves.toEqual({ status: "ok", device: "NeuraiHW" });
    expect(fake.writtenText()).toBe('{"action":"info"}\n');

    await protocol.close();
    expect(channel.isOpen).toBe(false);
    expect(fake.stats().closeCalls).toBe(1);
    expect(fake.stats().removeCalls).toBe(1);
  });

  it("round-trips base64 helpers", () => {
    const bytes = new Uint8Array([0, 1, 2, 255, 128]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });
});
