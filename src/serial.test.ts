import { TextDecoder } from "util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SerialConnection } from "./serial.js";

type MockPort = {
  closeCalls: number;
  openCalls: number;
  port: SerialPort;
  pushLine: (line: string) => void;
  writtenText: () => string;
};

function createMockPort(): MockPort {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const writtenChunks: Uint8Array[] = [];
  let readableController: ReadableStreamDefaultController<Uint8Array> | null = null;

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      readableController = controller;
    },
  });

  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      writtenChunks.push(chunk.slice());
    },
  });

  let openCalls = 0;
  let closeCalls = 0;

  const port = {
    readable,
    writable,
    async open() {
      openCalls += 1;
    },
    async close() {
      closeCalls += 1;
    },
  } as unknown as SerialPort;

  return {
    closeCalls,
    openCalls,
    port,
    pushLine(line: string) {
      readableController?.enqueue(encoder.encode(`${line}\n`));
    },
    writtenText() {
      return writtenChunks.map((chunk) => decoder.decode(chunk)).join("");
    },
  };
}

function installMockSerial(port: SerialPort) {
  Object.defineProperty(navigator, "serial", {
    configurable: true,
    value: {
      requestPort: vi.fn().mockResolvedValue(port),
    },
  });
}

afterEach(() => {
  delete (navigator as Navigator & { serial?: Serial }).serial;
  vi.restoreAllMocks();
});

beforeEach(() => {
  vi.spyOn(console, "debug").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("SerialConnection", () => {
  it("detects Web Serial support", () => {
    installMockSerial({} as SerialPort);
    expect(SerialConnection.isSupported()).toBe(true);
  });

  it("opens the port and sends a JSON command terminated by a newline", async () => {
    const mockPort = createMockPort();
    installMockSerial(mockPort.port);

    const connection = new SerialConnection();
    (connection as any).delay = () => Promise.resolve();

    await connection.open();
    const responsePromise = connection.sendCommand({ action: "info" }, 500);
    mockPort.pushLine(JSON.stringify({ status: "ok", device: "NeuraiHW" }));

    await expect(responsePromise).resolves.toEqual({
      status: "ok",
      device: "NeuraiHW",
    });
    expect(connection.connected).toBe(true);
    expect(mockPort.writtenText()).toBe("{\"action\":\"info\"}\n");
    await connection.close();
  });

  it("ignores processing responses until the final payload arrives", async () => {
    const mockPort = createMockPort();
    installMockSerial(mockPort.port);

    const connection = new SerialConnection();
    (connection as any).delay = () => Promise.resolve();

    await connection.open();
    const responsePromise = connection.sendCommandFinal(
      { action: "sign_psbt", psbt: "base64" },
      1000
    );

    mockPort.pushLine(JSON.stringify({ status: "processing", stage: "review" }));
    mockPort.pushLine(JSON.stringify({ status: "ok", psbt: "signed", signed_inputs: 1 }));

    await expect(responsePromise).resolves.toEqual({
      status: "ok",
      psbt: "signed",
      signed_inputs: 1,
    });
    await connection.close();
  });

  it("throws if Web Serial is unavailable", async () => {
    delete (navigator as Navigator & { serial?: Serial }).serial;

    const connection = new SerialConnection();
    await expect(connection.open()).rejects.toThrow(/Web Serial API not supported/);
  });
});
