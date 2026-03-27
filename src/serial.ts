/**
 * Web Serial API communication layer for ESP32 hardware wallet.
 *
 * Handles USB Serial connection, JSON command/response protocol,
 * and line-based buffering matching the NeuraiHW firmware protocol.
 */

import type { DeviceResponse, ISerialOptions } from "./types.js";

const DEFAULT_FILTERS: SerialPortFilter[] = [
  { usbVendorId: 0x303a, usbProductId: 0x1001 },
  { usbVendorId: 0x303a },
  { usbVendorId: 0x10c4, usbProductId: 0xea60 },
  { usbVendorId: 0x1a86, usbProductId: 0x7523 },
  { usbVendorId: 0x0403, usbProductId: 0x6001 },
  { usbVendorId: 0x067b, usbProductId: 0x2303 },
  { usbVendorId: 0x2886 },
];

const DEFAULT_BAUD_RATE = 115200;

export class SerialConnection {
  private port: SerialPort | null = null;
  private reader: ReadableStreamDefaultReader<string> | null = null;
  private writer: WritableStreamDefaultWriter<string> | null = null;
  private readableStreamClosed: Promise<void> | null = null;
  private writableStreamClosed: Promise<void> | null = null;
  private isReading = false;
  private responseQueue: DeviceResponse[] = [];
  private baudRate: number;
  private filters: SerialPortFilter[];

  constructor(options?: ISerialOptions) {
    this.baudRate = options?.baudRate ?? DEFAULT_BAUD_RATE;
    this.filters = options?.filters ?? DEFAULT_FILTERS;
  }

  static isSupported(): boolean {
    return typeof navigator !== "undefined" && "serial" in navigator;
  }

  async open(): Promise<void> {
    if (!SerialConnection.isSupported()) {
      throw new Error("Web Serial API not supported. Use Chrome, Edge, or Opera.");
    }

    this.port = await navigator.serial.requestPort({ filters: this.filters });
    await this.port.open({
      baudRate: this.baudRate,
      dataBits: 8,
      stopBits: 1,
      parity: "none",
      flowControl: "none",
      bufferSize: 8192,
    });

    const decoder = new TextDecoderStream();
    this.readableStreamClosed = this.port.readable!.pipeTo(
      decoder.writable as unknown as WritableStream<Uint8Array>
    );
    this.reader = decoder.readable.getReader();

    const encoder = new TextEncoderStream();
    this.writableStreamClosed = encoder.readable.pipeTo(this.port.writable!);
    this.writer = encoder.writable.getWriter();

    this.isReading = true;
    void this.readLoop();

    await this.delay(1200);
    this.responseQueue = [];
  }

  async close(): Promise<void> {
    this.isReading = false;

    if (this.reader) {
      await this.reader.cancel();
      await this.readableStreamClosed?.catch(() => {});
      this.reader = null;
    }

    if (this.writer) {
      await this.writer.close();
      await this.writableStreamClosed;
      this.writer = null;
    }

    if (this.port) {
      await this.port.close();
      this.port = null;
    }

    this.responseQueue = [];
  }

  get connected(): boolean {
    return this.port !== null && this.writer !== null;
  }

  async sendCommand(command: Record<string, unknown>, timeoutMs = 65000): Promise<DeviceResponse> {
    if (!this.writer) {
      throw new Error("Serial port not connected");
    }

    this.responseQueue = [];

    const json = JSON.stringify(command);
    console.debug("[NeuraiESP32 Serial] Sending command", {
      action: command.action,
      payloadLength: json.length + 1,
      timeoutMs,
    });
    await this.writeChunked(json);
    await this.writer.ready;
    await this.writer.write("\n");

    const response = await this.waitForResponse(timeoutMs);
    if (!response) {
      throw new Error("Device response timeout");
    }

    return response;
  }

  async sendCommandFinal(command: Record<string, unknown>, timeoutMs = 65000): Promise<DeviceResponse> {
    if (!this.writer) {
      throw new Error("Serial port not connected");
    }

    this.responseQueue = [];

    const json = JSON.stringify(command);
    console.debug("[NeuraiESP32 Serial] Sending command", {
      action: command.action,
      payloadLength: json.length + 1,
      timeoutMs,
    });
    await this.writeChunked(json);
    await this.writer.ready;
    await this.writer.write("\n");

    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      const response = await this.waitForResponse(timeoutMs - (Date.now() - startTime));
      if (!response) {
        throw new Error("Device response timeout");
      }
      if (response.status === "processing") {
        continue;
      }
      return response;
    }

    throw new Error("Device response timeout");
  }

  private async readLoop(): Promise<void> {
    let buffer = "";

    while (this.isReading && this.reader) {
      try {
        const { value, done } = await this.reader.read();
        if (done) break;

        buffer += value;

        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const rawLine of lines) {
          const line = rawLine.trim().replace(/\r/g, "");
          if (line.length === 0) continue;

          if (line.startsWith("{")) {
            try {
              const data = JSON.parse(line) as DeviceResponse;
              console.debug("[NeuraiESP32 Serial] JSON line received", data);
              this.responseQueue.push(data);
            } catch {
              console.debug("[NeuraiESP32 Serial] Invalid JSON line", line);
            }
          } else {
            console.debug("[NeuraiESP32 Serial] Non-JSON serial line", line);
          }
        }
      } catch {
        break;
      }
    }
  }

  private waitForResponse(timeoutMs: number): Promise<DeviceResponse | null> {
    return new Promise((resolve) => {
      const startTime = Date.now();
      const check = () => {
        if (this.responseQueue.length > 0) {
          const response = this.responseQueue.shift()!;
          console.debug("[NeuraiESP32 Serial] Response dequeued", {
            waitedMs: Date.now() - startTime,
            pendingResponses: this.responseQueue.length,
            status: response.status,
          });
          resolve(response);
        } else if (Date.now() - startTime > timeoutMs) {
          console.error("[NeuraiESP32 Serial] Response timeout", {
            timeoutMs,
            queuedResponses: this.responseQueue.length,
          });
          resolve(null);
        } else {
          setTimeout(check, 50);
        }
      };
      check();
    });
  }

  private async writeChunked(data: string, chunkSize = 256, pauseMs = 8): Promise<void> {
    if (!this.writer) {
      throw new Error("Serial port not connected");
    }

    const totalChunks = Math.ceil(data.length / chunkSize);
    const startedAt = Date.now();
    let totalReadyMs = 0;
    let totalWriteMs = 0;
    let totalPauseMs = 0;

    console.debug("[NeuraiESP32 Serial][writeChunked] start", {
      totalBytes: data.length,
      chunkSize,
      pauseMs,
      totalChunks,
    });

    for (let offset = 0, chunkIndex = 0; offset < data.length; offset += chunkSize, chunkIndex += 1) {
      const chunk = data.slice(offset, offset + chunkSize);
      const readyStartedAt = Date.now();
      await this.writer.ready;
      const readyMs = Date.now() - readyStartedAt;
      totalReadyMs += readyMs;

      const writeStartedAt = Date.now();
      await this.writer.write(chunk);
      const writeMs = Date.now() - writeStartedAt;
      totalWriteMs += writeMs;

      let actualPauseMs = 0;
      if (pauseMs > 0 && offset + chunkSize < data.length) {
        const pauseStartedAt = Date.now();
        await this.delay(pauseMs);
        actualPauseMs = Date.now() - pauseStartedAt;
        totalPauseMs += actualPauseMs;
      }

      console.debug("[NeuraiESP32 Serial][writeChunked] chunk", {
        chunkIndex: chunkIndex + 1,
        totalChunks,
        chunkBytes: chunk.length,
        readyMs,
        writeMs,
        pauseMs: actualPauseMs,
      });
    }

    console.debug("[NeuraiESP32 Serial][writeChunked] complete", {
      totalBytes: data.length,
      totalChunks,
      totalMs: Date.now() - startedAt,
      totalReadyMs,
      totalWriteMs,
      totalPauseMs,
    });
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
