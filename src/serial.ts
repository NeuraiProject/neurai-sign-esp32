/**
 * Web Serial API communication layer for ESP32 hardware wallet.
 *
 * Handles USB Serial connection, JSON command/response protocol,
 * and line-based buffering matching the NeuraiHW firmware protocol.
 */

import type { DeviceResponse, ISerialOptions } from "./types.js";

// Default USB filters for ESP32 devices
const DEFAULT_FILTERS: SerialPortFilter[] = [
  { usbVendorId: 0x303a, usbProductId: 0x1001 }, // ESP32-S3 USB JTAG/Serial
  { usbVendorId: 0x303a },                         // Espressif generic
  { usbVendorId: 0x10c4, usbProductId: 0xea60 },  // Silicon Labs CP210x
  { usbVendorId: 0x1a86, usbProductId: 0x7523 },  // CH340
  { usbVendorId: 0x0403, usbProductId: 0x6001 },  // FTDI FT232
  { usbVendorId: 0x067b, usbProductId: 0x2303 },  // Prolific PL2303
  { usbVendorId: 0x2886 },                         // Seeed Studio (XIAO)
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

  /**
   * Check if Web Serial API is available.
   */
  static isSupported(): boolean {
    return typeof navigator !== "undefined" && "serial" in navigator;
  }

  /**
   * Open a serial connection to the ESP32.
   * Triggers browser port selection dialog.
   */
  async open(): Promise<void> {
    if (!SerialConnection.isSupported()) {
      throw new Error(
        "Web Serial API not supported. Use Chrome, Edge, or Opera."
      );
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

    // Set up readable stream (text decoding)
    const decoder = new TextDecoderStream();
    this.readableStreamClosed = this.port.readable!.pipeTo(decoder.writable as unknown as WritableStream<Uint8Array>);
    this.reader = decoder.readable.getReader();

    // Set up writable stream (text encoding)
    const encoder = new TextEncoderStream();
    this.writableStreamClosed = encoder.readable.pipeTo(this.port.writable!);
    this.writer = encoder.writable.getWriter();

    // Start background read loop
    this.isReading = true;
    void this.readLoop();

    // Give the ESP32 CDC port time to settle after connect/re-enumeration.
    await this.delay(1200);
    this.responseQueue = [];
  }

  /**
   * Close the serial connection.
   */
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

  /**
   * Whether the serial port is currently connected.
   */
  get connected(): boolean {
    return this.port !== null && this.writer !== null;
  }

  /**
   * Send a JSON command to the device and wait for a JSON response.
   *
   * @param command - The command object (e.g. { action: "info" })
   * @param timeoutMs - Response timeout in milliseconds (default: 65000 for sign operations)
   * @returns The parsed device response
   */
  async sendCommand(
    command: Record<string, unknown>,
    timeoutMs = 65000
  ): Promise<DeviceResponse> {
    if (!this.writer) {
      throw new Error("Serial port not connected");
    }

    // Clear stale responses
    this.responseQueue = [];

    // Send JSON in small chunks, then newline to trigger processing.
    // The ESP32 CDC serial buffer can lose data if sent too fast in one write.
    const json = JSON.stringify(command);
    await this.writeChunked(json);
    await this.writer.ready;
    await this.writer.write("\n");

    // Wait for response
    const response = await this.waitForResponse(timeoutMs);
    if (!response) {
      throw new Error("Device response timeout");
    }

    return response;
  }

  /**
   * Send a command and wait, skipping intermediate "processing" status messages.
   * Useful for sign_psbt which sends a processing ACK before the actual response.
   */
  async sendCommandFinal(
    command: Record<string, unknown>,
    timeoutMs = 65000
  ): Promise<DeviceResponse> {
    if (!this.writer) {
      throw new Error("Serial port not connected");
    }

    this.responseQueue = [];

    const json = JSON.stringify(command);
    await this.writeChunked(json);
    await this.writer.ready;
    await this.writer.write("\n");

    // Wait for a non-processing response
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      const response = await this.waitForResponse(
        timeoutMs - (Date.now() - startTime)
      );
      if (!response) {
        throw new Error("Device response timeout");
      }
      // Skip intermediate "processing" status
      if (response.status === "processing") {
        continue;
      }
      return response;
    }

    throw new Error("Device response timeout");
  }

  // ─── Private ──────────────────────────────────────────────────────────────

  private async readLoop(): Promise<void> {
    let buffer = "";

    while (this.isReading && this.reader) {
      try {
        const { value, done } = await this.reader.read();
        if (done) break;

        buffer += value;

        // Process complete lines
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? ""; // Keep incomplete line in buffer

        for (const rawLine of lines) {
          const line = rawLine.trim().replace(/\r/g, "");
          if (line.length === 0) continue;

          // Try to parse as JSON response
          if (line.startsWith("{")) {
            try {
              const data = JSON.parse(line) as DeviceResponse;
              this.responseQueue.push(data);
            } catch {
              // Not valid JSON — debug output from firmware, ignore
            }
          }
          // Non-JSON lines are firmware debug output, ignored
        }
      } catch {
        // Read error — connection may have been closed
        break;
      }
    }
  }

  private waitForResponse(timeoutMs: number): Promise<DeviceResponse | null> {
    return new Promise((resolve) => {
      const startTime = Date.now();
      const check = () => {
        if (this.responseQueue.length > 0) {
          resolve(this.responseQueue.shift()!);
        } else if (Date.now() - startTime > timeoutMs) {
          resolve(null);
        } else {
          setTimeout(check, 50);
        }
      };
      check();
    });
  }

  /**
   * Write data in small chunks with pauses between them.
   *
   * The ESP32 CDC serial buffer can lose data when the host sends a large
   * payload in a single write. Splitting into 32-byte chunks with a 4 ms
   * pause gives the firmware time to drain its receive buffer.
   */
  private async writeChunked(
    data: string,
    chunkSize = 32,
    pauseMs = 4
  ): Promise<void> {
    if (!this.writer) {
      throw new Error("Serial port not connected");
    }

    for (let offset = 0; offset < data.length; offset += chunkSize) {
      const chunk = data.slice(offset, offset + chunkSize);
      await this.writer.ready;
      await this.writer.write(chunk);
      if (offset + chunkSize < data.length) {
        await this.delay(pauseMs);
      }
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
