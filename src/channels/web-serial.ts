/**
 * Web Serial API byte channel for the ESP32 hardware wallet.
 *
 * This is the browser-specific half of the transport: it opens a USB serial
 * port via the Web Serial API and moves raw bytes. All protocol logic (chunked
 * writes, line buffering, JSON parsing, timeouts) lives in {@link SerialProtocol}.
 */

import type { IByteChannel, ISerialOptions, ISerialPortFilter } from "../types.js";

const DEFAULT_FILTERS: ISerialPortFilter[] = [
  { usbVendorId: 0x303a, usbProductId: 0x1001 },
  { usbVendorId: 0x303a },
  { usbVendorId: 0x10c4, usbProductId: 0xea60 },
  { usbVendorId: 0x1a86, usbProductId: 0x7523 },
  { usbVendorId: 0x0403, usbProductId: 0x6001 },
  { usbVendorId: 0x067b, usbProductId: 0x2303 },
  { usbVendorId: 0x2886 },
];

const DEFAULT_BAUD_RATE = 115200;

export class WebSerialByteChannel implements IByteChannel {
  private port: SerialPort | null = null;
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private handler: ((chunk: Uint8Array) => void) | null = null;
  private reading = false;
  private baudRate: number;
  private filters: ISerialPortFilter[];

  constructor(options?: ISerialOptions) {
    this.baudRate = options?.baudRate ?? DEFAULT_BAUD_RATE;
    this.filters = options?.filters ?? DEFAULT_FILTERS;
  }

  static isSupported(): boolean {
    return typeof navigator !== "undefined" && "serial" in navigator;
  }

  get isOpen(): boolean {
    return this.port !== null && this.writer !== null;
  }

  onData(handler: (chunk: Uint8Array) => void): void {
    this.handler = handler;
  }

  async open(): Promise<void> {
    if (!WebSerialByteChannel.isSupported()) {
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

    this.reader = this.port.readable!.getReader();
    this.writer = this.port.writable!.getWriter();

    this.reading = true;
    void this.readLoop();
  }

  async write(data: Uint8Array): Promise<void> {
    if (!this.writer) {
      throw new Error("Serial port not connected");
    }
    await this.writer.ready;
    await this.writer.write(data);
  }

  async close(): Promise<void> {
    this.reading = false;

    if (this.reader) {
      await this.reader.cancel().catch(() => {});
      try {
        this.reader.releaseLock();
      } catch {
        // already released
      }
      this.reader = null;
    }

    if (this.writer) {
      await this.writer.close().catch(() => {});
      this.writer = null;
    }

    if (this.port) {
      await this.port.close().catch(() => {});
      this.port = null;
    }
  }

  private async readLoop(): Promise<void> {
    while (this.reading && this.reader) {
      try {
        const { value, done } = await this.reader.read();
        if (done) break;
        if (value && value.length > 0) {
          this.handler?.(value);
        }
      } catch {
        break;
      }
    }
  }
}
