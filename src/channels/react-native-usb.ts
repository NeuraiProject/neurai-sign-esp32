/**
 * React Native / Android USB byte channel for the ESP32 hardware wallet.
 *
 * This channel speaks the byte-level {@link IByteChannel} contract on top of a
 * USB-serial *driver* that the host app provides. The library intentionally
 * does NOT depend on any specific native module: you adapt your chosen module
 * (e.g. `react-native-usb-serialport-for-android`, `react-native-serialport`,
 * a TurboModule of your own…) to the small {@link IUsbSerialDriver} interface
 * and pass it in. That keeps this package publishable to npm without a React
 * Native dependency, and keeps it equally useful in the browser.
 *
 * All protocol logic (256-byte / 8 ms chunked writes, line buffering, JSON
 * parsing, timeouts) is handled by {@link SerialProtocol}, so a driver only has
 * to move raw bytes.
 *
 * NOTE: USB-host serial is an Android capability. iOS does not expose generic
 * USB serial to apps, so this channel targets Android.
 */

import { Buffer } from "buffer";
import type { IByteChannel } from "../types.js";

/** Handle returned when subscribing to inbound data; call `remove()` to detach. */
export interface IUsbSubscription {
  remove(): void;
}

/** An opened USB-serial port. Adapt your native module to this shape. */
export interface IUsbSerialPort {
  /** Write raw bytes to the device. */
  write(data: Uint8Array): Promise<void>;
  /** Subscribe to inbound raw bytes. Must deliver chunks verbatim. */
  onReceive(handler: (data: Uint8Array) => void): IUsbSubscription;
  /** Close the port and free the underlying USB resources. */
  close(): Promise<void>;
}

/** Opens USB-serial ports. Adapt your native module to this shape. */
export interface IUsbSerialDriver {
  /** Open a port at the given baud rate (the firmware uses 115200). */
  open(options: { baudRate: number }): Promise<IUsbSerialPort>;
}

const DEFAULT_BAUD_RATE = 115200;

export class NativeUsbByteChannel implements IByteChannel {
  private driver: IUsbSerialDriver;
  private baudRate: number;
  private port: IUsbSerialPort | null = null;
  private subscription: IUsbSubscription | null = null;
  private handler: ((chunk: Uint8Array) => void) | null = null;

  constructor(driver: IUsbSerialDriver, options?: { baudRate?: number }) {
    this.driver = driver;
    this.baudRate = options?.baudRate ?? DEFAULT_BAUD_RATE;
  }

  get isOpen(): boolean {
    return this.port !== null;
  }

  onData(handler: (chunk: Uint8Array) => void): void {
    this.handler = handler;
    // If the port is already open (onData registered late), wire it up now.
    this.attach();
  }

  async open(): Promise<void> {
    this.port = await this.driver.open({ baudRate: this.baudRate });
    this.attach();
  }

  async write(data: Uint8Array): Promise<void> {
    if (!this.port) {
      throw new Error("Serial port not connected");
    }
    await this.port.write(data);
  }

  async close(): Promise<void> {
    if (this.subscription) {
      this.subscription.remove();
      this.subscription = null;
    }
    if (this.port) {
      const port = this.port;
      this.port = null;
      await port.close();
    }
  }

  private attach(): void {
    if (this.port && this.handler && !this.subscription) {
      this.subscription = this.port.onReceive((data) => this.handler!(data));
    }
  }
}

/**
 * Encode bytes to a base64 string. Convenience for adapting native USB modules
 * that exchange data as base64 (the common case on Android).
 */
export function bytesToBase64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

/**
 * Decode a base64 string to bytes. Convenience for adapting native USB modules
 * that deliver inbound data as base64.
 */
export function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
