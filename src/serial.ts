/**
 * Web Serial connection for the ESP32 hardware wallet.
 *
 * `SerialConnection` is the default, browser-targeted transport: it drives the
 * NeuraiHW JSON protocol ({@link SerialProtocol}) over a Web Serial byte channel
 * ({@link WebSerialByteChannel}). Its public API is unchanged — it remains the
 * out-of-the-box transport `NeuraiESP32` uses when none is injected.
 *
 * To run the library on another platform (e.g. React Native / Android USB),
 * implement an `IByteChannel`, wrap it in a `SerialProtocol`, and pass that as
 * `transport` to `NeuraiESP32`. See `src/channels/` and the README.
 */

import { SerialProtocol } from "./serial-protocol.js";
import { WebSerialByteChannel } from "./channels/web-serial.js";
import type { ISerialOptions } from "./types.js";

export class SerialConnection extends SerialProtocol {
  constructor(options?: ISerialOptions) {
    super(new WebSerialByteChannel(options));
  }

  static isSupported(): boolean {
    return WebSerialByteChannel.isSupported();
  }
}
