/**
 * React Native entry point for neurai-sign-esp32.
 *
 * Re-exports the full library plus the React Native / Android USB transport.
 * Unlike the browser entry, nothing here touches the Web Serial API, so it is
 * safe to import in a React Native bundle.
 *
 * Quick start (Android):
 *
 * ```ts
 * import { createNeuraiESP32OverUsb } from "@neuraiproject/neurai-sign-esp32/react-native";
 *
 * // `usbDriver` adapts your chosen native USB-serial module to IUsbSerialDriver.
 * const device = createNeuraiESP32OverUsb(usbDriver);
 * await device.connect();
 * const info = await device.getInfo();
 * const { address } = await device.getAddress();
 * const { txHex } = await device.signTransaction({ utxos, outputs, changeAddress: address });
 * await device.disconnect();
 * ```
 */

export * from "./index.js";

export { SerialProtocol } from "./serial-protocol.js";
export {
  NativeUsbByteChannel,
  bytesToBase64,
  base64ToBytes,
} from "./channels/react-native-usb.js";
export type {
  IUsbSerialDriver,
  IUsbSerialPort,
  IUsbSubscription,
} from "./channels/react-native-usb.js";

import { NeuraiESP32 } from "./NeuraiESP32.js";
import { SerialProtocol } from "./serial-protocol.js";
import { NativeUsbByteChannel } from "./channels/react-native-usb.js";
import type { IUsbSerialDriver } from "./channels/react-native-usb.js";

/**
 * Build a {@link NeuraiESP32} wired to an Android USB-serial driver.
 *
 * @param driver  your native USB-serial module adapted to `IUsbSerialDriver`
 * @param options optional baud rate (defaults to the firmware's 115200)
 */
export function createNeuraiESP32OverUsb(
  driver: IUsbSerialDriver,
  options?: { baudRate?: number }
): NeuraiESP32 {
  const channel = new NativeUsbByteChannel(driver, options);
  const transport = new SerialProtocol(channel);
  return new NeuraiESP32({ transport });
}
