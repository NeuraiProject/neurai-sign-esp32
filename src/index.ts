/**
 * @neuraiproject/neurai-sign-esp32
 *
 * Library for creating and signing Neurai (XNA) PSBTs
 * via ESP32 hardware wallet (NeuraiHW).
 */

// Main class
export { NeuraiESP32 } from "./NeuraiESP32.js";

// PSBT utilities
export {
  buildPSBT,
  buildPSBTFromRawTransaction,
  finalizePSBT,
  finalizeSignedPSBT,
  validatePSBT,
} from "./psbt.js";

// Display metadata helpers
export { buildAssetTransferDisplayMetadata } from "./display.js";

// Serial connection (for advanced use)
export { SerialConnection } from "./serial.js";

// Network configs
export {
  getNetwork,
  neuraiMainnet,
  neuraiTestnet,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
} from "./networks.js";

// Types
export type {
  IUTXO,
  ITxOutput,
  IBuildPSBTOptions,
  IBuildPSBTFromRawOptions,
  IBuildAssetTransferDisplayMetadataOptions,
  IPSBTInputMetadata,
  IAssetTransferDisplayMetadata,
  ISigningDisplayMetadata,
  IDeviceInfo,
  IAddressResponse,
  IBip32PubkeyResponse,
  ISignPsbtResponse,
  ISignMessageResponse,
  IErrorResponse,
  ISerialOptions,
  ISignResult,
  NetworkType,
} from "./types.js";
