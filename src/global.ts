import { NeuraiESP32 } from "./NeuraiESP32.js";
import { buildAssetTransferDisplayMetadata } from "./display.js";
import {
  getNetwork,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
  neuraiMainnet,
  neuraiTestnet,
} from "./networks.js";
import {
  buildPSBT,
  buildPSBTFromRawTransaction,
  finalizePSBT,
  finalizeSignedPSBT,
  validatePSBT,
} from "./psbt.js";
import { SerialConnection } from "./serial.js";

const api = {
  NeuraiESP32,
  SerialConnection,
  buildPSBT,
  buildPSBTFromRawTransaction,
  finalizePSBT,
  finalizeSignedPSBT,
  validatePSBT,
  buildAssetTransferDisplayMetadata,
  getNetwork,
  neuraiMainnet,
  neuraiTestnet,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
};

declare global {
  var NeuraiSignESP32: typeof api | undefined;

  interface Window {
    NeuraiSignESP32?: typeof api;
  }
}

globalThis.NeuraiSignESP32 = api;

export default api;
