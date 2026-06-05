import { NeuraiESP32 } from "./NeuraiESP32.js";
import { buildAssetTransferDisplayMetadata } from "./display.js";
import {
  getNetwork,
  getPQNetworkParams,
  resolveNetwork,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
  neuraiMainnet,
  neuraiPQMainnet,
  neuraiPQTestnet,
  neuraiTestnet,
} from "./networks.js";
import {
  buildPSBT,
  buildPSBTFromRawTransaction,
  finalizePSBT,
  finalizeSignedPSBT,
  validatePSBT,
} from "./psbt.js";
import {
  DEFAULT_WITNESS_SCRIPT_HEX,
  decodeAddress,
  encodeDestinationScript,
  isPQAddress,
  pqAddressFromPublicKey,
  pqAuthDescriptor,
  pqCommitment,
  publicKeyToAddress,
} from "./pq-address.js";
import {
  MAX_OUTPUTS,
  MAX_PQ_INPUTS,
  buildUnsignedPQTransaction,
  parseSignedPQTransaction,
} from "./pq-tx.js";
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
  resolveNetwork,
  getPQNetworkParams,
  neuraiMainnet,
  neuraiTestnet,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
  neuraiPQMainnet,
  neuraiPQTestnet,
  // PQ address / AuthScript helpers
  isPQAddress,
  decodeAddress,
  encodeDestinationScript,
  publicKeyToAddress,
  pqAddressFromPublicKey,
  pqCommitment,
  pqAuthDescriptor,
  DEFAULT_WITNESS_SCRIPT_HEX,
  // PQ raw-transaction builder
  buildUnsignedPQTransaction,
  parseSignedPQTransaction,
  MAX_PQ_INPUTS,
  MAX_OUTPUTS,
};

declare global {
  var NeuraiSignESP32: typeof api | undefined;

  interface Window {
    NeuraiSignESP32?: typeof api;
  }
}

globalThis.NeuraiSignESP32 = api;

export default api;
