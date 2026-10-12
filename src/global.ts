import { NeuraiESP32 } from "./NeuraiESP32.js";
import {
  createDepinDeviceIdentity,
  DepinDeviceIdentityError,
  derSignatureToRecoverable,
  neuraiSignedMessageDigest,
} from "./depin-identity.js";
import { buildAssetTransferDisplayMetadata } from "./display.js";
import {
  AUTHSCRIPT_FAMILIES,
  fromNeuraiKeyNetwork,
  getNetwork,
  getPQNetworkParams,
  resolveNetwork,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
  neuraiMainnet,
  neuraiPQMainnet,
  neuraiPQStrictMainnet,
  neuraiPQStrictTestnet,
  neuraiPQTestnet,
  neuraiTestnet,
} from "./networks.js";
import {
  assertDeviceCanSignPSBT,
  buildPSBT,
  buildPSBTFromRawTransaction,
  finalizePSBT,
  finalizeSignedPSBT,
  validatePSBT,
} from "./psbt.js";
import {
  DEFAULT_WITNESS_SCRIPT_HEX,
  authScriptCommitment,
  decodeAddress,
  ecdsaAddressFromPublicKey,
  ecdsaCommitment,
  encodeDestinationScript,
  getAddressFamily,
  isPQAddress,
  isWitnessAddress,
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
  extractPQWitness,
} from "./pq-tx.js";
import { pqAuthScriptSighash, strictAuthScriptSighash } from "./pq-sighash.js";
import { SerialConnection } from "./serial.js";

const api = {
  NeuraiESP32,
  createDepinDeviceIdentity,
  DepinDeviceIdentityError,
  derSignatureToRecoverable,
  neuraiSignedMessageDigest,
  SerialConnection,
  assertDeviceCanSignPSBT,
  buildPSBT,
  buildPSBTFromRawTransaction,
  finalizePSBT,
  finalizeSignedPSBT,
  validatePSBT,
  buildAssetTransferDisplayMetadata,
  getNetwork,
  resolveNetwork,
  fromNeuraiKeyNetwork,
  getPQNetworkParams,
  AUTHSCRIPT_FAMILIES,
  neuraiMainnet,
  neuraiTestnet,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
  neuraiPQMainnet,
  neuraiPQTestnet,
  neuraiPQStrictMainnet,
  neuraiPQStrictTestnet,
  // Address / AuthScript helpers
  isPQAddress,
  isWitnessAddress,
  getAddressFamily,
  decodeAddress,
  encodeDestinationScript,
  publicKeyToAddress,
  pqAddressFromPublicKey,
  ecdsaAddressFromPublicKey,
  authScriptCommitment,
  pqCommitment,
  ecdsaCommitment,
  pqAuthDescriptor,
  DEFAULT_WITNESS_SCRIPT_HEX,
  // PQ raw-transaction builder
  buildUnsignedPQTransaction,
  parseSignedPQTransaction,
  extractPQWitness,
  pqAuthScriptSighash,
  strictAuthScriptSighash,
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
