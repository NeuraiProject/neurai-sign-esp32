/**
 * @neuraiproject/neurai-sign-esp32
 *
 * Library for creating and signing Neurai (XNA) PSBTs
 * via ESP32 hardware wallet (NeuraiHW).
 */

// Main class
export { NeuraiESP32 } from "./NeuraiESP32.js";
export {
  createDepinDeviceIdentity,
  DepinDeviceIdentityError,
  derSignatureToRecoverable,
  neuraiSignedMessageDigest,
} from "./depin-identity.js";
export type {
  DepinAdapterNetwork,
  DepinAuthSigningContext,
  DepinDeviceIdentityErrorCode,
  DepinMessageSigningContext,
  IDepinDeviceIdentity,
  IDepinIdentityAdapterOptions,
} from "./depin-identity.js";

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

// Transport layer (for advanced use / custom platforms)
export { SerialConnection } from "./serial.js";
export { SerialProtocol } from "./serial-protocol.js";
export { WebSerialByteChannel } from "./channels/web-serial.js";

// Network configs
export {
  getNetwork,
  resolveNetwork,
  getPQNetworkParams,
  neuraiMainnet,
  neuraiTestnet,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
  neuraiPQMainnet,
  neuraiPQTestnet,
} from "./networks.js";
export type { PQNetworkParams } from "./networks.js";

// PQ address / AuthScript helpers
export {
  isPQAddress,
  decodeAddress,
  encodeDestinationScript,
  publicKeyToAddress,
  pqAddressFromPublicKey,
  pqCommitment,
  pqAuthDescriptor,
  DEFAULT_WITNESS_SCRIPT_HEX,
} from "./pq-address.js";
export type { DecodedAddress } from "./pq-address.js";

// PQ raw-transaction builder (spend from PQ)
export {
  buildUnsignedPQTransaction,
  parseSignedPQTransaction,
  extractPQWitness,
  MAX_PQ_INPUTS,
  MAX_OUTPUTS,
} from "./pq-tx.js";
export type {
  IPQSignInput,
  IBuildUnsignedPQTxOptions,
  IUnsignedPQTx,
  IPQWitness,
} from "./pq-tx.js";

// PQ AuthScript sighash (for verifying device signatures)
export { pqAuthScriptSighash, SIGHASH_ALL, PQ_AUTH_TYPE } from "./pq-sighash.js";
export type { IPQSighashOptions } from "./pq-sighash.js";

// Types
export type {
  INeuraiTransport,
  IByteChannel,
  IUTXO,
  IPQUTXO,
  ITxOutput,
  IBuildPSBTOptions,
  IBuildPSBTFromRawOptions,
  IBuildAssetTransferDisplayMetadataOptions,
  IPSBTInputMetadata,
  IAssetTransferDisplayMetadata,
  ISigningDisplayMetadata,
  IPingResponse,
  ISetupSeedOptions,
  ISetupSeedResponse,
  DeviceState,
  IDeviceInfo,
  IAddressResponse,
  IBip32PubkeyResponse,
  ISignPsbtResponse,
  ISignTxResponse,
  ISignMessageResponse,
  DepinSessionPermission,
  DepinSignAuthCommand,
  IDepinSessionResponse,
  IDepinSessionStatusResponse,
  IDepinIdentityResponse,
  IDepinSignAuthResponse,
  IDepinSignResponse,
  IDepinDecryptResponse,
  IDepinSignDigestResponse,
  IErrorResponse,
  ISerialOptions,
  ISerialPortFilter,
  ISignResult,
  Network,
  KeyType,
  NetworkType,
} from "./types.js";
