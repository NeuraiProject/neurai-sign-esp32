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
  assertDeviceCanSignPSBT,
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
  fromNeuraiKeyNetwork,
  getPQNetworkParams,
  authScriptFamilyByHrp,
  authScriptFamilyByVersion,
  AUTHSCRIPT_FAMILIES,
  neuraiMainnet,
  neuraiTestnet,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
  neuraiPQMainnet,
  neuraiPQTestnet,
  neuraiPQStrictMainnet,
  neuraiPQStrictTestnet,
} from "./networks.js";
export type {
  AuthScriptFamily,
  AuthScriptFamilyParams,
  NeuraiKeyNetworkAlias,
  PQNetworkParams,
} from "./networks.js";

// Address / AuthScript helpers (every Neurai address type)
export {
  isPQAddress,
  isWitnessAddress,
  getAddressFamily,
  decodeAddress,
  encodeDestinationScript,
  encodeAuthScriptDestination,
  encodeP2PKHDestination,
  authScriptWitnessVersionOfScript,
  normalizeDeviceAuthScriptAddress,
  publicKeyToAddress,
  pqAddressFromPublicKey,
  ecdsaAddressFromPublicKey,
  authScriptAddressFromProgram,
  authScriptCommitment,
  pqCommitment,
  ecdsaCommitment,
  pqAuthDescriptor,
  ecdsaAuthDescriptor,
  DEFAULT_WITNESS_SCRIPT_HEX,
} from "./pq-address.js";
export type {
  AddressFamily,
  DecodedAddress,
  IAuthScriptCommitmentOptions,
} from "./pq-address.js";

// PQ raw-transaction builder (spend from PQ)
export {
  buildUnsignedPQTransaction,
  parseSignedPQTransaction,
  extractPQWitness,
  assertSignTxPrevoutScript,
  MAX_PQ_INPUTS,
  MAX_OUTPUTS,
} from "./pq-tx.js";
export type {
  IPQSignInput,
  IBuildUnsignedPQTxOptions,
  IUnsignedPQTx,
  IPQWitness,
} from "./pq-tx.js";

// AuthScript sighash (for verifying device signatures): generic v1 and strict v2/v3
export {
  pqAuthScriptSighash,
  strictAuthScriptSighash,
  SIGHASH_ALL,
  PQ_AUTH_TYPE,
  ECDSA_AUTH_TYPE,
} from "./pq-sighash.js";
export type { IPQSighashOptions, IStrictSighashOptions } from "./pq-sighash.js";

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

// Monetary input types: raw protocol integers versus display units.
export type { RawAmount, DecimalAmount } from "./amounts.js";
