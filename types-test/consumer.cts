// CommonJS consumer: resolves the `require` condition (dist/index.d.cts).
// Every value export of dist/index.cjs is used, so a missing declaration
// fails to compile.
import esp32 = require("@neuraiproject/neurai-sign-esp32");

export const values = [
  esp32.AUTHSCRIPT_FAMILIES, esp32.DEFAULT_WITNESS_SCRIPT_HEX, esp32.DepinDeviceIdentityError,
  esp32.ECDSA_AUTH_TYPE, esp32.MAX_OUTPUTS, esp32.MAX_PQ_INPUTS, esp32.NeuraiESP32,
  esp32.PQ_AUTH_TYPE, esp32.SIGHASH_ALL, esp32.SerialConnection, esp32.SerialProtocol,
  esp32.WebSerialByteChannel, esp32.assertSignTxPrevoutScript, esp32.authScriptAddressFromProgram,
  esp32.authScriptCommitment, esp32.authScriptFamilyByHrp, esp32.authScriptFamilyByVersion,
  esp32.authScriptWitnessVersionOfScript, esp32.buildAssetTransferDisplayMetadata, esp32.buildPSBT,
  esp32.buildPSBTFromRawTransaction, esp32.buildUnsignedPQTransaction,
  esp32.createDepinDeviceIdentity, esp32.decodeAddress, esp32.derSignatureToRecoverable,
  esp32.ecdsaAddressFromPublicKey, esp32.ecdsaAuthDescriptor, esp32.ecdsaCommitment,
  esp32.encodeAuthScriptDestination, esp32.encodeDestinationScript, esp32.encodeP2PKHDestination,
  esp32.extractPQWitness, esp32.finalizePSBT, esp32.finalizeSignedPSBT, esp32.fromNeuraiKeyNetwork,
  esp32.getAddressFamily, esp32.getNetwork, esp32.getPQNetworkParams, esp32.isPQAddress,
  esp32.isWitnessAddress, esp32.neuraiLegacyMainnet, esp32.neuraiLegacyTestnet,
  esp32.neuraiMainnet, esp32.neuraiPQMainnet, esp32.neuraiPQStrictMainnet,
  esp32.neuraiPQStrictTestnet, esp32.neuraiPQTestnet, esp32.neuraiSignedMessageDigest,
  esp32.neuraiTestnet, esp32.normalizeDeviceAuthScriptAddress, esp32.parseSignedPQTransaction,
  esp32.pqAddressFromPublicKey, esp32.pqAuthDescriptor, esp32.pqAuthScriptSighash,
  esp32.pqCommitment, esp32.publicKeyToAddress, esp32.resolveNetwork,
  esp32.strictAuthScriptSighash, esp32.validatePSBT,
];
export const output: esp32.ITxOutput = { address: "tpq1z…", value: 1n };
