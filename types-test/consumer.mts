// ESM consumer (.mts is ESM whatever package.json#type says), compiled by
// `npm run test:types` against the built package (dist/index.d.ts) the way an
// ESM application imports it, with skipLibCheck: false.
import {
  createDepinDeviceIdentity,
  decodeAddress,
  fromNeuraiKeyNetwork,
  NeuraiESP32,
  type ITxOutput,
  type RawAmount,
} from "@neuraiproject/neurai-sign-esp32";

const raw: RawAmount = 10000000000000001n;
export const output: ITxOutput = { address: "tnq1r…", value: raw };
export const decode = decodeAddress;
export const network = fromNeuraiKeyNetwork;
export const Device: typeof NeuraiESP32 = NeuraiESP32;
export const identity = createDepinDeviceIdentity;
