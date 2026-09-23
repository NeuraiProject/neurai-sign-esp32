import { describe, expect, it } from "vitest";
import {
  AUTHSCRIPT_FAMILIES,
  authScriptFamilyByHrp,
  authScriptFamilyByVersion,
  fromNeuraiKeyNetwork,
  getNetwork,
  getPQNetworkParams,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
  neuraiMainnet,
  neuraiPQMainnet,
  neuraiTestnet,
} from "./networks.js";

describe("getNetwork", () => {
  it("returns the expected network objects", () => {
    expect(getNetwork("xna")).toBe(neuraiMainnet);
    expect(getNetwork("xna-test")).toBe(neuraiTestnet);
    expect(getNetwork("xna-legacy")).toBe(neuraiLegacyMainnet);
    expect(getNetwork("xna-legacy-test")).toBe(neuraiLegacyTestnet);
  });
});

describe("neurai-key 5 network names", () => {
  it("accepts the unambiguous aliases in getNetwork", () => {
    expect(getNetwork("xna-old-legacy")).toBe(neuraiLegacyMainnet);
    expect(getNetwork("xna-authscript").bech32).toBe("nc");
    expect(getNetwork("xna-authscript-test").bech32).toBe("tnc");
    expect(getNetwork("xna-pq").bech32).toBe("nc");
  });

  it("translates key-5 names with key-5 semantics", () => {
    expect(fromNeuraiKeyNetwork("xna-legacy")).toBe("xna");
    expect(fromNeuraiKeyNetwork("xna-legacy-test")).toBe("xna-test");
    expect(fromNeuraiKeyNetwork("xna-old-legacy")).toBe("xna-legacy");
    expect(fromNeuraiKeyNetwork("xna-authscript")).toBe("xna-pq");
    expect(fromNeuraiKeyNetwork("xna-authscript-test")).toBe("xna-pq-test");
    expect(() => fromNeuraiKeyNetwork("xna")).toThrow(/strict ECDSA witness v3/);
    expect(() => fromNeuraiKeyNetwork("xna-test")).toThrow(/strict ECDSA witness v3/);
    expect(() => fromNeuraiKeyNetwork("xna-pq")).toThrow(/strict PQ witness v2/);
    expect(() => fromNeuraiKeyNetwork("xna-pq-test")).toThrow(/strict PQ witness v2/);
    expect(() => fromNeuraiKeyNetwork("btc")).toThrow(/Unknown/);
  });
});

describe("AuthScript families", () => {
  it("pairs each HRP with one witness version", () => {
    expect(AUTHSCRIPT_FAMILIES.authscript).toMatchObject({ witnessVersion: 1, hrp: { mainnet: "nc", testnet: "tnc" } });
    expect(AUTHSCRIPT_FAMILIES.pq).toMatchObject({ witnessVersion: 2, authType: 1, hrp: { mainnet: "pq", testnet: "tpq" } });
    expect(AUTHSCRIPT_FAMILIES.ecdsa).toMatchObject({ witnessVersion: 3, authType: 2, hrp: { mainnet: "nq", testnet: "tnq" } });
    expect(authScriptFamilyByHrp("TNQ")).toMatchObject({ network: "testnet", params: { family: "ecdsa" } });
    expect(authScriptFamilyByHrp("bc")).toBeUndefined();
    expect(authScriptFamilyByVersion(2)?.family).toBe("pq");
    expect(authScriptFamilyByVersion(0)).toBeUndefined();
  });

  it("keeps the device PQ params on the generic v1 family", () => {
    expect(getPQNetworkParams("mainnet")).toMatchObject({ hrp: "nc", witnessVersion: 1, coinType: 1900 });
    expect(getPQNetworkParams("testnet")).toMatchObject({ hrp: "tnc", witnessVersion: 1, coinType: 1 });
    expect(getPQNetworkParams("testnet", 2)).toMatchObject({ hrp: "tpq", witnessVersion: 2, coinType: 1 });
    expect(neuraiPQMainnet.hrp).toBe("nc");
  });
});
