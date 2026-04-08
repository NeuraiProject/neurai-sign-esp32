import { describe, expect, it } from "vitest";
import {
  getNetwork,
  neuraiLegacyMainnet,
  neuraiLegacyTestnet,
  neuraiMainnet,
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
