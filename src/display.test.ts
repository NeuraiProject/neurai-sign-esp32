import { describe, expect, it } from "vitest";
import { buildAssetTransferDisplayMetadata } from "./display.js";

describe("buildAssetTransferDisplayMetadata", () => {
  it("formats numeric amounts and fills defaults", () => {
    const metadata = buildAssetTransferDisplayMetadata({
      assetName: "MY_ASSET",
      assetAmount: 1,
      destinationAddress: "Ndestination",
      changeAddress: "Nchange",
      feeAmount: 0.01234567,
    });

    expect(metadata).toEqual({
      kind: "asset_transfer",
      assetName: "MY_ASSET",
      assetAmount: "1.00000000",
      destinationAddress: "Ndestination",
      destinationCount: 1,
      changeAddress: "Nchange",
      changeCount: 0,
      inputAddresses: [],
      feeAmount: "0.01234567",
      baseCurrency: "XNA",
    });
  });

  it("preserves string amounts as-is", () => {
    const metadata = buildAssetTransferDisplayMetadata({
      assetName: "MY_ASSET",
      assetAmount: "1.5000",
      destinationAddress: "Ndestination",
    });

    expect(metadata.assetAmount).toBe("1.5000");
  });
});
