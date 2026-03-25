import type {
  IAssetTransferDisplayMetadata,
  IBuildAssetTransferDisplayMetadataOptions,
} from "./types.js";

function formatAmount(value: number | string): string {
  if (typeof value === "string") {
    return value;
  }
  return value.toFixed(8);
}

export function buildAssetTransferDisplayMetadata(
  options: IBuildAssetTransferDisplayMetadataOptions
): IAssetTransferDisplayMetadata {
  return {
    kind: "asset_transfer",
    assetName: options.assetName,
    assetAmount: formatAmount(options.assetAmount),
    destinationAddress: options.destinationAddress,
    destinationCount: options.destinationCount ?? 1,
    changeAddress: options.changeAddress,
    changeCount: options.changeCount ?? 0,
    inputAddresses: options.inputAddresses ?? [],
    feeAmount:
      options.feeAmount === undefined ? undefined : formatAmount(options.feeAmount),
    baseCurrency: options.baseCurrency ?? "XNA",
  };
}
