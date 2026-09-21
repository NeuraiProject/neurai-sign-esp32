import { formatDisplayAmount } from "./amounts.js";
import type {
  IAssetTransferDisplayMetadata,
  IBuildAssetTransferDisplayMetadataOptions,
} from "./types.js";

export function buildAssetTransferDisplayMetadata(
  options: IBuildAssetTransferDisplayMetadataOptions
): IAssetTransferDisplayMetadata {
  return {
    kind: "asset_transfer",
    assetName: options.assetName,
    assetAmount: formatDisplayAmount(options.assetAmount),
    destinationAddress: options.destinationAddress,
    destinationCount: options.destinationCount ?? 1,
    changeAddress: options.changeAddress,
    changeCount: options.changeCount ?? 0,
    inputAddresses: options.inputAddresses ?? [],
    feeAmount:
      options.feeAmount === undefined ? undefined : formatDisplayAmount(options.feeAmount),
    baseCurrency: options.baseCurrency ?? "XNA",
  };
}

/** Validate display data even when callers bypass the convenience builder. */
export function normalizeSigningDisplay(display: IAssetTransferDisplayMetadata): IAssetTransferDisplayMetadata {
  return {
    ...display,
    assetAmount: formatDisplayAmount(display.assetAmount),
    ...(display.feeAmount === undefined ? {} : { feeAmount: formatDisplayAmount(display.feeAmount) }),
  };
}
