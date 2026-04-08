import {
  NeuraiESP32,
  buildAssetTransferDisplayMetadata,
  getNetwork,
  validatePSBT,
} from "../dist/browser.js";

const logElement = document.getElementById("log");
const connectButton = document.getElementById("connect-button");

function log(title, value) {
  const rendered =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
  logElement.textContent += `[${title}]\n${rendered}\n\n`;
}

function assert(condition, message, details) {
  if (!condition) {
    throw new Error(details ? `${message}: ${details}` : message);
  }
}

try {
  log("esm-import", "ok");
  log("web-serial-supported", String(NeuraiESP32.isSupported()));

  const network = getNetwork("xna");
  assert(network.pubKeyHash === 53, "unexpected xna network pubKeyHash");
  log("network", network);

  const display = buildAssetTransferDisplayMetadata({
    assetName: "SMOKE_ASSET",
    assetAmount: 1,
    destinationAddress: "NsmokeDestination",
    changeAddress: "NsmokeChange",
    feeAmount: 0.00012345,
  });
  assert(display.assetAmount === "1.00000000", "display formatting mismatch");
  log("display-metadata", display);

  assert(validatePSBT("not-a-psbt", "xna") === false, "validatePSBT should reject invalid data");
  log("validate-psbt-invalid-input", "ok");
} catch (error) {
  log("startup-error", error instanceof Error ? error.message : String(error));
}

connectButton?.addEventListener("click", async () => {
  const device = new NeuraiESP32();

  try {
    await device.connect();
    log("connect", "port opened");

    const info = await device.getInfo();
    log("device-info", info);

    await device.disconnect();
    log("disconnect", "port closed");
  } catch (error) {
    log("serial-flow-error", error instanceof Error ? error.message : String(error));
    try {
      await device.disconnect();
    } catch {
      // Ignore cleanup failures in smoke harness.
    }
  }
});
