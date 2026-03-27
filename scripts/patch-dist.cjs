const fs = require('fs');
const path = require('path');

const files = [
  path.join(__dirname, '..', 'dist', 'index.mjs'),
  path.join(__dirname, '..', 'dist', 'index.cjs'),
];

const replacements = [
  {
    label: 'relax-sighash-check',
    from: /function checkPartialSigSighashes\(input\) \{\s*if \(!input\.sighashType \|\| !input\.partialSig\) return;\s*const \{ partialSig, sighashType \} = input;\s*partialSig\.forEach\(\(pSig\) => \{\s*const \{ hashType \} = signature\.decode\(pSig\.signature\);\s*if \(sighashType !== hashType\) \{\s*throw new Error\("Signature sighash does not match input sighash type"\);\s*\}\s*\}\);\s*\}/g,
    to: `function checkPartialSigSighashes(input) {
    if (!input.sighashType || !input.partialSig) return;
    const { partialSig, sighashType } = input;
    let normalizedSighashType = sighashType;
    partialSig.forEach((pSig) => {
      const { hashType } = signature.decode(pSig.signature);
      if (normalizedSighashType !== hashType) {
        console.warn("[NeuraiSignESP32] Adjusting input sighashType to match returned signature", {
          previousSighashType: normalizedSighashType,
          returnedHashType: hashType
        });
        normalizedSighashType = hashType;
      }
    });
    input.sighashType = normalizedSighashType;
  }`,
  },
  {
    label: 'allow-negative-fee-extraction',
    from: /if \(fee < 0\) \{\s*throw new Error\("Outputs are spending more than Inputs"\);\s*\}/g,
    to: `if (fee < 0) {
      cache.__FEE = 0n;
      cache.__EXTRACTED_TX = tx;
      cache.__FEE_RATE = 0;
      return;
    }`,
  },
];

for (const file of files) {
  let text = fs.readFileSync(file, 'utf8');
  for (const { label, from, to } of replacements) {
    const next = text.replace(from, to);
    if (next === text) {
      console.warn(`[patch-dist] No match for ${label} in ${path.basename(file)}`);
    }
    text = next;
  }
  fs.writeFileSync(file, text);
  console.log(`[patch-dist] Patched ${path.basename(file)}`);
}
