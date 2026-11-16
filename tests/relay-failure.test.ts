import assert from "node:assert/strict";
import { test } from "node:test";

import { settledTxHash } from "../lib/checkout/relay-failure";

test("returns the tx hash when the payment settled but the order was not saved", () => {
  assert.equal(
    settledTxHash({ error: "not recorded", txHash: "0xabc", orderPersisted: false }),
    "0xabc",
  );
});

test("returns null for an ordinary relay failure", () => {
  assert.equal(settledTxHash({ error: "Relay failed" }), null);
  assert.equal(settledTxHash({ txHash: "0xabc" }), null);
  assert.equal(settledTxHash({ txHash: "0xabc", orderPersisted: true }), null);
});

test("returns null for a body that is not an object or has no usable hash", () => {
  assert.equal(settledTxHash(null), null);
  assert.equal(settledTxHash("oops"), null);
  assert.equal(settledTxHash({ orderPersisted: false }), null);
  assert.equal(settledTxHash({ orderPersisted: false, txHash: 42 }), null);
});
