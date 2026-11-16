/**
 * Copyright 2026 Circle Internet Group, Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

"use client";

import type { Hex } from "viem";
import { buildReceiveAuthTypedData } from "@/lib/payments/authorization";
import { arcExplorerLink } from "@/lib/arc/chain";
import type { Currency } from "@/lib/products";
import { settledTxHash } from "@/lib/checkout/relay-failure";

/**
 * Real checkout: ask the operator to build + hold the PaymentInfo, have the
 * shopper sign the ERC-3009 authorization in their own wallet, then post the
 * signature for the operator to relay (Authorize) - sponsoring gas. The signing
 * step happens between two server calls, so it has to live on the client.
 */

/** Drives the primary-button label and the wallet-signing overlay. */
export type CheckoutPhase = "idle" | "signing" | "reserving" | "done";

export type CheckoutResult = {
  orderId: string;
  status: "Reserved";
  txHash: string;
  explorerUrl: string;
};

/** The async signer from wagmi's `useSignTypedData` (typed loosely on purpose). */
type SignTypedData = (
  typedData: ReturnType<typeof buildReceiveAuthTypedData>,
) => Promise<Hex>;

/**
 * The payment landed on-chain but the order could not be saved. The caller
 * must not let the shopper pay for the same cart again.
 */
export class PaymentSettledError extends Error {
  constructor(
    message: string,
    readonly txHash: string,
  ) {
    super(message);
    this.name = "PaymentSettledError";
  }
}

async function readFailure(
  res: Response,
  fallback: string,
): Promise<{ message: string; settledTxHash: string | null }> {
  try {
    const body = await res.json();
    const message = body.error ?? fallback;
    return {
      message: body.txHash ? `${message} Transaction hash: ${body.txHash}` : message,
      settledTxHash: settledTxHash(body),
    };
  } catch {
    return { message: fallback, settledTxHash: null };
  }
}

export async function submitCheckout({
  currency,
  payer,
  items,
  signTypedDataAsync,
  onPhase,
}: {
  currency: Currency;
  payer: Hex;
  /** Cart line items. Prices are re-derived server-side from the product catalog. */
  items: { name: string; qty: number; price: number }[];
  signTypedDataAsync: SignTypedData;
  onPhase: (phase: CheckoutPhase) => void;
}): Promise<CheckoutResult> {
  const intentRes = await fetch("/api/checkout/intent", {
    method: "POST",
    headers: { "content-type": "application/json" },
    // `amount` is deliberately not sent: the server prices the cart from its own product
    // catalog (`lib/products.ts`) and recomputes the total, so a client cannot influence the
    // authorized amount. The response's `value` is authoritative.
    body: JSON.stringify({ currency, payer, items }),
  });
  if (!intentRes.ok) {
    throw new Error((await readFailure(intentRes, "Could not start checkout")).message);
  }
  const intent: {
    nonce: Hex;
    value: string;
    preApprovalExpiry: number;
    collector: Hex;
  } = await intentRes.json();

  onPhase("signing");
  const signature = await signTypedDataAsync(
    buildReceiveAuthTypedData({
      currency,
      collector: intent.collector,
      payer,
      value: BigInt(intent.value),
      validBefore: intent.preApprovalExpiry,
      nonce: intent.nonce,
    }),
  );

  onPhase("reserving");
  const relayRes = await fetch("/api/checkout/authorize", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: intent.nonce, signature }),
  });
  if (!relayRes.ok) {
    const failure = await readFailure(relayRes, "Payment relay failed");
    if (failure.settledTxHash) {
      throw new PaymentSettledError(failure.message, failure.settledTxHash);
    }
    throw new Error(failure.message);
  }
  const { txHash, orderId, status } = await relayRes.json();
  return { orderId, status, txHash, explorerUrl: arcExplorerLink("tx", txHash) };
}
