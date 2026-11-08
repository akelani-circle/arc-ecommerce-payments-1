/**
 * Copyright 2026 Circle Internet Group, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import type { SupabaseClient } from "@supabase/supabase-js";
import { formatUnits } from "viem";

const SCP_EVENT_NAMES = [
  "Authorized",
  "Captured",
  "Charged",
  "Voided",
  "Reclaimed",
  "Refunded",
] as const;

type ScpEventName = (typeof SCP_EVENT_NAMES)[number];

// Events whose amount moves captured_amount / refunded_amount, so it must be present.
const AMOUNT_REQUIRED: ReadonlySet<ScpEventName> = new Set(["Captured", "Refunded"]);

function isScpEventName(value: unknown): value is ScpEventName {
  return SCP_EVENT_NAMES.some((name) => name === value);
}

interface ScpWebhookPayload {
  contractAddress: string;
  eventName: string;
  data: {
    salt?: string;
    amount?: string;
    transactionHash?: string;
    blockNumber?: number;
  };
}

/**
 * Base units (6 decimals) -> exact decimal string for numeric(20,6).
 * Returns null when absent, and throws on anything that is not a non-negative integer.
 */
function toTokenAmount(raw: string | undefined): string | null {
  if (raw === undefined) return null;
  if (!/^\d+$/.test(raw)) {
    throw new Error(`invalid amount: ${raw}`);
  }
  return formatUnits(BigInt(raw), 6);
}

function verifyWebhookSignature(
  body: string,
  signature: string,
  secret: string,
): boolean {
  const expected = createHmac("sha256", secret)
    .update(body)
    .digest("hex");

  const receivedBuffer = Buffer.from(signature, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");

  if (receivedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(receivedBuffer, expectedBuffer);
}

export async function handleWebhook(
  req: NextRequest,
  supabase: SupabaseClient,
): Promise<Response> {
  const secret = process.env.WEBHOOK_SECRET;

  if (!secret) {
    console.error("[webhook] WEBHOOK_SECRET is not configured");

    return NextResponse.json(
      { error: "webhook not configured" },
      { status: 503 },
    );
  }

  const signature = req.headers.get("x-scp-signature") ?? "";

  if (!signature) {
    console.warn("[webhook] missing signature");

    return NextResponse.json(
      { error: "missing signature" },
      { status: 401 },
    );
  }

  const body = await req.text();

  if (!verifyWebhookSignature(body, signature, secret)) {
    console.warn("[webhook] invalid signature");

    return NextResponse.json(
      { error: "invalid signature" },
      { status: 401 },
    );
  }

  let payload: ScpWebhookPayload;

  try {
    payload = JSON.parse(body) as ScpWebhookPayload;
  } catch {
    return NextResponse.json(
      { error: "invalid JSON" },
      { status: 400 },
    );
  }

  const { eventName, data } = payload;
  const salt = data?.salt;

  if (!salt) {
    return NextResponse.json({ ok: true });
  }

  // The contract may emit events this store does not track; acknowledge them so SCP stops retrying.
  if (!isScpEventName(eventName)) {
    console.log(`[webhook] ignoring untracked event ${String(eventName)}`);
    return NextResponse.json({ ok: true, ignored: true });
  }

  let amount: string | null;
  try {
    amount = toTokenAmount(data.amount);
  } catch {
    return NextResponse.json({ error: "invalid amount" }, { status: 400 });
  }

  if (AMOUNT_REQUIRED.has(eventName) && amount === null) {
    return NextResponse.json({ error: "missing amount" }, { status: 400 });
  }

  const txHash = data.transactionHash;

  if (!txHash) {
    return NextResponse.json(
      { error: "missing transaction hash" },
      { status: 400 },
    );
  }

  const { data: order, error: fetchError } = await supabase
    .from("orders")
    .select("id")
    .filter("payment_info->>salt", "eq", salt)
    .single();

  if (fetchError || !order) {
    console.error(
      "[webhook] order not found for salt",
      salt,
      fetchError?.message,
    );

    return NextResponse.json(
      { error: "order not found" },
      { status: 404 },
    );
  }

  // The RPC derives the "partial" note itself, under the order row lock.
  const { data: processed, error: processError } = await supabase.rpc(
    "process_webhook_event",
    {
      p_order_id: order.id,
      p_operation: eventName,
      p_tx_hash: txHash,
      p_amount: amount,
      p_note: null,
      p_block_number: data.blockNumber ?? null,
    },
  );

  if (processError) {
    console.error(
      "[webhook] atomic event processing failed",
      order.id,
      processError.message,
    );

    return NextResponse.json(
      { error: "db update failed" },
      { status: 500 },
    );
  }

  if (!processed) {
    console.log(
      `[webhook] duplicate delivery ignored for tx ${txHash} (${eventName})`,
    );

    return NextResponse.json({ ok: true, duplicate: true });
  }
  console.log(
    `[webhook] ${eventName} -> order ${order.id} processed`,
    { txHash, amount },
  );

  return NextResponse.json({ ok: true });
}

export async function POST(req: NextRequest): Promise<Response> {
  const { createServiceClient } = await import("@/lib/supabase/service");
  return handleWebhook(req, createServiceClient());
}
