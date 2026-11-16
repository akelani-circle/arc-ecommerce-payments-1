import { createHmac } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { NextRequest } from "next/server";

import { handleWebhook } from "../app/api/webhooks/payments/route";

const SECRET = "test-webhook-secret";

function sign(body: string): string {
  return createHmac("sha256", SECRET).update(body).digest("hex");
}

function request(body: string, signature?: string): NextRequest {
  const headers = new Headers();

  if (signature !== undefined) {
    headers.set("x-scp-signature", signature);
  }

  return new NextRequest("http://localhost/api/webhooks/payments", {
    method: "POST",
    headers,
    body,
  });
}

function responseStatus(response: Response): number {
  return response.status;
}

test("missing signature returns 401 and does not process the event", async () => {
  process.env.WEBHOOK_SECRET = SECRET;

  let supabaseTouched = false;

  const supabase = {
    from() {
      supabaseTouched = true;
      throw new Error("Supabase must not be touched");
    },
  } as never;

  const body = JSON.stringify({
    contractAddress: "0x123",
    eventName: "Authorized",
    data: {
      salt: "123",
    },
  });

  const response = await handleWebhook(request(body), supabase);

  assert.equal(responseStatus(response), 401);
  assert.equal(supabaseTouched, false);
});

test("empty signature returns 401 and does not process the event", async () => {
  process.env.WEBHOOK_SECRET = SECRET;

  let supabaseTouched = false;

  const supabase = {
    from() {
      supabaseTouched = true;
      throw new Error("Supabase must not be touched");
    },
  } as never;

  const body = JSON.stringify({
    contractAddress: "0x123",
    eventName: "Authorized",
    data: {
      salt: "123",
    },
  });

  const response = await handleWebhook(request(body, ""), supabase);

  assert.equal(responseStatus(response), 401);
  assert.equal(supabaseTouched, false);
});

test("invalid signature returns 401 and does not process the event", async () => {
  process.env.WEBHOOK_SECRET = SECRET;

  let supabaseTouched = false;

  const supabase = {
    from() {
      supabaseTouched = true;
      throw new Error("Supabase must not be touched");
    },
  } as never;

  const body = JSON.stringify({
    contractAddress: "0x123",
    eventName: "Authorized",
    data: {
      salt: "123",
    },
  });

  const response = await handleWebhook(
    request(body, sign(`${body}-tampered`)),
    supabase,
  );

  assert.equal(responseStatus(response), 401);
  assert.equal(supabaseTouched, false);
});

test("signature is verified against the raw request body", async () => {
  process.env.WEBHOOK_SECRET = SECRET;

  const body = JSON.stringify(
    {
      contractAddress: "0x123",
      eventName: "Authorized",
      data: {
        salt: "123",
        transactionHash: "0xraw",
      },
    },
    null,
    2,
  );

  const validSignature = sign(body);

  let fromCalls = 0;

  const supabase = {
    from() {
      fromCalls += 1;

      return {
        select() {
          return {
            filter() {
              return {
                single: async () => ({
                  data: null,
                  error: new Error("stop after signature verification"),
                }),
              };
            },
          };
        },
      };
    },
  } as never;

  const response = await handleWebhook(
    request(body, validSignature),
    supabase,
  );

  assert.equal(response.status, 404);
  assert.equal(fromCalls, 1);
});

test("duplicate event is ignored before the order is patched", async () => {
  process.env.WEBHOOK_SECRET = SECRET;

  const body = JSON.stringify({
    contractAddress: "0x123",
    eventName: "Captured",
    data: {
      salt: "123",
      amount: "1000000",
      transactionHash: "0xduplicate",
      blockNumber: 123,
    },
  });

  let rpcCalls = 0;

  const supabase = {
    from(table: string) {
      if (table !== "orders") {
        throw new Error(`Unexpected table: ${table}`);
      }

      return {
        select() {
          return {
            filter() {
              return {
                single: async () => ({
                  data: {
                    id: "order-1",
                    status: "Reserved",
                    total: 1,
                    currency: "USDC",
                    captured_amount: 0,
                    refunded_amount: 0,
                  },
                  error: null,
                }),
              };
            },
          };
        },
      };
    },

    rpc: async () => {
      rpcCalls += 1;
      return { data: false, error: null };
    },
  } as never;

  const response = await handleWebhook(
    request(body, sign(body)),
    supabase,
  );

  assert.equal(response.status, 200);
  assert.equal(rpcCalls, 1);

  const result = await response.json();
  assert.equal(result.duplicate, true);
});

test("concurrent duplicate deliveries are gracefully handled", async () => {
  process.env.WEBHOOK_SECRET = SECRET;

  const body = JSON.stringify({
    contractAddress: "0x123",
    eventName: "Captured",
    data: {
      salt: "123",
      amount: "1000000",
      transactionHash: "0xconcurrent",
      blockNumber: 123,
    },
  });

  let rpcCalls = 0;
  let releaseRpc!: () => void;

  const rpcReady = new Promise<void>((resolve) => {
    releaseRpc = resolve;
  });

  const supabase = {
    from(table: string) {
      if (table !== "orders") {
        throw new Error(`Unexpected table: ${table}`);
      }

      return {
        select() {
          return {
            filter() {
              return {
                single: async () => ({
                  data: {
                    id: "order-1",
                    status: "Reserved",
                    total: 1,
                    currency: "USDC",
                    captured_amount: 0,
                    refunded_amount: 0,
                  },
                  error: null,
                }),
              };
            },
          };
        },
      };
    },

    rpc: async () => {
      const callNumber = ++rpcCalls;

      if (callNumber === 2) {
        releaseRpc();
      }

      await rpcReady;

      return {
        data: callNumber === 1,
        error: null,
      };
    },
  } as never;

  const [first, second] = await Promise.all([
    handleWebhook(request(body, sign(body)), supabase),
    handleWebhook(request(body, sign(body)), supabase),
  ]);

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(rpcCalls, 2);

  const results = await Promise.all([
    first.json(),
    second.json(),
  ]);

  assert.equal(
    results.filter((result) => result.duplicate === true).length,
    1,
  );
});

function untouchedSupabase(onTouch: () => void) {
  return {
    from() {
      onTouch();
      throw new Error("Supabase must not be touched");
    },
    rpc() {
      onTouch();
      throw new Error("Supabase must not be touched");
    },
  } as never;
}

function capturedEvent(data: Record<string, unknown>, eventName = "Captured") {
  return JSON.stringify({
    contractAddress: "0x123",
    eventName,
    data: { salt: "123", transactionHash: "0xabc", blockNumber: 1, ...data },
  });
}

test("an untracked event is acknowledged without touching the database", async () => {
  process.env.WEBHOOK_SECRET = SECRET;
  let touched = false;
  const body = capturedEvent({ amount: "1000000" }, "OwnershipTransferred");

  const response = await handleWebhook(request(body, sign(body)), untouchedSupabase(() => (touched = true)));

  assert.equal(response.status, 200);
  assert.equal((await response.json()).ignored, true);
  assert.equal(touched, false);
});

for (const amount of ["abc", "-5000000", "1.5", "1e6", ""]) {
  test(`a malformed amount ${JSON.stringify(amount)} is rejected before anything is recorded`, async () => {
    process.env.WEBHOOK_SECRET = SECRET;
    let touched = false;
    const body = capturedEvent({ amount });

    const response = await handleWebhook(request(body, sign(body)), untouchedSupabase(() => (touched = true)));

    assert.equal(response.status, 400);
    assert.equal(touched, false);
  });
}

test("a Captured event without an amount is rejected before anything is recorded", async () => {
  process.env.WEBHOOK_SECRET = SECRET;
  let touched = false;
  const body = capturedEvent({});

  const response = await handleWebhook(request(body, sign(body)), untouchedSupabase(() => (touched = true)));

  assert.equal(response.status, 400);
  assert.equal(touched, false);
});

test("the amount reaches the RPC as an exact decimal string", async () => {
  process.env.WEBHOOK_SECRET = SECRET;
  const body = capturedEvent({ amount: "123456789012345678" });
  let rpcArgs: Record<string, unknown> | undefined;

  const supabase = {
    from() {
      return {
        select() {
          return { filter: () => ({ single: async () => ({ data: { id: "order-1" }, error: null }) }) };
        },
      };
    },
    rpc: async (_name: string, args: Record<string, unknown>) => {
      rpcArgs = args;
      return { data: true, error: null };
    },
  } as never;

  const response = await handleWebhook(request(body, sign(body)), supabase);

  assert.equal(response.status, 200);
  assert.equal(rpcArgs?.p_amount, "123456789012.345678");
  assert.equal(rpcArgs?.p_note, null);
});

test("a missing WEBHOOK_SECRET fails closed with 503", async () => {
  delete process.env.WEBHOOK_SECRET;
  let touched = false;
  const body = capturedEvent({ amount: "1" });

  const response = await handleWebhook(request(body, "sig"), untouchedSupabase(() => (touched = true)));

  assert.equal(response.status, 503);
  assert.equal(touched, false);
  process.env.WEBHOOK_SECRET = SECRET;
});
