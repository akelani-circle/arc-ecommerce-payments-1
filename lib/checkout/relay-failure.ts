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

/**
 * The authorize route answers `orderPersisted: false` with the tx hash when the
 * payment landed on-chain but the order row could not be saved. Returns that
 * hash, so the client can stop the shopper from paying again; null otherwise.
 */
export function settledTxHash(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return null;
  if (!("orderPersisted" in body) || body.orderPersisted !== false) return null;
  if (!("txHash" in body) || typeof body.txHash !== "string") return null;
  return body.txHash;
}
