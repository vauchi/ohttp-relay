// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

// k6 Load Test for Vauchi OHTTP Relay
//
// Tests HTTP throughput and latency for the OHTTP forwarding proxy.
// Requires a mock upstream gateway (started by CI) to accept forwarded blobs.
//
// Usage:
//   k6 run ohttp-relay/tests/load/ohttp-relay-load-test.js
//   k6 run --env RELAY_URL=http://staging:8082 ohttp-relay/tests/load/ohttp-relay-load-test.js

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// ============================================================
// Configuration
// ============================================================

const RELAY_URL = __ENV.RELAY_URL || "http://127.0.0.1:8082";

export const options = {
  stages: [
    { duration: "10s", target: 20 },  // Ramp up to 20 VUs
    { duration: "40s", target: 20 },  // Sustain 20 VUs
    { duration: "10s", target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ["p(95)<500"],        // p95 latency < 500ms
    ohttp_forward_duration: ["p(95)<500"],   // p95 OHTTP forward < 500ms
    ohttp_key_duration: ["p(95)<300"],       // p95 key fetch < 300ms
    health_duration: ["p(95)<100"],          // p95 health < 100ms
    forward_success_rate: ["rate>0.95"],     // >95% success rate
  },
};

// ============================================================
// Custom metrics
// ============================================================

const ohttpForwardDuration = new Trend("ohttp_forward_duration", true);
const ohttpKeyDuration = new Trend("ohttp_key_duration", true);
const healthDuration = new Trend("health_duration", true);
const forwardSuccessRate = new Rate("forward_success_rate");
const forwardErrors = new Counter("forward_errors");

// ============================================================
// Helpers
// ============================================================

// Generate a random opaque blob (simulates encrypted OHTTP payload)
function generateOpaqueBlob(size) {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes.buffer;
}

// ============================================================
// Main scenario
// ============================================================

export default function () {
  // 70% OHTTP forward, 20% key fetch, 10% health
  const roll = Math.random();

  if (roll < 0.7) {
    // POST /v2/ohttp — forward encrypted blob
    const blob = generateOpaqueBlob(512);
    const res = http.post(`${RELAY_URL}/v2/ohttp`, blob, {
      headers: { "Content-Type": "message/ohttp-req" },
      tags: { endpoint: "ohttp-forward" },
    });

    const success = res.status === 200;
    forwardSuccessRate.add(success);
    ohttpForwardDuration.add(res.timings.duration);

    if (!success) {
      forwardErrors.add(1);
    }

    check(res, {
      "OHTTP forward returns 200": (r) => r.status === 200,
      "OHTTP response has correct content-type": (r) =>
        r.headers["Content-Type"] === "message/ohttp-res",
    });
  } else if (roll < 0.9) {
    // GET /v2/ohttp-key — fetch OHTTP key
    const res = http.get(`${RELAY_URL}/v2/ohttp-key`, {
      tags: { endpoint: "ohttp-key" },
    });

    ohttpKeyDuration.add(res.timings.duration);

    check(res, {
      "Key fetch returns 200": (r) => r.status === 200,
      "Key response has correct content-type": (r) =>
        r.headers["Content-Type"] === "application/ohttp-keys",
    });
  } else {
    // GET /health
    const res = http.get(`${RELAY_URL}/health`, {
      tags: { endpoint: "health" },
    });

    healthDuration.add(res.timings.duration);

    check(res, {
      "Health returns 200": (r) => r.status === 200,
      "Health body is ok": (r) => r.body === "ok",
    });
  }

  sleep(0.1);
}
