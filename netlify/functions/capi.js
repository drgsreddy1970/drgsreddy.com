// netlify/functions/capi.js
// Meta Conversions API relay. Deploys with the site on Netlify.
//
// The access token is NEVER stored in this file or the repo.
// Set it in Netlify:  Site configuration > Environment variables
//   META_CAPI_TOKEN   = <the token>            (required)
//   META_PIXEL_ID     = 1350797673305876       (optional, defaults below)
//   META_TEST_EVENT_CODE = TESTxxxxx           (optional, only while testing)
//
// The browser (GTM) POSTs an event here with a shared event_id. This function
// hashes any PII, adds IP + user agent, and forwards to Meta. Meta dedupes the
// server event against the pixel event using the shared event_id.

const crypto = require("crypto");

const PIXEL_ID = process.env.META_PIXEL_ID || "1350797673305876";
const TOKEN = process.env.META_CAPI_TOKEN;
const API_VERSION = "v21.0";
const ALLOWED_EVENTS = new Set(["Lead", "Contact", "PageView", "ViewContent"]);
const ALLOWED_ORIGINS = ["https://drgsreddy.com", "https://www.drgsreddy.com"];

const sha256 = (v) =>
  crypto.createHash("sha256").update(String(v).trim().toLowerCase()).digest("hex");

// digits only; caller should send phone WITH country code, e.g. 917075523360
const normPhone = (v) => String(v).replace(/[^0-9]/g, "");

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }
  if (!TOKEN) {
    return { statusCode: 500, body: "CAPI token not configured" };
  }

  const origin = event.headers.origin || event.headers.referer || "";
  if (origin && !ALLOWED_ORIGINS.some((o) => origin.startsWith(o))) {
    return { statusCode: 403, body: "Forbidden origin" };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, body: "Bad JSON" };
  }

  const {
    event_name,
    event_id,
    event_source_url,
    email,
    phone,
    fbp,
    fbc,
    test_event_code,
  } = body;

  if (!ALLOWED_EVENTS.has(event_name)) {
    return { statusCode: 400, body: "Unsupported event_name" };
  }

  const ip =
    event.headers["x-nf-client-connection-ip"] ||
    (event.headers["x-forwarded-for"] || "").split(",")[0].trim();
  const ua = event.headers["user-agent"] || "";

  const user_data = {};
  if (email) user_data.em = [sha256(email)];
  if (phone) user_data.ph = [sha256(normPhone(phone))];
  if (fbp) user_data.fbp = fbp;
  if (fbc) user_data.fbc = fbc;
  if (ip) user_data.client_ip_address = ip;
  if (ua) user_data.client_user_agent = ua;

  const payload = {
    data: [
      {
        event_name,
        event_time: Math.floor(Date.now() / 1000),
        event_id: event_id || crypto.randomUUID(),
        event_source_url: event_source_url || origin,
        action_source: "website",
        user_data,
      },
    ],
  };

  const code = test_event_code || process.env.META_TEST_EVENT_CODE;
  if (code) payload.test_event_code = code;

  const url =
    `https://graph.facebook.com/${API_VERSION}/${PIXEL_ID}/events` +
    `?access_token=${encodeURIComponent(TOKEN)}`;

  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    return {
      statusCode: r.ok ? 200 : 502,
      headers: { "Content-Type": "application/json" },
      body: text,
    };
  } catch (e) {
    return { statusCode: 502, body: "CAPI forward failed" };
  }
};
