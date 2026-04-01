/**
 * mpesaService.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Server-side Safaricom Daraja API helper.
 *
 * ALL secrets (consumer key/secret, passkey, shortcode) are read from env vars.
 * NOTHING is ever sent to the frontend.
 *
 * Required env vars:
 *   MPESA_ENV              = 'sandbox' | 'production'
 *   MPESA_CONSUMER_KEY     = your Daraja app consumer key
 *   MPESA_CONSUMER_SECRET  = your Daraja app consumer secret
 *   MPESA_SHORTCODE        = your paybill / till number
 *   MPESA_PASSKEY          = your LipaNaMpesa online passkey
 *   MPESA_CALLBACK_URL     = publicly accessible URL e.g. https://api.yourdomain.com/api/payments/mpesa/callback
 */

import axios from 'axios';
import crypto from 'crypto';

const IS_SANDBOX = (process.env.MPESA_ENV || 'sandbox') === 'sandbox';

const DARAJA = {
  base:    IS_SANDBOX ? 'https://sandbox.safaricom.co.ke' : 'https://api.safaricom.co.ke',
  authUrl: '/oauth/v1/generate?grant_type=client_credentials',
  stkUrl:  '/mpesa/stkpush/v1/processrequest',
  queryUrl:'/mpesa/stkpushquery/v1/query',
};

// ─── Token cache (access tokens are valid for 1 hour) ─────────────────────────
let _cachedToken    = null;
let _tokenExpiresAt = 0;

async function getAccessToken() {
  if (_cachedToken && Date.now() < _tokenExpiresAt - 60_000) return _cachedToken;

  const key    = process.env.MPESA_CONSUMER_KEY;
  const secret = process.env.MPESA_CONSUMER_SECRET;
  if (!key || !secret) throw new Error('M-Pesa credentials not configured');

  const credentials = Buffer.from(`${key}:${secret}`).toString('base64');
  const res = await axios.get(`${DARAJA.base}${DARAJA.authUrl}`, {
    headers: { Authorization: `Basic ${credentials}` },
    timeout: 10_000,
  });

  _cachedToken    = res.data.access_token;
  _tokenExpiresAt = Date.now() + (parseInt(res.data.expires_in, 10) * 1000);
  return _cachedToken;
}

// ─── Build password & timestamp ───────────────────────────────────────────────
function buildPassword() {
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey   = process.env.MPESA_PASSKEY;
  if (!shortcode || !passkey) throw new Error('M-Pesa shortcode/passkey not configured');

  const timestamp = new Date()
    .toISOString()
    .replace(/[-:T.Z]/g, '')
    .slice(0, 14); // YYYYMMDDHHmmss

  const password = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
  return { password, timestamp };
}

// ─── STK Push ─────────────────────────────────────────────────────────────────
/**
 * Initiates a Lipa Na M-Pesa Online (STK push) payment.
 *
 * @param {object} opts
 * @param {string} opts.phone     - Normalised phone e.g. 254712345678
 * @param {number} opts.amountKes - Amount in KES (integer)
 * @param {string} opts.accountRef - Short booking reference shown to user on phone
 * @param {string} opts.description - Transaction description
 * @returns Daraja response (MerchantRequestID, CheckoutRequestID, ResponseCode)
 */
export async function stkPush({ phone, amountKes, accountRef, description }) {
  const token = await getAccessToken();
  const { password, timestamp } = buildPassword();

  const payload = {
    BusinessShortCode: process.env.MPESA_SHORTCODE,
    Password:          password,
    Timestamp:         timestamp,
    TransactionType:   'CustomerPayBillOnline',
    Amount:            Math.ceil(amountKes),   // must be integer
    PartyA:            phone,
    PartyB:            process.env.MPESA_SHORTCODE,
    PhoneNumber:       phone,
    CallBackURL:       process.env.MPESA_CALLBACK_URL,
    AccountReference:  accountRef.slice(0, 12), // Daraja max 12 chars
    TransactionDesc:   description.slice(0, 13), // Daraja max 13 chars
  };

  const res = await axios.post(`${DARAJA.base}${DARAJA.stkUrl}`, payload, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    timeout: 15_000,
  });

  // ResponseCode '0' = success (prompt sent to phone)
  if (res.data.ResponseCode !== '0') {
    throw new Error(`STK push rejected: ${res.data.ResponseDescription}`);
  }

  return {
    merchantRequestId:  res.data.MerchantRequestID,
    checkoutRequestId:  res.data.CheckoutRequestID,
    responseCode:       res.data.ResponseCode,
    responseDescription: res.data.ResponseDescription,
  };
}

// ─── STK Query ────────────────────────────────────────────────────────────────
/**
 * Queries the status of a pending STK push transaction.
 * Used as fallback when the callback is delayed.
 *
 * @param {string} checkoutRequestId
 * @returns {{ resultCode: string, resultDesc: string }}
 */
export async function stkQuery(checkoutRequestId) {
  const token = await getAccessToken();
  const { password, timestamp } = buildPassword();

  const payload = {
    BusinessShortCode: process.env.MPESA_SHORTCODE,
    Password:          password,
    Timestamp:         timestamp,
    CheckoutRequestID: checkoutRequestId,
  };

  const res = await axios.post(`${DARAJA.base}${DARAJA.queryUrl}`, payload, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    timeout: 10_000,
  });

  return {
    resultCode: res.data.ResultCode,
    resultDesc: res.data.ResultDesc,
  };
}

// ─── Callback signature validation ────────────────────────────────────────────
/**
 * Optional: Validate that an incoming M-Pesa callback originated from Safaricom.
 * In production, whitelist Safaricom IPs at the firewall level as well.
 *
 * Safaricom sandbox does NOT sign callbacks, so this is only meaningful in production.
 * Pass a secret you've pre-shared (e.g. in the callback URL as a query param token)
 * and compare it to the one Safaricom sends back.
 *
 * @param {string} receivedSecret - Value from incoming request
 * @param {string} expectedSecret - Your stored secret
 */
export function validateCallbackSecret(receivedSecret, expectedSecret) {
  if (!receivedSecret || !expectedSecret) return false;
  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(receivedSecret),
    Buffer.from(expectedSecret),
  );
}