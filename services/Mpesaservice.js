// services/Mpesaservice.js
// Safaricom Daraja API — STK Push & Query
//
// Required env vars (set these in Render dashboard):
//   MPESA_CONSUMER_KEY
//   MPESA_CONSUMER_SECRET
//   MPESA_SHORTCODE          ← your Paybill or Till number
//   MPESA_PASSKEY            ← from Safaricom portal
//   MPESA_CALLBACK_URL       ← must be public HTTPS e.g. https://umrahmarket-backend.onrender.com/api/payments/mpesa/callback
//   MPESA_ENV                ← 'sandbox' or 'production'

import axios from 'axios';

const MPESA_ENV = (process.env.MPESA_ENV || 'sandbox').toLowerCase();
const BASE_URL  = MPESA_ENV === 'production'
  ? 'https://api.safaricom.co.ke'
  : 'https://sandbox.safaricom.co.ke';

// ── Token cache (in-memory, safe — not a secret at runtime) ──────────────────
let _tokenCache = { token: null, expiresAt: 0 };

async function getAccessToken() {
  if (_tokenCache.token && Date.now() < _tokenCache.expiresAt) {
    return _tokenCache.token;
  }

  const key    = process.env.MPESA_CONSUMER_KEY;
  const secret = process.env.MPESA_CONSUMER_SECRET;

  if (!key || !secret) {
    throw new Error('MPESA_CONSUMER_KEY or MPESA_CONSUMER_SECRET is not set in environment variables');
  }

  const credentials = Buffer.from(`${key}:${secret}`).toString('base64');

  let res;
  try {
    res = await axios.get(
      `${BASE_URL}/oauth/v1/generate?grant_type=client_credentials`,
      {
        headers: { Authorization: `Basic ${credentials}` },
        timeout: 10_000,
      }
    );
  } catch (err) {
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    throw new Error(`Daraja OAuth failed: ${detail}`);
  }

  if (!res.data?.access_token) {
    throw new Error(`Daraja returned no access_token: ${JSON.stringify(res.data)}`);
  }

  const ttl = parseInt(res.data.expires_in || '3600', 10);
  _tokenCache = {
    token:     res.data.access_token,
    expiresAt: Date.now() + (ttl - 60) * 1000, // refresh 60s early
  };

  return _tokenCache.token;
}

function buildPassword() {
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey   = process.env.MPESA_PASSKEY;

  if (!shortcode) throw new Error('MPESA_SHORTCODE is not set');
  if (!passkey)   throw new Error('MPESA_PASSKEY is not set');

  // Timestamp format: YYYYMMDDHHmmss
  const ts = new Date()
    .toISOString()
    .replace(/[-:T.Z]/g, '')
    .slice(0, 14);

  const password = Buffer.from(`${shortcode}${passkey}${ts}`).toString('base64');
  return { password, timestamp: ts };
}

// ── STK Push ─────────────────────────────────────────────────────────────────
// Returns the full Daraja response object (PascalCase keys from Safaricom)
export async function stkPush({ phone, amount, accountRef, description }) {
  const token              = await getAccessToken();
  const { password, timestamp } = buildPassword();
  const shortcode          = process.env.MPESA_SHORTCODE;
  const callbackUrl        = process.env.MPESA_CALLBACK_URL;

  if (!callbackUrl) throw new Error('MPESA_CALLBACK_URL is not set');

  const payload = {
    BusinessShortCode: shortcode,
    Password:          password,
    Timestamp:         timestamp,
    TransactionType:   'CustomerPayBillOnline', // use CustomerBuyGoodsOnline for Till
    Amount:            Math.ceil(Number(amount)),
    PartyA:            phone,
    PartyB:            shortcode,
    PhoneNumber:       phone,
    CallBackURL:       callbackUrl,
    AccountReference:  String(accountRef).slice(0, 12),  // Daraja max 12 chars
    TransactionDesc:   String(description).slice(0, 13), // Daraja max 13 chars
  };

  let res;
  try {
    res = await axios.post(
      `${BASE_URL}/mpesa/stkpush/v1/processrequest`,
      payload,
      {
        headers: {
          Authorization:  `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        timeout: 15_000,
      }
    );
  } catch (err) {
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    throw new Error(`STK push HTTP error: ${detail}`);
  }

  if (res.data.ResponseCode !== '0') {
    throw new Error(`STK push rejected by Daraja: ${res.data.ResponseDescription || JSON.stringify(res.data)}`);
  }

  // Return PascalCase as Safaricom sends it — controller normalises both casings
  return res.data;
  // res.data shape: { MerchantRequestID, CheckoutRequestID, ResponseCode, ResponseDescription, CustomerMessage }
}

// ── STK Query (check status of existing push) ────────────────────────────────
export async function stkQuery(checkoutRequestId) {
  const token              = await getAccessToken();
  const { password, timestamp } = buildPassword();
  const shortcode          = process.env.MPESA_SHORTCODE;

  let res;
  try {
    res = await axios.post(
      `${BASE_URL}/mpesa/stkpushquery/v1/query`,
      {
        BusinessShortCode: shortcode,
        Password:          password,
        Timestamp:         timestamp,
        CheckoutRequestID: checkoutRequestId,
      },
      {
        headers: {
          Authorization:  `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        timeout: 10_000,
      }
    );
  } catch (err) {
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    throw new Error(`STK query HTTP error: ${detail}`);
  }

  return res.data;
  // res.data shape: { ResponseCode, ResponseDescription, MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc }
}