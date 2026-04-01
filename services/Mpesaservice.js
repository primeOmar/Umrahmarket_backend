// services/mpesaService.js
import axios  from 'axios';
import crypto from 'crypto';

const IS_SANDBOX = (process.env.MPESA_ENV || 'sandbox') === 'sandbox';

const DARAJA = {
  base:     IS_SANDBOX ? 'https://sandbox.safaricom.co.ke' : 'https://api.safaricom.co.ke',
  authUrl:  '/oauth/v1/generate?grant_type=client_credentials',
  stkUrl:   '/mpesa/stkpush/v1/processrequest',
  queryUrl: '/mpesa/stkpushquery/v1/query',
};

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

function buildPassword() {
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey   = process.env.MPESA_PASSKEY;
  if (!shortcode || !passkey) throw new Error('M-Pesa shortcode/passkey not configured');
  const timestamp = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
  const password  = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
  return { password, timestamp };
}

export async function stkPush({ phone, amount, accountRef, description }) {
  const token = await getAccessToken();
  const { password, timestamp } = buildPassword();
  const payload = {
    BusinessShortCode: process.env.MPESA_SHORTCODE,
    Password:          password,
    Timestamp:         timestamp,
    TransactionType:   'CustomerPayBillOnline',
    Amount:            Math.ceil(amount),
    PartyA:            phone,
    PartyB:            process.env.MPESA_SHORTCODE,
    PhoneNumber:       phone,
    CallBackURL:       process.env.MPESA_CALLBACK_URL,
    AccountReference:  accountRef.slice(0, 12),
    TransactionDesc:   description.slice(0, 13),
  };
  const res = await axios.post(`${DARAJA.base}${DARAJA.stkUrl}`, payload, {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    timeout: 15_000,
  });
  if (res.data.ResponseCode !== '0')
    throw new Error(`STK push rejected: ${res.data.ResponseDescription}`);
  return {
    merchantRequestId:   res.data.MerchantRequestID,
    checkoutRequestId:   res.data.CheckoutRequestID,
    responseCode:        res.data.ResponseCode,
    responseDescription: res.data.ResponseDescription,
  };
}

export async function stkQuery(checkoutRequestId) {
  const token = await getAccessToken();
  const { password, timestamp } = buildPassword();
  const res = await axios.post(`${DARAJA.base}${DARAJA.queryUrl}`,
    { BusinessShortCode: process.env.MPESA_SHORTCODE, Password: password, Timestamp: timestamp, CheckoutRequestID: checkoutRequestId },
    { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, timeout: 10_000 }
  );
  return { resultCode: res.data.ResultCode, resultDesc: res.data.ResultDesc };
}

export function validateCallbackSecret(received, expected) {
  if (!received || !expected) return false;
  return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected));
}