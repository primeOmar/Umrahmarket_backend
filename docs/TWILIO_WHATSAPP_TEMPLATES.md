# Twilio WhatsApp Automation Guide

Business-initiated WhatsApp messages (outside the 24h reply window) **must** use
Meta-approved templates. The backend sends them through
`services/whatsappService.js` → `sendWhatsAppTemplate({ to, templateSid, variables })`.

## 1. Prerequisites

1. Twilio account (upgraded, not trial).
2. WhatsApp sender: Console → Messaging → Senders → WhatsApp senders. Needs a verified Meta Business account, a number that is not already on WhatsApp, and an approved display name.
3. Environment variables (`.env`):

```env
TWILIO_ACCOUNT_SID=ACxxxxxxxx
TWILIO_AUTH_TOKEN=xxxxxxxx
TWILIO_WHATSAPP_FROM=whatsapp:+254XXXXXXXXX
TWILIO_STATUS_CALLBACK_URL=https://api.umrahmarket.net/api/whatsapp/status
FRONTEND_URL=https://umrahmarket.net

# Template SIDs (HX...) – filled in after approval
TWILIO_TEMPLATE_CUSTOM_REQUEST_REPLY_SID=HX...
WHATSAPP_TEMPLATE_BOOKING_CONFIRMED=HX...
TWILIO_TEMPLATE_WELCOME_SID=HX...
TWILIO_TEMPLATE_REMINDER_SID=HX...
TWILIO_TEMPLATE_TASK_ASSIGNED_SID=HX...
TWILIO_TEMPLATE_AGENT_PACKAGE_REMINDER_SID=HX...
ENABLE_AGENT_PACKAGE_REMINDERS=false   # true = weekly automatic reminder
```

## 2. Creating a template

Console → Messaging → Content Template Builder → **Create new** → type *Text* (or *Call to action* for buttons) → channel **WhatsApp**.

1. Name: lowercase + underscores, language `en` (add `sw` as a separate translation if wanted).
2. Category: **Utility** for transactional messages (Marketing for promos – costs more, needs opt-in).
3. Paste the body, add a **sample value** for every `{{n}}`.
4. Click **Save and submit for WhatsApp approval** (usually minutes to 24h).
5. Copy the Content SID (`HX…`) into `.env`, restart the server.

Rules: variables cannot contain newlines/tabs or 4+ spaces; do not start/end the body with a variable; keep a sensible text-to-variable ratio; no promotional wording in Utility templates.

## 3. Template definitions

### 3.1 `custom_request_reply` — client: agent replied to custom request (currently used)
Env: `TWILIO_TEMPLATE_CUSTOM_REQUEST_REPLY_SID` · Code: `notifyClientOfReply` in `controllers/inquiries.controller.js`

Variables sent: `1` = request reference, `2` = summary text + dashboard link.

```
Assalamu alaikum. An agent is ready to offer your custom Umrah package request {{1}}. {{2}} Log in to review the details, then upload passports and proceed to payment if you are happy.
```
Samples: `{{1}}` = `REQ-1A2B3C`, `{{2}}` = `Price from USD 1,450 pp. Open: https://umrahmarket.net/client/dashboard?tab=custom&request=123`

### 3.2 `custom_offer_ready_v2` — recommended replacement (cleaner, dynamic button)
Type: *Call to action*. Requires a small code change: send variables `1` client first name, `2` reference, `3` price text; URL button suffix variable `4` = request id.

```
Assalamu alaikum {{1}}, good news! An agent has offered to arrange your custom package request {{2}} from {{3}}. Tap below to review the details, upload passports for all travellers and pay securely.
```
Button (URL): `https://umrahmarket.net/client/dashboard?tab=custom&request={{4}}` — label `View offer`.
Samples: `Amina`, `REQ-1A2B3C`, `USD 1,450 per adult`, `123`.

### 3.3 `booking_confirmed` — client
Env: `WHATSAPP_TEMPLATE_BOOKING_CONFIRMED` · Variables: 1 name, 2 package, 3 booking ref, 4 total, 5 receipt URL.

```
Hello {{1}}, your booking for {{2}} is confirmed. Reference: {{3}}. Total paid: {{4}}. Receipt: {{5}} Thank you for choosing Umrah Market.
```

### 3.4 Agent notices (`services/agentVerification.service.js`)
Each takes `1` = first name.

`TWILIO_TEMPLATE_WELCOME_SID` — `agent_welcome`
```
Hello {{1}}, welcome to Umrah Market! Your agent account has been approved. Log in to your dashboard to create packages and receive client requests.
```
`TWILIO_TEMPLATE_REMINDER_SID` — `agent_document_reminder`
```
Hello {{1}}, a reminder that your verification documents are still pending. Please log in to your dashboard to complete them so you can start receiving bookings.
```
`TWILIO_TEMPLATE_TASK_ASSIGNED_SID` — `agent_task_assigned`
```
Hello {{1}}, a new verification task has been assigned to you. Please log in to your dashboard to review and respond.
```

### 3.5 `agent_package_reminder` — all agents: log in and add packages (NEW, wired)
Env: `TWILIO_TEMPLATE_AGENT_PACKAGE_REMINDER_SID` · Code: `services/agentPackageReminder.service.js` · Variable `1` = agent first name. Category: **Utility**.

```
Assalamu alaikum {{1}}, your UmrahMarket agent account is ready but travellers cannot book what is not listed yet. Log in to your dashboard to add your Umrah packages and start receiving bookings.
```
Sample: `{{1}}` = `Omar`. Optional button (URL, static): `` — label `Open dashboard`.

How it is triggered:
- **Superadmin dashboard → WhatsApp → "Remind agents"** (optionally only agents with no packages). Agents already reminded within `AGENT_REMINDER_COOLDOWN_DAYS` (default 6) are skipped.
- **Automatic weekly job** (off by default): `ENABLE_AGENT_PACKAGE_REMINDERS=true`, schedule `AGENT_PACKAGE_REMINDER_CRON` (default `0 9 * * 1`, Monday 09:00 Nairobi).

### 3.6 Manual broadcasts from the superadmin dashboard
**Superadmin → WhatsApp → Send a message** lets you pick any approved template from Twilio, choose all agents / selected agents / all clients, and paste extra phone numbers (people who are not in the system). Use `{name}` in a variable to insert each person's first name. Run `sql/2026_whatsapp_messaging.sql` once in Supabase before first use.

### 3.7 `agent_invitation` — invite unregistered agents to register (manual broadcast)
No `.env` entry needed: it appears in **Superadmin → WhatsApp → Template** once approved. Category: **Marketing**. Type: *Call to action* with one static URL button.

```
Assalamu alaikum {{1}}, UmrahMarket is a trusted marketplace connecting licensed Umrah agents with travellers in Kenya and Tanzania. List your packages, receive bookings and get paid securely. Register as an agent in minutes using the button below.
```
Button (URL): `https://umrahmarket.net/register` — label `Register as an agent` (use your real agent sign-up URL).
Sample: `{{1}}` = `Omar`.

Usage: choose **Phone numbers only**, paste the numbers, set variable `{{1}}` to `{name}` (becomes "there" for people not in the system). Only message people who have agreed to hear from you; start with 20–50 numbers and watch the failures list. Add "Reply STOP to opt out" for repeat campaigns and never message anyone who opts out.

### 3.8 Suggested additions (not yet wired)
- `agent_offer_decision` (Utility): `Hello {{1}}, the client has {{2}} your offer for request {{3}}. Log in to your dashboard for next steps.`
- `payment_received` (Utility): `Hello {{1}}, we received your payment of {{2}} for {{3}}. Your booking reference is {{4}}.`
- `passport_reminder` (Utility): `Hello {{1}}, please upload passports for all travellers on {{2}} to complete your booking.`

## 4. Adding a new automated message

```js
import { sendWhatsAppTemplate } from '../services/whatsappService.js';

await sendWhatsAppTemplate({
  to: profile.phone,                       // normalised to E.164 internally
  templateSid: process.env.TWILIO_TEMPLATE_PAYMENT_RECEIVED_SID,
  templateName: 'payment_received',
  variables: { 1: firstName, 2: amount, 3: packageTitle, 4: ref },
  category: 'utility',
});
```
Always wrap in try/catch so a failed notification never blocks the main request, and skip when the SID is unset (as `notifyClientOfReply` does).

## 5. Delivery tracking
In the WhatsApp sender settings set **Status callback URL** to `https://api.umrahmarket.net/api/whatsapp/status` (same as `TWILIO_STATUS_CALLBACK_URL`). Statuses (queued → sent → delivered → read/failed) are written to the `whatsapp_messages` table.

## 6. Testing
1. Sandbox: Console → Messaging → Try it out → WhatsApp; join with the `join <code>` message, set `TWILIO_WHATSAPP_FROM=whatsapp:+14155238886`. Templates still need to be approved for production senders.
2. Create a custom request as a client (with a phone on the profile), reply as an approved agent, and check the `whatsapp_messages` row and your phone.

## 7. Troubleshooting

| Code | Meaning | Fix |
|------|---------|-----|
| 63016 | Free-form message outside 24h window | Use an approved template |
| 63049 | Meta refused to deliver (marketing limits) | Use Utility category / ensure opt-in |
| 63024 | Invalid recipient | Check E.164 number on the profile |
| 63007 | Sender not found | Check `TWILIO_WHATSAPP_FROM` format `whatsapp:+…` |
| 21211 | Invalid `To` number | Fix phone formatting |
| 20003 | Auth error | Check SID/token |

## 8. Compliance
Only message users who have opted in (`whatsapp_opt_in`), include an opt-out path for marketing messages, and keep Utility templates strictly transactional.
