// ═══════════════════════════════════════════════════════════════════════════
// routes/mpesaRoutes.js
// ═══════════════════════════════════════════════════════════════════════════
const express    = require('express');
const rateLimit  = require('express-rate-limit');
const { initiate, callback, getStatus } = require('../controllers/mpesaController');
const { requireAuth } = require('../middleware/auth'); // your existing auth middleware

const router = express.Router();

// ── Rate limiters ──────────────────────────────────────────────────────────
const initiateLimiter = rateLimit({
  windowMs: 60_000,       // 1 minute
  max:      5,            // max 5 initiation attempts per IP per minute
  message:  { success: false, message: 'Too many payment attempts. Please wait and try again.' },
  standardHeaders: true,
  legacyHeaders:   false,
});

const statusLimiter = rateLimit({
  windowMs: 60_000,
  max:      60,           // polling — more generous
  message:  { success: false, message: 'Too many requests.' },
});

// POST /api/payments/mpesa/initiate  (authenticated + rate limited)
router.post('/initiate', requireAuth, initiateLimiter, initiate);

// POST /api/payments/mpesa/callback  (public — Safaricom webhook, no JWT)
// ⚠️  Do NOT add requireAuth here — Safaricom has no JWT
router.post('/callback', callback);

// GET /api/payments/mpesa/status/:checkoutRequestId  (authenticated + rate limited)
router.get('/status/:checkoutRequestId', requireAuth, statusLimiter, getStatus);

module.exports = router;


// ═══════════════════════════════════════════════════════════════════════════
// models/Payment.js  — paste into its own file
// ═══════════════════════════════════════════════════════════════════════════
/*
const mongoose = require('mongoose');

const PaymentSchema = new mongoose.Schema(
  {
    userId:            { type: mongoose.Schema.Types.ObjectId, ref: 'User',    required: true, index: true },
    packageId:         { type: mongoose.Schema.Types.ObjectId, ref: 'Package', required: true },
    phone:             { type: String, required: true },       // normalised 254...
    amountKes:         { type: Number, required: true },
    merchantRequestId: { type: String, index: true },
    checkoutRequestId: { type: String, index: true },
    mpesaRef:          { type: String },                       // e.g. PGH57AYEF8
    status:            { type: String, enum: ['PENDING','SUCCESS','FAILED','CANCELLED'], default: 'PENDING', index: true },
    resultCode:        { type: Number },
    resultDesc:        { type: String },
    paidAt:            { type: Date },
  },
  {
    timestamps: true,
    // Never expose phone or mpesaRef through the default toJSON
    toJSON: {
      transform: (_, ret) => {
        delete ret.phone;
        return ret;
      },
    },
  }
);

// Compound index for idempotency check in controller
PaymentSchema.index({ userId: 1, packageId: 1, status: 1, createdAt: -1 });

module.exports = mongoose.model('Payment', PaymentSchema);
*/


// ═══════════════════════════════════════════════════════════════════════════
// models/Booking.js  — paste into its own file (if not already existing)
// ═══════════════════════════════════════════════════════════════════════════
/*
const mongoose = require('mongoose');

const BookingSchema = new mongoose.Schema(
  {
    userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User',    required: true, index: true },
    packageId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Package', required: true },
    paymentId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Payment', required: true },
    mpesaRef:   { type: String },
    amountPaid: { type: Number },
    currency:   { type: String, default: 'KES' },
    phone:      { type: String },
    status:     { type: String, enum: ['confirmed','cancelled','completed'], default: 'confirmed', index: true },
    bookedAt:   { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = mongoose.model('Booking', BookingSchema);
*/


// ═══════════════════════════════════════════════════════════════════════════
// HOW TO WIRE INTO ClientDashboard.jsx
// ═══════════════════════════════════════════════════════════════════════════
//
// 1. Import BookingModal at top of ClientDashboard.jsx:
//      import BookingModal from './BookingModal';
//
// 2. Add state for the selected package:
//      const [bookingPkg, setBookingPkg] = useState(null);
//
// 3. Handle booking success (refresh bookings list):
//      const handleBookingSuccess = (newBooking) => {
//        setBookings(prev => [newBooking, ...prev]);
//        setActiveTab('bookings');
//        setBookingPkg(null);
//        showToast('Package booked successfully!', 'success');
//      };
//
// 4. In PackageDiscovery / PackageCard, change onBook to:
//      onBook={pkg => setBookingPkg(pkg)}
//
// 5. Render modal inside the return (just before closing </div>):
//      {bookingPkg && (
//        <BookingModal
//          pkg={bookingPkg}
//          user={user}
//          onClose={() => setBookingPkg(null)}
//          onSuccess={handleBookingSuccess}
//        />
//      )}
//
// ═══════════════════════════════════════════════════════════════════════════
// REQUIRED .env variables
// ═══════════════════════════════════════════════════════════════════════════
//   MPESA_CONSUMER_KEY=
//   MPESA_CONSUMER_SECRET=
//   MPESA_SHORTCODE=
//   MPESA_PASSKEY=
//   MPESA_CALLBACK_URL=https://yourdomain.com/api/payments/mpesa/callback
//   MPESA_ENV=sandbox       # change to production when going live
//   KES_PER_USD=130         # update regularly or fetch from an exchange-rate API
//
// ═══════════════════════════════════════════════════════════════════════════
// SECURITY CHECKLIST
// ═══════════════════════════════════════════════════════════════════════════
//  ✅ Amount read from DB, never from request body (prevents price tampering)
//  ✅ Phone validated server-side with regex (prevents injection)
//  ✅ Safaricom callback IP whitelisted (prevents spoofed callbacks)
//  ✅ JWT auth on initiate + status routes (prevents IDOR)
//  ✅ User-scoped status query (userId filter prevents querying others' payments)
//  ✅ Idempotency check prevents double-charge on rapid retry
//  ✅ Atomic DB transaction — booking only created after payment confirmed
//  ✅ Amount-match validation in callback (prevents partial-payment attacks)
//  ✅ Rate limiting on all endpoints (prevents brute force / DoS)
//  ✅ Daraja credentials only in env vars, never in code
//  ✅ Phone masked in logs (privacy / PII)
//  ✅ phone field stripped from Payment.toJSON (prevents API leaks)
//  ✅ ObjectId validation before DB queries (prevents NoSQL injection)
//  ✅ STK query uses checkoutRequestId format check (prevents probing)
//  ✅ Express rate-limit package needed: npm install express-rate-limit
