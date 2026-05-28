// models/Payment.js
import mongoose from 'mongoose';

const PaymentSchema = new mongoose.Schema(
  {
    userId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'User',
      required: true,
      index:    true,
    },
    packageId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'Package',
      required: true,
      index:    true,
    },
    phone: {
      type:     String,
      required: true,   // normalised 254XXXXXXXXX — masked in toJSON
    },
    amountKes: {
      type:     Number,
      required: true,
    },
    method: {
      type:    String,
      enum:    ['MPESA', 'CARD', 'BANK'],
      default: 'MPESA',
    },

    // ── M-Pesa specific ──────────────────────────────────────────────────
    merchantRequestId: {
      type:  String,
      index: true,
    },
    checkoutRequestId: {
      type:  String,
      index: true,
      sparse: true,     // allows null for card/bank payments
    },
    mpesaRef: {
      type: String,     // e.g. PGH57AYEF8  — Safaricom receipt number
    },

    // ── Card (Flutterwave) specific ──────────────────────────────────────
    flwTxRef: {
      type:   String,
      index:  true,
      sparse: true,
    },
    flwTxId: {
      type: String,
    },

    // ── Status ───────────────────────────────────────────────────────────
    status: {
      type:    String,
      enum:    ['PENDING', 'SUCCESS', 'FAILED', 'CANCELLED'],
      default: 'PENDING',
      index:   true,
    },
    resultCode: {
      type: String,   // stored as string to handle Daraja string codes
    },
    resultDesc: {
      type: String,
    },
    paidAt: {
      type: Date,
    },
    // Accounting/disbursement tracking
    disbursed: {
      type: Boolean,
      default: false,
      index: true,
    },
    disbursedAt: {
      type: Date,
    },
    disbursedBy: {
      type: String,
    },
    receiptGenerated: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,   // createdAt + updatedAt

    // Strip phone from any JSON response — never expose PII via API
    toJSON: {
      transform: (_, ret) => {
        delete ret.phone;
        delete ret.__v;
        return ret;
      },
    },
  }
);

// Compound index for idempotency check in mpesaController
PaymentSchema.index({ userId: 1, packageId: 1, status: 1, createdAt: -1 });

// Compound index for Flutterwave dedup check
PaymentSchema.index({ flwTxRef: 1 }, { unique: true, sparse: true });

export default mongoose.model('Payment', PaymentSchema);