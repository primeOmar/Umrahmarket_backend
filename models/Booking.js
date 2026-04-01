// models/Booking.js
import mongoose from 'mongoose';

const BookingSchema = new mongoose.Schema(
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
    paymentId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'Payment',
      required: true,
    },

    // ── Payment summary (denormalised for quick reads) ───────────────────
    paymentMethod: {
      type:    String,
      enum:    ['MPESA', 'CARD', 'BANK'],
      default: 'MPESA',
    },
    amountPaid: {
      type:     Number,
      required: true,
    },
    currency: {
      type:    String,
      default: 'KES',
    },

    // ── M-Pesa receipt (stored for reconciliation, not exposed in lists) ──
    mpesaRef: {
      type: String,
    },

    // ── Booking status ───────────────────────────────────────────────────
    status: {
      type:    String,
      enum:    ['pending', 'confirmed', 'cancelled', 'completed'],
      default: 'pending',
      index:   true,
    },
    confirmedAt: {
      type: Date,
    },
    cancelledAt: {
      type: Date,
    },

    // ── Optional agent notes / admin fields ──────────────────────────────
    notes: {
      type: String,
      maxlength: 500,
    },
  },
  {
    timestamps: true,   // createdAt + updatedAt

    toJSON: {
      transform: (_, ret) => {
        delete ret.__v;
        delete ret.mpesaRef;  // don't expose receipt number in list responses
        return ret;
      },
      virtuals: true,
    },
  }
);

// Prevent a user from booking the same package twice concurrently
BookingSchema.index(
  { userId: 1, packageId: 1, status: 1 },
  {
    unique: false,   // not unique — allows re-booking after cancellation
    name:   'user_package_status',
  }
);

// Virtual: expose booking id as 'id' (Mongoose default)
BookingSchema.virtual('id').get(function () {
  return this._id.toHexString();
});

export default mongoose.model('Booking', BookingSchema);