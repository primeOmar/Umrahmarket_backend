const PASSPORT_PROCEED_STATUSES = new Set(['verified', 'manual_review']);

export function evaluatePassportStatusForBooking({ passportRows = [], totalTravelers = 1 }) {
  const safeTotal = Math.max(1, Math.min(30, Number.parseInt(totalTravelers, 10) || 1));
  const indices = Array.from({ length: safeTotal }, (_, i) => i);
  const byIndex = new Map((passportRows || []).map((row) => [row.traveler_index, row]));

  const travelers = indices.map((i) => {
    const row = byIndex.get(i);
    const canProceed = !!row && PASSPORT_PROCEED_STATUSES.has(row.verification_status);

    return {
      travelerIndex: i,
      exists: !!row,
      status: row?.verification_status || null,
      verified: row?.verified || false,
      canProceed,
      attemptsUsed: row?.attempts || 0,
      attemptsRemaining: Math.max(0, 3 - (row?.attempts || 0)),
      facePhotoUrl: row?.face_photo_url || null,
    };
  });

  return {
    totalTravelers: safeTotal,
    travelers,
    allCanProceed: travelers.every((t) => t.canProceed),
    nextIncompleteIndex: travelers.findIndex((t) => !t.canProceed),
  };
}
