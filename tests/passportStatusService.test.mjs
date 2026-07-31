import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePassportStatusForBooking } from '../services/passportStatus.service.js';

test('marks a booking as incomplete when any traveler slot is still pending', () => {
  const result = evaluatePassportStatusForBooking({
    passportRows: [
      { traveler_index: 0, verification_status: 'verified', verified: true },
      { traveler_index: 1, verification_status: 'pending', verified: false },
    ],
    totalTravelers: 2,
  });

  assert.equal(result.allCanProceed, false);
  assert.equal(result.nextIncompleteIndex, 1);
  assert.equal(result.travelers[0].canProceed, true);
  assert.equal(result.travelers[1].canProceed, false);
});

test('allows payment when every traveler slot is verified or manual review', () => {
  const result = evaluatePassportStatusForBooking({
    passportRows: [
      { traveler_index: 0, verification_status: 'verified', verified: true },
      { traveler_index: 1, verification_status: 'manual_review', verified: false },
    ],
    totalTravelers: 2,
  });

  assert.equal(result.allCanProceed, true);
  assert.equal(result.nextIncompleteIndex, -1);
  assert.deepEqual(result.travelers.map((traveler) => traveler.canProceed), [true, true]);
});
