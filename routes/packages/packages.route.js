import express from 'express';
import { parseFormData, uploadImagesToR2 } from '../../middleware/uploads/Uploadtocloudflare.js';
import { getAgentPackages, getAllActivePackages, getPackageById } from '../../controllers/packages/getpackages.controller.js';
import { createPackage, updatePackage, deletePackage } from '../../controllers/packages/createpackages.controller.js';
import { getItinerary, saveItinerary } from '../../controllers/packages/itinerary.controller.js';
import { verifyToken } from '../../middleware/auth.middleware.js';
import { validatePackage } from '../../middleware/uploads/validatePackage.js';
import { requireApprovedAgent } from '../../middleware/agentVerification.middleware.js';

const router = express.Router();

// GET /api/packages/all-active — public, no auth
router.get('/all-active', getAllActivePackages);

// POST /api/packages/create-packages
//
// Pipeline:
//  1. verifyToken          — authenticate the agent
//  2. requireApprovedAgent — block unverified/rejected agents with a clear
//                            reason (AGENT_NOT_VERIFIED) before we ever
//                            parse the multipart body or touch R2
//  3. parseFormData        — multer parses multipart body; req.body + req.files populated (nothing uploaded yet)
//  4. validatePackage      — reject early if required text fields are missing or invalid
//  5. uploadImagesToR2     — security scan + R2 upload only if validation passed
//  6. createPackage        — insert record into Supabase with image URLs
router.post(
  '/create-packages',
  verifyToken,
  requireApprovedAgent,
  parseFormData,
  validatePackage,
  uploadImagesToR2,
  createPackage
);

// GET /api/packages/getagentpackages
router.get('/getagentpackages', verifyToken, getAgentPackages);

// GET /api/packages/:id — single package fetch, incl. price_tiers.
// No verifyToken here: Active packages must stay reachable by guests. This
// means a logged-in agent viewing their own Draft/Inactive package via this
// fallback route currently gets the same 404 an anonymous visitor would —
// req.user is never populated without auth middleware. Wire in an
// optional-auth middleware here (one that decodes a token if present but
// doesn't reject its absence) if agents need to preview their own
// unpublished packages through this endpoint.
router.get('/:id', getPackageById);

// PUT /api/packages/:id — agent edits their own package (all fields + images)
// Same pipeline as create: auth → approved-agent gate → parse multipart →
// validate → upload any new images to R2 → update the record. Ownership is
// re-checked inside updatePackage itself, not just inferred from the token.
router.put(
  '/:id',
  verifyToken,
  requireApprovedAgent,
  parseFormData,
  validatePackage,
  uploadImagesToR2,
  updatePackage
);

// DELETE /api/packages/:id — agent deletes their own package
router.delete('/:id', verifyToken, deletePackage);

// GET  /api/packages/:id/itinerary  — public
router.get('/:id/itinerary', getItinerary);

// POST /api/packages/:id/itinerary  — agent only
router.post('/:id/itinerary', verifyToken, saveItinerary);

export default router;