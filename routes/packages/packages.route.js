import express from 'express';
import { parseFormData, uploadImagesToR2 } from '../../middleware/uploads/Uploadtocloudflare.js';
import { getAgentPackages, getAllActivePackages } from '../../controllers/packages/getpackages.controller.js';
import { createPackage } from '../../controllers/packages/createpackages.controller.js';
import { verifyToken } from '../../middleware/auth.middleware.js';
import { validatePackage } from '../../middleware/uploads/Validatepackage.js';

const router = express.Router();

// GET /api/packages/all-active — public, no auth
router.get('/all-active', getAllActivePackages);

// POST /api/packages/create-packages
//
// Pipeline:
//  1. verifyToken      — authenticate the agent
//  2. parseFormData    — multer parses multipart body; req.body + req.files populated (nothing uploaded yet)
//  3. validatePackage  — reject early if required text fields are missing or invalid
//  4. uploadImagesToR2 — security scan + R2 upload only if validation passed
//  5. createPackage    — insert record into Supabase with image URLs
router.post(
  '/create-packages',
  verifyToken,
  parseFormData,
  validatePackage,
  uploadImagesToR2,
  createPackage
);

// GET /api/packages/getagentpackages
router.get('/getagentpackages', verifyToken, getAgentPackages);

export default router;