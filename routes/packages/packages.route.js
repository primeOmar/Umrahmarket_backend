import express from 'express';
import { uploadImages } from '../../middleware/uploads/Uploadtocloudflare.js';
import { createPackage, getAgentPackages } from '../../controllers/packages/packages.controller.js';
import { verifyToken } from '../../middleware/auth.middleware.js';
const router = express.Router();

// POST /api/packages  — multipart/form-data (images + text fields)
router.post('/create-packages', verifyToken, uploadImages, createPackage);

// GET  /api/packages  — list packages for the authenticated organisation
router.get('/getagentpackages', verifyToken, getAgentPackages);

export default router;