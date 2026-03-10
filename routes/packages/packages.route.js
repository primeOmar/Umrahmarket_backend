import express from 'express';
import { parseFormData, uploadImagesToR2 } from '../../middleware/uploads/Uploadtocloudflare.js';
import { getAgentPackages } from '../../controllers/packages/getpackages.controller.js';
import { createPackage } from '../../controllers/packages/createpackages.controller.js';
import { verifyToken } from '../../middleware/auth.middleware.js';
import { validatePackage } from '../../middleware/uploads/validatePackage.js';
import { getAllActivePackages } from '../../controllers/packages/getallactivepackages.controller.js';
const router = express.Router();

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
router.get('/all-active', getAllActivePackages);
export default router;