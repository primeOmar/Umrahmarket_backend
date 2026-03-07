import express from 'express';
import { uploadImages } from '../../middleware/uploads/Uploadtocloudflare.js';
import { getAgentPackages } from '../../controllers/packages/getpackages.controller.js';
import { createPackage } from '../../controllers/packages/createpackages.controller.js';
import { verifyToken } from '../../middleware/auth.middleware.js';
import { validatePackage } from '../../middleware/uploads/validatePackage.js';
const router = express.Router();

router.post('/create-packages', verifyToken, validatePackage, uploadImages, createPackage);

router.get('/getagentpackages', verifyToken, getAgentPackages);

export default router;