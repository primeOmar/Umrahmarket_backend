import express from 'express';
import { getResources,  createResource,deleteResource } from '../controllers/resources/resources.js';
import {parseResourceData, uploadResourceToR2 } from '../controllers/resources/r2ResourceUpload.js';
import { verifyToken } from '../middleware/auth.middleware.js';
const router = express.Router();


router.post('/superadmin/resources', verifyToken, parseResourceData, uploadResourceToR2, createResource);
router.get('/superadmin/resources', verifyToken, getResources);
router.delete('/superadmin/resources/:id', verifyToken, deleteResource);

export default router;