import express from 'express';
import { getResources,  createResource,deleteResource } from '../controllers/resources/resources.js';
import {parseResourceData, uploadResourceToR2 } from '../controllers/resources/r2ResourceUpload.js';
import { verifyToken } from '../middleware/auth.middleware.js';
import { authenticateSuperadmin } from './superadmin_routes.js';
const router = express.Router();


router.post('/superadmin/resources', authenticateSuperadmin, parseResourceData, uploadResourceToR2, createResource);
router.get('/superadmin/resources', authenticateSuperadmin, getResources);
router.delete('/superadmin/resources/:id', authenticateSuperadmin, deleteResource);

export default router;