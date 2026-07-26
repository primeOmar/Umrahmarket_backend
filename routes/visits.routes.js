// agentVisitsRoutes.js
import express from 'express';
import { logAgentVisit, logPackageVisit, getPackageAgentVisits, getAgentVisits } from '../controllers/visits/visits.controller.js';
import { authenticateSuperadmin } from './superadmin_routes.js';

const router = express.Router();

router.post('/agentvisits', logAgentVisit);
router.get('/getagentvisits',authenticateSuperadmin, getAgentVisits);
router.get('/getpackagesvisits', authenticateSuperadmin, getPackageAgentVisits);
router.post('/packagevisits', logPackageVisit);

export default router;