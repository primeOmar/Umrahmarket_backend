import express from 'express';
import { toggleFavourite, getFavourites } from '../../controllers/packages/favourites.controller.js';
import { verifyToken } from '../../middleware/auth.middleware.js';

const router = express.Router();

// All favourites routes require auth
router.use(verifyToken);

// GET  /api/favourites        — get all favourites for current user
router.get('/', getFavourites);

// POST /api/favourites/toggle — add or remove a favourite
router.post('/toggle', toggleFavourite);

export default router;