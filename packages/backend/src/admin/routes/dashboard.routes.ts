import { Router } from 'express';
import * as dashboardController from '../controllers/dashboard.controller';
import { asyncHandler } from '@/api/middlewares/error.middleware';

const router = Router();

// Dashboard index page
router.get('/', asyncHandler(dashboardController.getDashboard));

export default router;