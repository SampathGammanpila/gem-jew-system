// File: packages/backend/src/admin/routes/dashboard.routes.ts

import { Router } from 'express'
import * as dashboardController from '../controllers/dashboard.controller'
import { asyncHandler } from '@/api/middlewares/error.middleware'
import { authenticateAdmin } from '@/api/middlewares/auth.middleware'

const router = Router()

// Dashboard home page
router.get('/', authenticateAdmin, asyncHandler(dashboardController.dashboardPage))

// API endpoint for dashboard stats
router.get('/api/stats', authenticateAdmin, asyncHandler(dashboardController.getStats))

export default router