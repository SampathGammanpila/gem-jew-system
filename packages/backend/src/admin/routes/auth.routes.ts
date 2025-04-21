// File: packages/backend/src/admin/routes/auth.routes.ts

import { Router } from 'express'
import * as authController from '../controllers/auth.controller'
import { asyncHandler } from '@/api/middlewares/error.middleware'
import { authenticateAdmin } from '@/api/middlewares/auth.middleware'
import { rateLimiter } from '@/api/middlewares/rate-limit.middleware'

const router = Router()

// Admin login page
router.get('/login', asyncHandler(authController.loginPage))

// Admin login action
router.post('/login', rateLimiter('adminLogin'), asyncHandler(authController.login))

// Admin logout action
router.get('/logout', asyncHandler(authController.logout))

// Admin change password page
router.get('/change-password', authenticateAdmin, asyncHandler(authController.changePasswordPage))

// Admin change password action
router.post('/change-password', authenticateAdmin, asyncHandler(authController.changePassword))

// Admin MFA setup page
router.get('/setup-mfa', asyncHandler(authController.setupMfaPage))

// Admin MFA setup action
router.post('/setup-mfa', asyncHandler(authController.setupMfa))

// Admin MFA verification page
router.get('/verify-mfa', asyncHandler(authController.verifyMfaPage))

// Admin MFA verification action
router.post('/verify-mfa', asyncHandler(authController.verifyMfa))

export default router