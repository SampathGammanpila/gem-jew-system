// File: packages/backend/src/api/routes/auth.routes.ts

import { Router } from 'express'
import { authenticate, authenticateRefreshToken } from '../middlewares/auth.middleware'
import { validate } from '../middlewares/validation.middleware'
import { asyncHandler } from '../middlewares/error.middleware'
import * as authController from '../controllers/auth.controller'
import * as authValidator from '../validators/auth.validator'
import { rateLimiter } from '../middlewares/rate-limit.middleware'

const router = Router()

// User registration
router.post(
  '/register',
  rateLimiter('signup'),
  validate(authValidator.registerValidator),
  asyncHandler(authController.register)
)

// Professional registration
router.post(
  '/register/professional',
  rateLimiter('signup'),
  validate(authValidator.registerProfessionalValidator),
  asyncHandler(authController.registerProfessional)
)

// User login
router.post(
  '/login',
  rateLimiter('login'),
  validate(authValidator.loginValidator),
  asyncHandler(authController.login)
)

// Request password reset
router.post(
  '/forgot-password',
  rateLimiter('passwordReset'),
  validate(authValidator.forgotPasswordValidator),
  asyncHandler(authController.forgotPassword)
)

// Reset password with token
router.post(
  '/reset-password',
  validate(authValidator.resetPasswordValidator),
  asyncHandler(authController.resetPassword)
)

// Verify email with token
router.post(
  '/verify-email',
  validate(authValidator.verifyEmailValidator),
  asyncHandler(authController.verifyEmail)
)

// Refresh token
router.post(
  '/refresh-token',
  authenticateRefreshToken,
  asyncHandler(authController.refreshToken)
)

// Get current user (auth required)
router.get(
  '/me',
  authenticate,
  asyncHandler(authController.getCurrentUser)
)

// Change password (auth required)
router.post(
  '/change-password',
  authenticate,
  validate(authValidator.changePasswordValidator),
  asyncHandler(authController.changePassword)
)

// Logout (auth required)
router.post(
  '/logout',
  authenticate,
  asyncHandler(authController.logout)
)

// Setup MFA (auth required)
router.post(
  '/setup-mfa',
  authenticate,
  asyncHandler(authController.setupMFA)
)

// Verify and enable MFA (auth required)
router.post(
  '/verify-mfa',
  authenticate,
  validate(authValidator.verifyMfaValidator),
  asyncHandler(authController.verifyAndEnableMFA)
)

export default router