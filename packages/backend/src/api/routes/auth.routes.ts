import { Router } from 'express'
import { authenticate } from '../middlewares/auth.middleware'
import { validate } from '../middlewares/validation.middleware'
import { asyncHandler } from '../middlewares/error.middleware'
import * as authController from '../controllers/auth.controller'
import * as authValidator from '../validators/auth.validator'

const router = Router()

// User registration
router.post(
  '/register',
  validate(authValidator.registerValidator),
  asyncHandler(authController.register)
)

// Professional registration
router.post(
  '/register/professional',
  validate(authValidator.registerProfessionalValidator),
  asyncHandler(authController.registerProfessional)
)

// User login
router.post(
  '/login',
  validate(authValidator.loginValidator),
  asyncHandler(authController.login)
)

// Request password reset
router.post(
  '/forgot-password',
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

// Refresh token - removing authenticateRefreshToken as it's not defined
router.post(
  '/refresh-token',
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

export default router