import { Request, Response } from 'express'
import { ApiError } from '../middlewares/error.middleware'
import * as authService from '@/services/auth.service'
import logger from '@/utils/logger'
import { authConfig } from '@/config/auth'

/**
 * Register a new user
 * @route POST /api/auth/register
 */
export const register = async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body
    
    // Register the user
    const result = await authService.register(name, email, password)
    
    // Set refresh token in HTTP-only cookie if in production
    if (process.env.NODE_ENV === 'production') {
      res.cookie('refreshToken', result.tokens.refreshToken, {
        ...authConfig.cookie,
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      })
    }
    
    // Return user data and access token (not refresh token for security)
    res.status(201).json({
      status: 'success',
      message: 'User registered successfully. Please check your email to verify your account.',
      data: {
        user: result.user,
        token: result.tokens.accessToken,
        expiresIn: result.tokens.expiresIn
      }
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Registration error:', error)
    throw new ApiError(500, 'Error registering user')
  }
}

/**
 * Register a new professional user
 * @route POST /api/auth/register/professional
 */
export const registerProfessional = async (req: Request, res: Response) => {
  try {
    const { name, email, password, professionalType, company, phone } = req.body
    
    // Register the professional user
    const result = await authService.registerProfessional({
      name, 
      email, 
      password, 
      professionalType, 
      company, 
      phone
    })
    
    // Set refresh token in HTTP-only cookie if in production
    if (process.env.NODE_ENV === 'production') {
      res.cookie('refreshToken', result.tokens.refreshToken, {
        ...authConfig.cookie,
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      })
    }
    
    // Return user data and access token (not refresh token for security)
    res.status(201).json({
      status: 'success',
      message: 'Professional account registered. Please check your email to verify your account and submit verification documents.',
      data: {
        user: result.user,
        token: result.tokens.accessToken,
        expiresIn: result.tokens.expiresIn
      }
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Professional registration error:', error)
    throw new ApiError(500, 'Error registering professional user')
  }
}

/**
 * Login user
 * @route POST /api/auth/login
 */
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body
    
    // Get client IP and user agent for security
    const ipAddress = req.ip || req.socket.remoteAddress
    const userAgent = req.headers['user-agent']
    
    // Login the user
    const result = await authService.login(email, password, ipAddress, userAgent)
    
    // Set refresh token in HTTP-only cookie if in production
    if (process.env.NODE_ENV === 'production') {
      res.cookie('refreshToken', result.tokens.refreshToken, {
        ...authConfig.cookie,
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      })
    }
    
    // Return user data and access token (not refresh token for security)
    res.json({
      status: 'success',
      message: 'Login successful',
      data: {
        user: result.user,
        token: result.tokens.accessToken,
        expiresIn: result.tokens.expiresIn
      }
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Login error:', error)
    throw new ApiError(500, 'Error during login')
  }
}

/**
 * Get current user
 * @route GET /api/auth/me
 */
export const getCurrentUser = async (req: Request, res: Response) => {
  try {
    if (!req.user?.id) {
      throw new ApiError(401, 'Not authenticated')
    }
    
    // Get user from database with latest information
    const user = await authService.getUserById(req.user.id)
    
    // Return user data
    res.json({
      status: 'success',
      data: user
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Get current user error:', error)
    throw new ApiError(500, 'Error retrieving current user')
  }
}

/**
 * Request password reset
 * @route POST /api/auth/forgot-password
 */
export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body
    
    // Request password reset
    await authService.forgotPassword(email)
    
    // Don't reveal if user exists or not for security
    res.json({
      status: 'success',
      message: 'If your email is registered, you will receive password reset instructions.'
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Forgot password error:', error)
    
    // Still return success to not reveal if email exists
    res.json({
      status: 'success',
      message: 'If your email is registered, you will receive password reset instructions.'
    })
  }
}

/**
 * Reset password with token
 * @route POST /api/auth/reset-password
 */
export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { token, newPassword } = req.body
    
    // Reset password
    await authService.resetPassword(token, newPassword)
    
    // Return success
    res.json({
      status: 'success',
      message: 'Password has been reset successfully. You can now log in with your new password.'
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Reset password error:', error)
    throw new ApiError(500, 'Error resetting password')
  }
}

/**
 * Verify email with token
 * @route POST /api/auth/verify-email
 */
export const verifyEmail = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    
    // Verify email
    await authService.verifyEmail(token)
    
    // Return success
    res.json({
      status: 'success',
      message: 'Email verified successfully. You can now log in.'
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Verify email error:', error)
    throw new ApiError(500, 'Error verifying email')
  }
}

/**
 * Refresh token
 * @route POST /api/auth/refresh-token
 */
export const refreshToken = async (req: Request, res: Response) => {
  try {
    // Fixed: Changed the if condition to NOT operator
    if (!(req.cookies.refreshToken || (req.session && (req.session as any).token))) {
      throw new ApiError(401, 'Refresh token required')
    }
    
    // Get client IP and user agent for security
    const ipAddress = req.ip || req.socket.remoteAddress
    const userAgent = req.headers['user-agent']
    
    // Fixed: Use type assertion for session token
    const tokenToUse = req.cookies.refreshToken || (req.session ? (req.session as any).token : null);
    
    // Refresh the token
    const tokens = await authService.refreshToken(tokenToUse, ipAddress, userAgent)
    
    // Set new refresh token in HTTP-only cookie if in production
    if (process.env.NODE_ENV === 'production') {
      res.cookie('refreshToken', tokens.refreshToken, {
        ...authConfig.cookie,
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      })
    }
    
    // Return new access token
    res.json({
      status: 'success',
      data: {
        token: tokens.accessToken,
        expiresIn: tokens.expiresIn
      }
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Refresh token error:', error)
    throw new ApiError(500, 'Error refreshing token')
  }
}

/**
 * Logout user
 * @route POST /api/auth/logout
 */
export const logout = async (req: Request, res: Response) => {
  try {
    if (!req.user?.id) {
      throw new ApiError(401, 'Not authenticated')
    }
    
    // Get refresh token from cookie or request body
    const refreshToken = req.cookies?.refreshToken || req.body.refreshToken
    
    // Get logout from all devices flag
    const allDevices = req.body.allDevices === true
    
    // Logout user
    await authService.logout(req.user.id, refreshToken, allDevices)
    
    // Clear cookies
    if (req.cookies.refreshToken) {
      res.clearCookie('refreshToken')
    }
    
    if (req.cookies.token) {
      res.clearCookie('token')
    }
    
    // Clear session token using type assertion
    if (req.session) {
      (req.session as any).token = null;
    }
    
    // Return success
    res.json({
      status: 'success',
      message: 'Logged out successfully'
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Logout error:', error)
    throw new ApiError(500, 'Error during logout')
  }
}

/**
 * Change password (authenticated)
 * @route POST /api/auth/change-password
 */
export const changePassword = async (req: Request, res: Response) => {
  try {
    if (!req.user?.id) {
      throw new ApiError(401, 'Not authenticated')
    }
    
    const { currentPassword, newPassword } = req.body
    
    // Change password
    await authService.changePassword(req.user.id, currentPassword, newPassword)
    
    // Return success
    res.json({
      status: 'success',
      message: 'Password changed successfully'
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Change password error:', error)
    throw new ApiError(500, 'Error changing password')
  }
}

/**
 * Setup MFA (Multi-Factor Authentication)
 * @route POST /api/auth/setup-mfa
 */
export const setupMFA = async (req: Request, res: Response) => {
  try {
    if (!req.user?.id) {
      throw new ApiError(401, 'Not authenticated')
    }
    
    // Setup MFA
    const mfaData = await authService.setupMFA(req.user.id)
    
    // Return MFA setup data
    res.json({
      status: 'success',
      data: mfaData
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('MFA setup error:', error)
    throw new ApiError(500, 'Error setting up MFA')
  }
}

/**
 * Verify and enable MFA
 * @route POST /api/auth/verify-mfa
 */
export const verifyAndEnableMFA = async (req: Request, res: Response) => {
  try {
    if (!req.user?.id) {
      throw new ApiError(401, 'Not authenticated')
    }
    
    const { token } = req.body
    
    // Verify and enable MFA
    await authService.verifyAndEnableMFA(req.user.id, token)
    
    // Return success
    res.json({
      status: 'success',
      message: 'MFA enabled successfully'
    })
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('MFA verification error:', error)
    throw new ApiError(500, 'Error verifying MFA token')
  }
}