// File: packages/backend/src/admin/controllers/auth.controller.ts

import { Request, Response } from 'express'
import * as authService from '@/services/auth.service'
import { ApiError } from '@/api/middlewares/error.middleware'
import logger from '@/utils/logger'
import { authConfig } from '@/config/auth'
import crypto from 'crypto'

// Using simpler cookie-based approach for MFA instead of relying on session
// This avoids TypeScript errors and complexity while still providing security

/**
 * Render admin login page
 * @route GET /admin/auth/login
 */
export const loginPage = async (req: Request, res: Response) => {
  try {
    // Check if already logged in
    const token = req.cookies?.adminToken
    if (token) {
      try {
        // This will throw an error if token is invalid
        const decoded = await authService.verifyAdminToken(token)
        return res.redirect('/admin/dashboard')
      } catch (error) {
        // Token invalid, continue to login page
        // Clear invalid cookie
        res.clearCookie('adminToken', { path: '/admin' })
      }
    }
    
    res.render('auth/login', {
      title: 'Admin Login',
      error: req.query.error || null,
      success: req.query.success || null,
      hideHeader: true,
      hideSidebar: true,
      hideFooter: true,
      layout: 'layouts/main',
      path: req.path
    })
  } catch (error) {
    logger.error('Error rendering login page:', error)
    res.render('error', {
      title: 'Error',
      message: 'An error occurred while loading the login page',
      error: process.env.NODE_ENV === 'development' ? error : {},
      hideHeader: true,
      hideSidebar: true,
      hideFooter: true,
      layout: 'layouts/main',
    })
  }
}

/**
 * Process admin login
 * @route POST /admin/auth/login
 */
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body
    
    // Get client IP and user agent for security
    const ipAddress = req.ip || req.socket.remoteAddress
    const userAgent = req.headers['user-agent']
    
    // Attempt admin login
    const result = await authService.adminLogin(email, password, ipAddress, userAgent)
    
    const user = result.user
    
    // Check if MFA is required and enabled
    if (authConfig.admin.mfaRequired) {
      // Check if user has MFA enabled
      const userResult = await authService.checkUserMFA(user.id)
      
      if (!userResult.mfaEnabled) {
        // User doesn't have MFA set up, redirect to setup
        // Store user info in cookies for MFA setup
        res.cookie('tempAdminUserId', user.id, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: 10 * 60 * 1000, // 10 minutes
          path: '/admin/auth',
        })
        res.cookie('tempAdminAuth', 'true', {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: 10 * 60 * 1000, // 10 minutes
          path: '/admin/auth',
        })
        return res.redirect('/admin/auth/setup-mfa')
      }
      
      // User has MFA enabled, redirect to verification
      res.cookie('tempAdminUserId', user.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 10 * 60 * 1000, // 10 minutes
        path: '/admin/auth',
      })
      res.cookie('tempAdminAuth', 'true', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 10 * 60 * 1000, // 10 minutes
        path: '/admin/auth',
      })
      return res.redirect('/admin/auth/verify-mfa')
    }
    
    // No MFA required, set admin token directly
    res.cookie('adminToken', result.tokens.accessToken, {
      ...authConfig.cookie,
      path: '/admin', // Only accessible from admin routes
      maxAge: authConfig.admin.sessionDuration, // Shorter session for admin
    })
    
    // Redirect to dashboard
    res.redirect('/admin/dashboard')
  } catch (error) {
    logger.error('Admin login error:', error)
    
    let errorMessage = 'An error occurred during login. Please try again.'
    
    if (error instanceof ApiError) {
      errorMessage = error.message
    }
    
    res.redirect(`/admin/auth/login?error=${encodeURIComponent(errorMessage)}`)
  }
}

/**
 * Render MFA setup page
 * @route GET /admin/auth/setup-mfa
 */
export const setupMfaPage = async (req: Request, res: Response) => {
  try {
    // Check if user has temporary admin auth
    if (!req.cookies.tempAdminAuth || !req.cookies.tempAdminUserId) {
      return res.redirect('/admin/auth/login?error=Authentication required')
    }
    
    const userId = req.cookies.tempAdminUserId
    
    // Generate MFA secret
    const { secret, qrCodeUrl } = await authService.setupMFA(userId)
    
    // Store secret in cookie temporarily
    res.cookie('tempMfaSecret', secret, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 10 * 60 * 1000, // 10 minutes
      path: '/admin/auth',
    })
    
    res.render('auth/setup-mfa', {
      title: 'Setup MFA',
      qrCodeUrl,
      secret,
      error: req.query.error || null,
      hideHeader: true,
      hideSidebar: true,
      hideFooter: true,
      layout: 'layouts/main',
    })
  } catch (error) {
    logger.error('Error rendering MFA setup page:', error)
    res.render('error', {
      title: 'Error',
      message: 'An error occurred while setting up MFA',
      error: process.env.NODE_ENV === 'development' ? error : {},
      hideHeader: true,
      hideSidebar: true,
      hideFooter: true,
      layout: 'layouts/main',
    })
  }
}

/**
 * Process MFA setup
 * @route POST /admin/auth/setup-mfa
 */
export const setupMfa = async (req: Request, res: Response) => {
  try {
    // Check if user has temporary admin auth
    if (!req.cookies.tempAdminAuth || !req.cookies.tempAdminUserId || !req.cookies.tempMfaSecret) {
      return res.redirect('/admin/auth/login?error=Authentication required')
    }
    
    const userId = req.cookies.tempAdminUserId
    const mfaSecret = req.cookies.tempMfaSecret
    const { token } = req.body
    
    // Verify MFA token
    const verified = await authService.verifyMfaToken(mfaSecret, token)
    
    if (!verified) {
      return res.redirect('/admin/auth/setup-mfa?error=Invalid MFA token')
    }
    
    // Save MFA secret to user
    await authService.enableMFA(userId, mfaSecret)
    
    // Get user data and generate token
    const user = await authService.getUserById(userId)
    
    // Generate admin token
    const tokens = await authService.generateAdminTokens({
      id: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
    })
    
    // Set admin token cookie
    res.cookie('adminToken', tokens.accessToken, {
      ...authConfig.cookie,
      path: '/admin',
      maxAge: authConfig.admin.sessionDuration,
    })
    
    // Clear temporary cookies
    res.clearCookie('tempAdminAuth', { path: '/admin/auth' })
    res.clearCookie('tempAdminUserId', { path: '/admin/auth' })
    res.clearCookie('tempMfaSecret', { path: '/admin/auth' })
    
    // Redirect to dashboard
    res.redirect('/admin/dashboard')
  } catch (error) {
    logger.error('MFA setup error:', error)
    res.redirect('/admin/auth/setup-mfa?error=An error occurred while setting up MFA')
  }
}

/**
 * Render MFA verification page
 * @route GET /admin/auth/verify-mfa
 */
export const verifyMfaPage = async (req: Request, res: Response) => {
  try {
    // Check if user has temporary admin auth
    if (!req.cookies.tempAdminAuth || !req.cookies.tempAdminUserId) {
      return res.redirect('/admin/auth/login?error=Authentication required')
    }
    
    res.render('auth/verify-mfa', {
      title: 'Verify MFA',
      error: req.query.error || null,
      hideHeader: true,
      hideSidebar: true,
      hideFooter: true,
      layout: 'layouts/main',
    })
  } catch (error) {
    logger.error('Error rendering MFA verification page:', error)
    res.render('error', {
      title: 'Error',
      message: 'An error occurred while loading the MFA verification page',
      error: process.env.NODE_ENV === 'development' ? error : {},
      hideHeader: true,
      hideSidebar: true,
      hideFooter: true,
      layout: 'layouts/main',
    })
  }
}

/**
 * Process MFA verification
 * @route POST /admin/auth/verify-mfa
 */
export const verifyMfa = async (req: Request, res: Response) => {
  try {
    // Check if user has temporary admin auth
    if (!req.cookies.tempAdminAuth || !req.cookies.tempAdminUserId) {
      return res.redirect('/admin/auth/login?error=Authentication required')
    }
    
    const userId = req.cookies.tempAdminUserId
    const { token } = req.body
    
    // Get user's MFA secret and verify token
    const verified = await authService.verifyUserMfa(userId, token)
    
    if (!verified) {
      return res.redirect('/admin/auth/verify-mfa?error=Invalid MFA token')
    }
    
    // Get user data
    const user = await authService.getUserById(userId)
    
    // Generate admin token
    const tokens = await authService.generateAdminTokens({
      id: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
    })
    
    // Set admin token cookie
    res.cookie('adminToken', tokens.accessToken, {
      ...authConfig.cookie,
      path: '/admin',
      maxAge: authConfig.admin.sessionDuration,
    })
    
    // Clear temporary cookies
    res.clearCookie('tempAdminAuth', { path: '/admin/auth' })
    res.clearCookie('tempAdminUserId', { path: '/admin/auth' })
    
    // Redirect to dashboard
    res.redirect('/admin/dashboard')
  } catch (error) {
    logger.error('MFA verification error:', error)
    res.redirect('/admin/auth/verify-mfa?error=An error occurred during verification')
  }
}

/**
 * Process admin logout
 * @route GET /admin/auth/logout
 */
export const logout = async (req: Request, res: Response) => {
  try {
    // Clear admin token cookie
    res.clearCookie('adminToken', {
      path: '/admin',
    })
    
    // If user is authenticated, invalidate the session
    if (req.user?.id) {
      await authService.invalidateAdminSession(req.user.id)
    }
    
    // Redirect to login page
    res.redirect('/admin/auth/login?success=Successfully logged out')
  } catch (error) {
    logger.error('Admin logout error:', error)
    res.redirect('/admin/auth/login')
  }
}

/**
 * Render change password page
 * @route GET /admin/auth/change-password
 */
export const changePasswordPage = async (req: Request, res: Response) => {
  try {
    // Check if logged in
    if (!req.user?.id) {
      return res.redirect('/admin/auth/login?error=Please log in to change your password')
    }
    
    res.render('auth/change-password', {
      title: 'Change Password',
      userId: req.user.id,
      error: req.query.error || null,
      success: req.query.success || null,
      layout: 'layouts/main',
      path: req.path,
    })
  } catch (error) {
    logger.error('Error rendering change password page:', error)
    res.render('error', {
      title: 'Error',
      message: 'An error occurred while loading the change password page',
      error: process.env.NODE_ENV === 'development' ? error : {},
      layout: 'layouts/main',
    })
  }
}

/**
 * Process change password
 * @route POST /admin/auth/change-password
 */
export const changePassword = async (req: Request, res: Response) => {
  try {
    // Check if logged in
    if (!req.user?.id) {
      return res.redirect('/admin/auth/login?error=Please log in to change your password')
    }
    
    const { currentPassword, newPassword, confirmPassword } = req.body
    
    // Check if passwords match
    if (newPassword !== confirmPassword) {
      return res.redirect('/admin/auth/change-password?error=New passwords do not match')
    }
    
    // Change password
    await authService.changePassword(req.user.id, currentPassword, newPassword)
    
    // Redirect with success message
    res.redirect('/admin/auth/change-password?success=Password changed successfully')
  } catch (error) {
    logger.error('Change password error:', error)
    
    let errorMessage = 'An error occurred while changing password'
    
    if (error instanceof ApiError) {
      errorMessage = error.message
    }
    
    res.redirect(`/admin/auth/change-password?error=${encodeURIComponent(errorMessage)}`)
  }
}