// File: packages/backend/src/api/middlewares/auth.middleware.ts

import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { ApiError } from './error.middleware'
import { authConfig } from '@/config/auth'
import { verifyToken, TokenPayload } from '@/utils/jwtHelper'
import db from '@/db'
import logger from '@/utils/logger'

// Extend the Express Request interface to include user information
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string
        email: string
        role: string
        isAdmin?: boolean
        [key: string]: any
      }
      session?: {
        id: string
        token: string
        expiresAt: Date
      }
    }
  }
}

/**
 * Middleware to authenticate JWT token
 */
export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Get token from header or cookie
    const authHeader = req.headers.authorization
    let token: string | undefined
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      // Extract token from Bearer authorization header
      token = authHeader.split(' ')[1]
    } else if (req.cookies && req.cookies.token) {
      // Extract token from cookie
      token = req.cookies.token
    }
    
    // If no token found, return authentication error
    if (!token) {
      throw new ApiError(401, 'Authentication required')
    }
    
    // Verify the token
    const decoded = verifyToken(token)
    
    // Check token type (must be 'access')
    if (decoded.type !== 'access') {
      throw new ApiError(401, 'Invalid token type')
    }
    
    // Add user info to request
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      isAdmin: decoded.isAdmin || false,
    }
    
    next()
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return next(new ApiError(401, 'Token expired'))
    } else if (error instanceof jwt.JsonWebTokenError) {
      return next(new ApiError(401, 'Invalid token'))
    } else {
      return next(error)
    }
  }
}

/**
 * Middleware to authenticate using refresh token
 * Used for token refresh endpoint
 */
export const authenticateRefreshToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Get refresh token from body, cookie, or header
    const refreshToken = 
      req.body.refreshToken || 
      (req.cookies && req.cookies.refreshToken) ||
      (req.headers.authorization && req.headers.authorization.startsWith('Bearer ') 
        ? req.headers.authorization.split(' ')[1] 
        : undefined)
    
    if (!refreshToken) {
      throw new ApiError(401, 'Refresh token required')
    }
    
    // Check if token exists in sessions table
    const sessionResult = await db.query(
      'SELECT * FROM sessions WHERE token = $1 AND expires_at > NOW()',
      [refreshToken]
    )
    
    if (sessionResult.rowCount === 0) {
      throw new ApiError(401, 'Invalid or expired refresh token')
    }
    
    const session = sessionResult.rows[0]
    
    // Verify the token
    const decoded = verifyToken(refreshToken)
    
    // Check token type (must be 'refresh')
    if (decoded.type !== 'refresh') {
      throw new ApiError(401, 'Invalid token type')
    }
    
    // Add user and session info to request
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      isAdmin: decoded.isAdmin || false,
    }
    
    req.session = {
      id: session.id,
      token: refreshToken,
      expiresAt: new Date(session.expires_at)
    }
    
    next()
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return next(new ApiError(401, 'Refresh token expired'))
    } else if (error instanceof jwt.JsonWebTokenError) {
      return next(new ApiError(401, 'Invalid refresh token'))
    } else {
      return next(error)
    }
  }
}

/**
 * Middleware to check if user has required role
 * @param roles - Allowed roles (single role or array of roles)
 */
export const authorize = (roles: string | string[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Check if user exists on request (authenticate middleware should be called first)
      if (!req.user) {
        throw new ApiError(401, 'Authentication required')
      }
      
      // Convert single role to array
      const allowedRoles = Array.isArray(roles) ? roles : [roles]
      
      // Check user role
      if (allowedRoles.includes(req.user.role)) {
        return next()
      }
      
      // Check if user has multiple roles (from database)
      const userRolesResult = await db.query(
        `SELECT r.name FROM roles r
         JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_id = $1`,
        [req.user.id]
      )
      
      const userRoles = userRolesResult.rows.map(row => row.name)
      
      // Check if user has any of the allowed roles
      if (allowedRoles.some(role => userRoles.includes(role))) {
        return next()
      }
      
      // If we get here, user doesn't have the required role
      logger.warn('Unauthorized access attempt', {
        userId: req.user.id,
        requiredRoles: allowedRoles,
        userRole: req.user.role,
        userRoles,
        path: req.path
      })
      
      throw new ApiError(403, 'Insufficient permissions')
    } catch (error) {
      next(error)
    }
  }
}

/**
 * Middleware to check if user has specific permissions
 * @param permissions - Required permissions
 */
export const checkPermissions = (permissions: string | string[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Check if user exists on request (authenticate middleware should be called first)
      if (!req.user) {
        throw new ApiError(401, 'Authentication required')
      }
      
      // Admin users bypass permission checks
      if (req.user.role === 'admin' || req.user.isAdmin) {
        return next()
      }
      
      // Convert single permission to array
      const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions]
      
      // Get user permissions from database
      const permissionsResult = await db.query(
        `SELECT p.name FROM permissions p
         JOIN role_permissions rp ON p.id = rp.permission_id
         JOIN roles r ON rp.role_id = r.id
         JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_id = $1`,
        [req.user.id]
      )
      
      const userPermissions = permissionsResult.rows.map(row => row.name)
      
      // Check if user has all required permissions
      const hasAllPermissions = requiredPermissions.every(permission => 
        userPermissions.includes(permission)
      )
      
      if (hasAllPermissions) {
        return next()
      }
      
      // If we get here, user doesn't have the required permissions
      logger.warn('Insufficient permissions', {
        userId: req.user.id,
        requiredPermissions,
        userPermissions,
        path: req.path
      })
      
      throw new ApiError(403, 'Insufficient permissions')
    } catch (error) {
      next(error)
    }
  }
}

/**
 * Middleware to check if user is accessing their own resource
 * @param paramIdField - Parameter name that contains the resource ID
 * @param getResourceOwner - Function to get the resource owner ID
 */
export const checkOwnership = <T extends { userId?: string; ownerId?: string }>(
  paramIdField: string,
  getResourceOwner: (id: string) => Promise<T | null>
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Check if user exists on request
      if (!req.user) {
        throw new ApiError(401, 'Authentication required')
      }
      
      // Admin users can access any resource
      if (req.user.role === 'admin' || req.user.isAdmin) {
        return next()
      }
      
      // Get resource ID from parameters
      const resourceId = req.params[paramIdField]
      if (!resourceId) {
        throw new ApiError(400, 'Resource ID not provided')
      }
      
      // Get resource from database
      const resource = await getResourceOwner(resourceId)
      if (!resource) {
        throw new ApiError(404, 'Resource not found')
      }
      
      // Get owner ID from resource
      const ownerId = resource.userId || resource.ownerId
      
      // Check if user is the owner of the resource
      if (ownerId !== req.user.id) {
        logger.warn('Unauthorized ownership access attempt', {
          userId: req.user.id,
          resourceId,
          ownerId,
          path: req.path
        })
        
        throw new ApiError(403, 'You do not have permission to access this resource')
      }
      
      next()
    } catch (error) {
      next(error)
    }
  }
}

/**
 * Middleware for admin-only access
 */
export const adminOnly = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Check if user exists on request
    if (!req.user) {
      throw new ApiError(401, 'Authentication required')
    }
    
    // Check if user is an admin
    if (req.user.role !== 'admin' && !req.user.isAdmin) {
      logger.warn('Unauthorized admin access attempt', {
        userId: req.user.id,
        role: req.user.role,
        path: req.path
      })
      
      throw new ApiError(403, 'Admin access required')
    }
    
    next()
  } catch (error) {
    next(error)
  }
}

/**
 * Middleware to check if email is verified
 */
export const requireVerifiedEmail = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Check if user exists on request
    if (!req.user) {
      throw new ApiError(401, 'Authentication required')
    }
    
    // Get user from database to check verification status
    const result = await db.query(
      'SELECT is_verified FROM users WHERE id = $1',
      [req.user.id]
    )
    
    if (result.rowCount === 0) {
      throw new ApiError(404, 'User not found')
    }
    
    const user = result.rows[0]
    
    if (!user.is_verified) {
      throw new ApiError(403, 'Email verification required')
    }
    
    next()
  } catch (error) {
    next(error)
  }
}

/**
 * Middleware for admin authentication for EJS admin panel
 */
export const authenticateAdmin = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Get admin token from cookie
    const token = req.cookies?.adminToken
    
    if (!token) {
      return res.redirect('/admin/auth/login?error=Authentication required')
    }
    
    // Verify the token
    const decoded = verifyToken(token)
    
    // Check for admin role and admin flag
    if (decoded.role !== 'admin' && !decoded.isAdmin) {
      logger.warn('Non-admin tried to access admin panel', {
        userId: decoded.id,
        email: decoded.email,
        role: decoded.role
      })
      
      res.clearCookie('adminToken', { path: '/admin' })
      return res.redirect('/admin/auth/login?error=Admin access required')
    }
    
    // Store user info in request
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      isAdmin: true
    }
    
    // Add user to response locals for EJS templates
    res.locals.user = {
      id: decoded.id,
      name: decoded.name || decoded.email,
      email: decoded.email,
      role: decoded.role,
      isAdmin: true
    }
    
    // Set path in locals for active menu highlighting
    res.locals.path = req.path
    
    next()
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      res.clearCookie('adminToken', { path: '/admin' })
      return res.redirect('/admin/auth/login?error=Session expired. Please log in again.')
    } else if (error instanceof jwt.JsonWebTokenError) {
      res.clearCookie('adminToken', { path: '/admin' })
      return res.redirect('/admin/auth/login?error=Invalid session. Please log in again.')
    } else {
      logger.error('Admin authentication error:', error)
      return res.redirect('/admin/auth/login?error=Authentication error. Please try again.')
    }
  }
}