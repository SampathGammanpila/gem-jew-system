import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { ApiError } from './error.middleware'
import { authConfig } from '@/config/auth'
import { verifyToken } from '@/utils/jwtHelper'

// Extend the Express Request interface to include user information
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string
        email: string
        role: string
        [key: string]: any
      }
    }
  }
}

/**
 * Middleware to authenticate JWT token
 */
export const authenticate = (req: Request, res: Response, next: NextFunction) => {
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
    
    // Add user info to request
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
    }
    
    next()
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      next(new ApiError(401, 'Token expired'))
    } else if (error instanceof jwt.JsonWebTokenError) {
      next(new ApiError(401, 'Invalid token'))
    } else {
      next(error)
    }
  }
}

/**
 * Middleware to authenticate admin users
 */
export const authenticateAdmin = (req: Request, res: Response, next: NextFunction) => {
  try {
    // Check for admin token in cookie
    const adminToken = req.cookies?.adminToken
    
    if (!adminToken) {
      // If not authenticated, redirect to admin login
      return res.redirect('/admin/auth/login')
    }
    
    // Verify the admin token
    const decoded = verifyToken(adminToken)
    
    // Check if user is an admin
    if (decoded.role !== 'admin') {
      throw new ApiError(403, 'Admin access required')
    }
    
    // Add user info to request
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
    }
    
    // Make user data available to templates
    res.locals.user = {
      id: decoded.id,
      name: decoded.name || decoded.email,
      email: decoded.email,
      role: decoded.role,
    }
    
    next()
  } catch (error) {
    // For admin routes, redirect to login on auth failure
    res.clearCookie('adminToken', { path: '/admin' })
    res.redirect('/admin/auth/login?error=Your session has expired. Please log in again.')
  }
}

/**
 * Middleware to check if user has required role
 * @param roles - Allowed roles (single role or array of roles)
 */
export const authorize = (roles: string | string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Check if user exists on request (authenticate middleware should be called first)
      if (!req.user) {
        throw new ApiError(401, 'Authentication required')
      }
      
      // Convert single role to array
      const allowedRoles = Array.isArray(roles) ? roles : [roles]
      
      // Check if user has one of the allowed roles
      if (!allowedRoles.includes(req.user.role)) {
        throw new ApiError(403, 'Insufficient permissions')
      }
      
      next()
    } catch (error) {
      next(error)
    }
  }
}

/**
 * Middleware to check if user is accessing their own resource
 * This middleware requires the resource to have a userId or ownerId field
 * @param paramIdField - Parameter name that contains the resource ID
 * @param resourceGetter - Function to get the resource from database
 */
export const authorizeOwner = <T extends { userId?: string; ownerId?: string }>(
  paramIdField: string,
  resourceGetter: (id: string) => Promise<T | null>
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Check if user exists on request
      if (!req.user) {
        throw new ApiError(401, 'Authentication required')
      }
      
      // Get resource ID from parameters
      const resourceId = req.params[paramIdField]
      if (!resourceId) {
        throw new ApiError(400, 'Resource ID not provided')
      }
      
      // Get resource from database
      const resource = await resourceGetter(resourceId)
      if (!resource) {
        throw new ApiError(404, 'Resource not found')
      }
      
      // Get owner ID from resource
      const ownerId = resource.userId || resource.ownerId
      
      // Admin users can access any resource
      if (req.user.role === authConfig.roles.admin) {
        return next()
      }
      
      // Check if user is the owner of the resource
      if (ownerId !== req.user.id) {
        throw new ApiError(403, 'You do not have permission to access this resource')
      }
      
      next()
    } catch (error) {
      next(error)
    }
  }
}