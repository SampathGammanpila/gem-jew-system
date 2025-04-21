// File: packages/backend/src/api/middlewares/rate-limit.middleware.ts

import { Request, Response, NextFunction } from 'express'
import { rateLimit } from 'express-rate-limit'
import { authConfig } from '@/config/auth'
import logger from '@/utils/logger'
import { ApiError } from './error.middleware'

/**
 * Rate limiting scenarios configuration
 */
const rateLimitScenarios = {
  // Login attempts
  login: {
    windowMs: authConfig.rateLimit.loginWindow,
    max: authConfig.rateLimit.loginMax,
    message: 'Too many login attempts, please try again later',
    statusCode: 429,
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Registration attempts
  signup: {
    windowMs: authConfig.rateLimit.signupWindow,
    max: authConfig.rateLimit.signupMax,
    message: 'Too many registration attempts, please try again later',
    statusCode: 429,
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Password reset
  passwordReset: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 attempts per hour
    message: 'Too many password reset attempts, please try again later',
    statusCode: 429,
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // API calls (general)
  api: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per 15 minutes
    message: 'Too many requests, please try again later',
    statusCode: 429,
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Admin login
  adminLogin: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per 15 minutes
    message: 'Too many login attempts, please try again later',
    statusCode: 429,
    standardHeaders: true,
    legacyHeaders: false,
  }
}

/**
 * Log rate limit hit
 */
const onLimitReached = (req: Request, res: Response) => {
  logger.warn('Rate limit exceeded', {
    ip: req.ip || req.socket.remoteAddress,
    path: req.path,
    method: req.method,
    userAgent: req.headers['user-agent']
  })
}

/**
 * Function to create rate limiter middleware for different scenarios
 * @param scenario - Rate limiting scenario name
 */
export const rateLimiter = (scenario: keyof typeof rateLimitScenarios = 'api') => {
  // Get configuration for the specified scenario
  const config = rateLimitScenarios[scenario]
  
  // Create and return rate limiter
  return rateLimit({
    ...config,
    handler: (req, res, next, options) => {
      // Log rate limit hit
      onLimitReached(req, res)
      
      // Send error response
      res.status(options.statusCode).json({
        status: 'error',
        message: options.message,
        retryAfter: Math.ceil(options.windowMs / 1000 / 60) // minutes
      })
    },
    skip: (req) => {
      // Skip rate limiting in development if configured
      return process.env.NODE_ENV === 'development' && process.env.SKIP_RATE_LIMIT === 'true'
    },
    keyGenerator: (req) => {
      // Use IP address as key
      return req.ip || req.socket.remoteAddress || 'unknown'
    }
  })
}

/**
 * Middleware to apply dynamic rate limiting based on user status
 * This can be used for endpoints that need more complex rate limiting logic
 */
export const dynamicRateLimiter = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Example of dynamic rate limiting based on user role or status
    // For now, we'll just use the general API rate limiter
    return rateLimiter('api')(req, res, next)
  } catch (error) {
    next(error)
  }
}