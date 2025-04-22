// packages/backend/src/api/middlewares/csrf.middleware.ts
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { ApiError } from './error.middleware';

// Extend the Express Session interface to include CSRF token
declare module 'express-session' {
  interface SessionData {
    csrfToken?: string;
  }
}

/**
 * Generate a CSRF token and store it in the session
 */
export const generateCsrf = (req: Request, res: Response, next: NextFunction) => {
  // Only generate a token if the session exists
  if (req.session) {
    // Generate a random token
    const token = crypto.randomBytes(32).toString('hex');
    
    // Store it in the session
    req.session.csrfToken = token;
    
    // Make it available for templates
    res.locals.csrfToken = token;
  }
  
  next();
};

/**
 * Validate CSRF token for non-GET requests
 */
export const validateCsrf = (req: Request, res: Response, next: NextFunction) => {
  // Skip for GET, HEAD, OPTIONS requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  // Get token from request
  const requestToken = req.body._csrf || req.headers['x-csrf-token'] || req.headers['csrf-token'];
  
  // Get token from session
  const sessionToken = req.session?.csrfToken;
  
  // If no token in session, or tokens don't match
  if (!sessionToken || !requestToken || sessionToken !== requestToken) {
    return next(new ApiError(403, 'CSRF token validation failed'));
  }
  
  next();
};

/**
 * CSRF protection middleware
 */
export const csrfProtection = [generateCsrf, validateCsrf];