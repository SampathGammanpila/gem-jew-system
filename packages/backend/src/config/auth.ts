// File: packages/backend/src/config/auth.ts

/**
 * Authentication configuration
 */
export const authConfig = {
  // JWT configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'your_jwt_secret_key',
    accessTokenExpiration: process.env.JWT_ACCESS_EXPIRATION || '15m',
    refreshTokenExpiration: process.env.JWT_REFRESH_EXPIRATION || '7d',
  },
  
  // Password configuration
  password: {
    saltRounds: 12, // Increased from 10 to 12 for better security
    minLength: 8, // Minimum password length
    requireUppercase: true, // Require at least one uppercase letter
    requireLowercase: true, // Require at least one lowercase letter
    requireNumbers: true, // Require at least one number
    requireSpecialChars: true, // Require at least one special character
    passwordHistory: 5, // Number of previous passwords to remember
  },
  
  // User roles
  roles: {
    user: 'user',
    admin: 'admin',
    dealer: 'dealer',
    cutter: 'cutter',
    appraiser: 'appraiser',
  },
  
  // Cookie configuration
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict' as const,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    domain: process.env.COOKIE_DOMAIN || undefined,
    path: '/',
  },

  // Session configuration
  session: {
    name: 'sid',
    secret: process.env.SESSION_SECRET || 'your_session_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict' as const,
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  },

  // Rate limiting configuration
  rateLimit: {
    loginWindow: 15 * 60 * 1000, // 15 minutes
    loginMax: 5, // 5 attempts
    signupWindow: 60 * 60 * 1000, // 1 hour
    signupMax: 3, // 3 attempts
  },

  // Admin authentication (separate from regular user auth)
  admin: {
    sessionDuration: 4 * 60 * 60 * 1000, // 4 hours
    inactivityTimeout: 30 * 60 * 1000, // 30 minutes
    mfaRequired: process.env.NODE_ENV === 'production', // Require MFA in production
    ipCheck: true, // Check if IP address changes during session
  }
}