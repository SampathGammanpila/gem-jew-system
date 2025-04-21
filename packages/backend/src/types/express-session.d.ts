// File: packages/backend/src/types/express-session.d.ts

import 'express-session';

declare module 'express-session' {
  interface Session {
    // User identification
    userId?: string;
    
    // Admin authentication
    tempAdminAuth?: boolean;
    
    // MFA related
    mfaSecret?: string;
    
    // CSRF protection
    csrfToken?: string;
  }
}