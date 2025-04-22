// packages/backend/src/types/express-session.ts
import 'express-session';

declare module 'express-session' {
  export interface Session {
    csrfToken?: string;
    token?: string;
    user?: {
      id: string;
      name: string;
      email: string;
      role: string;
      [key: string]: any;
    };
  }
}