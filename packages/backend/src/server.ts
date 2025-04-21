// File: packages/backend/src/server.ts

import express, { Express, Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import compression from 'compression'
import cors from 'cors'
import morgan from 'morgan'
import path from 'path'
import cookieParser from 'cookie-parser'
import { rateLimit } from 'express-rate-limit'
import expressLayouts from 'express-ejs-layouts'
import session from 'express-session'
import crypto from 'crypto'

// Import routes
import apiRoutes from './api/routes'
import adminRoutes from './admin/routes'

// Import middlewares
import { errorMiddleware } from './api/middlewares/error.middleware'

// Import configuration
import { corsOptions } from './config/cors'

// Session configuration
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'your_session_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict' as const,
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  },
  name: 'sid',
}

export const createServer = (): Express => {
  const app = express()

  // Security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
        imgSrc: ["'self'", "data:"],
      }
    }
  }))

  // Parse JSON bodies
  app.use(express.json())
  
  // Parse URL-encoded bodies
  app.use(express.urlencoded({ extended: true }))
  
  // Parse cookies
  app.use(cookieParser())
  
  // Set up session middleware
  app.use(session(sessionConfig))
  
  // Enable CORS
  app.use(cors(corsOptions))
  
  // Compress all responses
  app.use(compression())
  
  // HTTP request logging
  app.use(morgan(process.env.LOG_FORMAT || 'dev'))
  
  // Rate limiting
  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
  })
  
  // Apply rate limiting to API routes
  app.use(`${process.env.API_PREFIX || '/api'}`, apiLimiter)
  
  // Set up static file serving
  app.use(express.static(path.join(__dirname, '../public')))
  
  // Set up view engine for admin panel
  app.set('views', path.join(__dirname, 'admin/views'))
  app.set('view engine', 'ejs')
  
  // Set up express-ejs-layouts
  app.use(expressLayouts)
  app.set('layout', 'layouts/main')
  app.set('layout extractScripts', true)
  app.set('layout extractStyles', true)
  
  // CSRF token middleware for forms
  app.use((req: Request, res: Response, next: NextFunction) => {
    // Add CSRF token to session if it doesn't exist
    if (req.session && !req.session.csrfToken) {
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    
    // Make CSRF token available to views
    if (req.session) {
      res.locals.csrfToken = req.session.csrfToken;
    }
    
    next();
  });
  
  // API routes
  app.use(`${process.env.API_PREFIX || '/api'}`, apiRoutes)
  
  // Admin panel routes
  app.use('/admin', adminRoutes)
  
  // Default route
  app.get('/', (req, res) => {
    res.json({ message: 'Gemstone System API' })
  })
  
  // 404 handler
  app.use((req, res, next) => {
    res.status(404).json({ message: 'Route not found' })
  })
  
  // Error handling middleware
  app.use(errorMiddleware)
  
  return app
}