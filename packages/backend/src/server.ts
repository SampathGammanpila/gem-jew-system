import express, { Express } from 'express'
import helmet from 'helmet'
import compression from 'compression'
import cors from 'cors'
import morgan from 'morgan'
import path from 'path'
import cookieParser from 'cookie-parser'
import { rateLimit } from 'express-rate-limit'
import expressLayouts from 'express-ejs-layouts'
import session from 'express-session'

// Import custom type definitions
import './types/express-session' // This ensures our session type definitions are loaded

// Import routes
import apiRoutes from './api/routes'
import adminRoutes from './admin/routes'

// Import middlewares
import { errorMiddleware } from './api/middlewares/error.middleware'
import { generateCsrf } from './api/middlewares/csrf.middleware'

// Import configuration
import { corsOptions } from './config/cors'

export const createServer = (): Express => {
  const app = express()

  // Security headers
  app.use(helmet({
    // Allow inline scripts for EJS templates
    contentSecurityPolicy: {
      directives: {
        "script-src": ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        "img-src": ["'self'", "data:"],
      },
    },
  }))

  // Parse JSON bodies
  app.use(express.json())
  
  // Parse URL-encoded bodies
  app.use(express.urlencoded({ extended: true }))
  
  // Parse cookies
  app.use(cookieParser())
  
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
  
  // Setup session middleware
  app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    }
  }))

  // Generate CSRF token for all requests
  app.use(generateCsrf)
  
  // Make user data available to templates
  app.use((req, res, next) => {
    // If there's a user in the session, make it available to views
    // Using type assertion to avoid TypeScript errors
    if (req.session && (req.session as any).user) {
      res.locals.user = (req.session as any).user
    }
    
    // Add the path for sidebar highlighting
    res.locals.path = req.path
    
    next()
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