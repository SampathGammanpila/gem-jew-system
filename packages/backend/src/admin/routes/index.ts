import { Router } from 'express'
import authRoutes from './auth.routes'
import dashboardRoutes from './dashboard.routes'
import { notFoundHandler } from '@/api/middlewares/error.middleware'
import { authenticateAdmin } from '@/api/middlewares/auth.middleware'

const router = Router()

// Admin dashboard route
router.get('/', (req, res) => {
  // Redirect to login if not authenticated
  res.redirect('/admin/auth/login')
})

// Mount auth routes (no authentication required)
router.use('/auth', authRoutes)

// Protect all other admin routes with admin authentication
router.use((req, res, next) => {
  // Skip authentication for login routes
  if (req.path.startsWith('/auth/')) {
    return next()
  }
  
  // Apply admin authentication for all other routes
  authenticateAdmin(req, res, next)
})

// Mount dashboard routes
router.use('/dashboard', dashboardRoutes)

// TODO: Add other admin routes here
// router.use('/users', userRoutes)
// router.use('/professionals', professionalRoutes)
// etc.