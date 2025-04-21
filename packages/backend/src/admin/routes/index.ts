// File: packages/backend/src/admin/routes/index.ts

import { Router } from 'express'
import authRoutes from './auth.routes'
import dashboardRoutes from './dashboard.routes'
import { authenticateAdmin } from '@/api/middlewares/auth.middleware'
import { notFoundHandler } from '@/api/middlewares/error.middleware'

const router = Router()

// Admin root route - redirect to dashboard if authenticated, otherwise to login
router.get('/', (req, res) => {
  // Check if admin token exists
  const adminToken = req.cookies?.adminToken
  if (adminToken) {
    // Redirect to dashboard
    return res.redirect('/admin/dashboard')
  }
  
  // Not authenticated, redirect to login
  res.redirect('/admin/auth/login')
})

// Mount routes
router.use('/auth', authRoutes)
router.use('/dashboard', dashboardRoutes)

// Future routes to implement
// router.use('/users', userRoutes)
// router.use('/professionals', professionalRoutes)
// router.use('/gemstones', gemstoneRoutes)
// router.use('/rough-stones', roughStoneRoutes)
// router.use('/jewelry', jewelryRoutes)
// router.use('/marketplace', marketplaceRoutes)
// router.use('/certificates', certificateRoutes)
// router.use('/reference-data', referenceDataRoutes)
// router.use('/system', systemRoutes)

// Handle 404 for admin routes
router.use(notFoundHandler)

export default router