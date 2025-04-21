// packages/backend/src/api/routes/index.ts

import { Router } from 'express'
import authRoutes from './auth.routes'
import userRoutes from './user.routes'
import { notFoundHandler } from '../middlewares/error.middleware'

const router = Router()

// Health check route for the base /api path
router.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: 'Gemstone System API is running',
    timestamp: new Date(),
    version: process.env.npm_package_version || '0.1.0',
  })
})

// Mount routes
router.use('/auth', authRoutes)
router.use('/users', userRoutes)
// TODO: Add other routes here as they are implemented
// router.use('/gemstones', gemstoneRoutes)
// router.use('/rough-stones', roughStoneRoutes)
// router.use('/jewelry', jewelryRoutes)
// router.use('/marketplace', marketplaceRoutes)
// router.use('/certificates', certificateRoutes)
// etc.

// Handle 404 for API routes
router.use(notFoundHandler)

export default router