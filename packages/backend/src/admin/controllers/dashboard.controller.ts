// File: packages/backend/src/admin/controllers/dashboard.controller.ts

import { Request, Response } from 'express'
import db from '@/db'
import logger from '@/utils/logger'

interface DashboardStats {
  usersCount: number
  professionalsCount: {
    total: number
    pending: number
    verified: number
  }
  gemstonesCount: number
  roughStonesCount: number
  jewelryCount: number
  marketplaceStats: {
    activeListings: number
    completedOrders: number
    salesVolume: number
  }
  certificatesCount: number
  recentUsers: Array<{
    id: string
    name: string
    email: string
    role: string
    createdAt: Date
  }>
  recentOrders: Array<{
    id: string
    userId: string
    userName: string
    total: number
    status: string
    createdAt: Date
  }>
}

/**
 * Get dashboard statistics
 */
const getDashboardStats = async (): Promise<DashboardStats> => {
  // Get users count
  const usersCountResult = await db.query('SELECT COUNT(*) FROM users WHERE role = $1', ['user'])
  const usersCount = parseInt(usersCountResult.rows[0].count)
  
  // Get professionals count
  const professionalsQuery = `
    SELECT 
      COUNT(*) AS total,
      SUM(CASE WHEN verification_status = 'pending' THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN verification_status = 'verified' THEN 1 ELSE 0 END) AS verified
    FROM professionals
  `
  const professionalsResult = await db.query(professionalsQuery)
  const professionalsCount = {
    total: parseInt(professionalsResult.rows[0].total) || 0,
    pending: parseInt(professionalsResult.rows[0].pending) || 0,
    verified: parseInt(professionalsResult.rows[0].verified) || 0
  }
  
  // These tables may not exist yet, so we'll use default values if not
  let gemstonesCount = 0
  let roughStonesCount = 0
  let jewelryCount = 0
  let marketplaceStats = {
    activeListings: 0,
    completedOrders: 0,
    salesVolume: 0
  }
  let certificatesCount = 0
  
  // Get recent users
  const recentUsersQuery = `
    SELECT id, name, email, role, created_at
    FROM users
    ORDER BY created_at DESC
    LIMIT 5
  `
  const recentUsersResult = await db.query(recentUsersQuery)
  const recentUsers = recentUsersResult.rows.map(row => ({
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    createdAt: row.created_at
  }))
  
  // Recent orders will be empty until the marketplace is implemented
  const recentOrders: Array<{
    id: string
    userId: string
    userName: string
    total: number
    status: string
    createdAt: Date
  }> = []
  
  return {
    usersCount,
    professionalsCount,
    gemstonesCount,
    roughStonesCount,
    jewelryCount,
    marketplaceStats,
    certificatesCount,
    recentUsers,
    recentOrders
  }
}

/**
 * Render admin dashboard
 * @route GET /admin/dashboard
 */
export const dashboardPage = async (req: Request, res: Response) => {
  try {
    // Get dashboard statistics
    const stats = await getDashboardStats()
    
    // Calculate completion percentages for the progress bars
    const percentages = {
      professionals: stats.professionalsCount.verified > 0 
        ? Math.round((stats.professionalsCount.verified / stats.professionalsCount.total) * 100) 
        : 0,
      // Other percentages would go here
    }
    
    res.render('dashboard/index', {
      title: 'Admin Dashboard',
      stats,
      percentages,
      path: req.path
    })
  } catch (error) {
    logger.error('Error rendering dashboard:', error)
    
    res.render('error', {
      title: 'Error',
      message: 'An error occurred while loading the dashboard',
      error: process.env.NODE_ENV === 'development' ? error : {},
    })
  }
}

/**
 * Get dashboard statistics (API)
 * @route GET /admin/api/dashboard/stats
 */
export const getStats = async (req: Request, res: Response) => {
  try {
    // Get dashboard statistics
    const stats = await getDashboardStats()
    
    res.json({
      status: 'success',
      data: stats
    })
  } catch (error) {
    logger.error('Error getting dashboard stats:', error)
    
    res.status(500).json({
      status: 'error',
      message: 'Error retrieving dashboard statistics'
    })
  }
}