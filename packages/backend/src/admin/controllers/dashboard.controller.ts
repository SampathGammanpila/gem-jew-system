import { Request, Response } from 'express';
import db from '@/db';
import logger from '@/utils/logger';

/**
 * Get dashboard statistics and render dashboard page
 * @route GET /admin/dashboard
 */
export const getDashboard = async (req: Request, res: Response) => {
  try {
    // Get basic statistics from database
    const stats = await getStatistics();
    
    // Get recent activities
    const activities = await getRecentActivities();
    
    // Render dashboard with data
    res.render('dashboard/index', {
      title: 'Dashboard',
      stats,
      activities,
      systemHealth: {
        status: 'Healthy',
        uptime: '99.8%',
        storage: '68%',
        databaseLoad: '45%',
        apiRequests: '1.2k/min'
      }
    });
  } catch (error) {
    logger.error('Dashboard error:', error);
    
    // If error, render with minimal data
    res.render('dashboard/index', {
      title: 'Dashboard',
      error: 'Error loading dashboard data',
      stats: getDefaultStats(),
      activities: [],
      systemHealth: {
        status: 'Unknown',
        uptime: 'N/A',
        storage: 'N/A',
        databaseLoad: 'N/A',
        apiRequests: 'N/A'
      }
    });
  }
};

/**
 * Get system statistics from database
 */
async function getStatistics() {
  try {
    // Query for user count
    const userCountResult = await db.query(
      'SELECT COUNT(*) as count FROM users'
    );
    
    // Query for gemstone count
    const gemstoneCountResult = await db.query(
      'SELECT COUNT(*) as count FROM gemstones WHERE is_active = true'
    );
    
    // Query for rough stone count
    const roughStoneCountResult = await db.query(
      'SELECT COUNT(*) as count FROM rough_stones WHERE is_active = true'
    );
    
    // Query for marketplace value (sum of active listings)
    const marketplaceValueResult = await db.query(
      'SELECT COALESCE(SUM(price), 0) as total FROM marketplace_listings WHERE status = $1',
      ['active']
    );
    
    // Return stats object
    return {
      userCount: parseInt(userCountResult.rows[0]?.count || '0'),
      gemstoneCount: parseInt(gemstoneCountResult.rows[0]?.count || '0'),
      roughStoneCount: parseInt(roughStoneCountResult.rows[0]?.count || '0'),
      marketplaceValue: parseFloat(marketplaceValueResult.rows[0]?.total || '0')
    };
  } catch (error) {
    logger.error('Error getting dashboard statistics:', error);
    return getDefaultStats();
  }
}

/**
 * Get recent system activities
 */
async function getRecentActivities() {
  try {
    // Query for recent activities from audit log
    const result = await db.query(
      `SELECT 
        a.action_type, 
        a.description, 
        a.created_at, 
        u.name as user_name, 
        u.id as user_id 
      FROM 
        audit_logs a
      LEFT JOIN 
        users u ON a.user_id = u.id
      ORDER BY 
        a.created_at DESC
      LIMIT 10`
    );
    
    // Format and return activities
    return result.rows.map(row => ({
      type: row.action_type,
      description: row.description,
      user: {
        id: row.user_id,
        name: row.user_name || 'Unknown User',
        initials: getInitials(row.user_name || 'Unknown User'),
      },
      timestamp: row.created_at,
      timeAgo: getTimeAgo(row.created_at)
    }));
  } catch (error) {
    logger.error('Error getting recent activities:', error);
    return [];
  }
}

/**
 * Get default statistics for fallback
 */
function getDefaultStats() {
  return {
    userCount: 0,
    gemstoneCount: 0,
    roughStoneCount: 0,
    marketplaceValue: 0
  };
}

/**
 * Get initials from name
 */
function getInitials(name: string): string {
  try {
    return name
      .split(' ')
      .map(part => part.charAt(0).toUpperCase())
      .join('')
      .substring(0, 2);
  } catch (error) {
    return 'UN';
  }
}

/**
 * Get relative time string (e.g., "5 hours ago")
 */
function getTimeAgo(timestamp: Date): string {
  try {
    const now = new Date();
    const diff = now.getTime() - new Date(timestamp).getTime();
    
    // Convert to seconds
    const seconds = Math.floor(diff / 1000);
    
    if (seconds < 60) {
      return `${seconds} sec ago`;
    }
    
    // Convert to minutes
    const minutes = Math.floor(seconds / 60);
    
    if (minutes < 60) {
      return `${minutes} min ago`;
    }
    
    // Convert to hours
    const hours = Math.floor(minutes / 60);
    
    if (hours < 24) {
      return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }
    
    // Convert to days
    const days = Math.floor(hours / 24);
    
    if (days < 7) {
      return `${days} day${days > 1 ? 's' : ''} ago`;
    }
    
    // Just return the date
    return new Date(timestamp).toLocaleDateString();
  } catch (error) {
    return 'Unknown time';
  }
}