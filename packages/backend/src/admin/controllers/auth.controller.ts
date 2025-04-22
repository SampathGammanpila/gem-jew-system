import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { generateToken } from '@/utils/jwtHelper';
import { authConfig } from '@/config/auth';
import db from '@/db';
import logger from '@/utils/logger';

/**
 * Render admin login page
 * @route GET /admin/auth/login
 */
export const loginPage = async (req: Request, res: Response) => {
  // Check if already logged in via admin token
  const adminToken = req.cookies?.adminToken;
  
  if (adminToken) {
    try {
      // Token exists, redirect to dashboard
      return res.redirect('/admin/dashboard');
    } catch (error) {
      // Token invalid, clear it
      res.clearCookie('adminToken', { path: '/admin' });
    }
  }
  
  res.render('auth/login', {
    title: 'Admin Login',
    error: req.query.error || null,
    success: req.query.success || null,
    hideHeader: true,
    hideSidebar: true,
    hideFooter: true,
    layout: 'layouts/main',
    path: req.path
  });
};

/**
 * Process admin login
 * @route POST /admin/auth/login
 */
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email and role
    const result = await db.query(
      'SELECT * FROM users WHERE email = $1 AND role = $2',
      [email, 'admin']
    );
    
    const user = result.rows[0];
    
    // Check if user exists and password is correct
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.render('auth/login', {
        title: 'Admin Login',
        error: 'Invalid email or password',
        hideHeader: true,
        hideSidebar: true,
        hideFooter: true,
        layout: 'layouts/main',
        path: req.path
      });
    }
    
    // Generate JWT
    const token = generateToken({
      id: user.id,
      email: user.email,
      role: user.role,
      name: user.name
    });
    
    // Set cookie with token
    res.cookie('adminToken', token, {
      ...authConfig.cookie,
      path: '/admin', // Only accessible from admin routes
    });
    
    // Update last login timestamp
    await db.query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [user.id]
    );
    
    // Log successful login
    logger.info(`Admin login: ${email} (${user.id})`);
    
    // Redirect to dashboard
    res.redirect('/admin/dashboard');
  } catch (error) {
    logger.error('Admin login error:', error);
    
    res.render('auth/login', {
      title: 'Admin Login',
      error: 'An error occurred. Please try again.',
      hideHeader: true,
      hideSidebar: true,
      hideFooter: true,
      layout: 'layouts/main',
      path: req.path
    });
  }
};

/**
 * Process admin logout
 * @route GET /admin/auth/logout
 */
export const logout = async (req: Request, res: Response) => {
  // Clear admin token cookie
  res.clearCookie('adminToken', {
    path: '/admin',
  });
  
  // Redirect to login page with success message
  res.redirect('/admin/auth/login?success=Successfully logged out');
};

/**
 * Render change password page
 * @route GET /admin/auth/change-password
 */
export const changePasswordPage = async (req: Request, res: Response) => {
  // User data is already set in res.locals by the authenticateAdmin middleware
  
  res.render('auth/change-password', {
    title: 'Change Password',
    userId: req.user?.id,
    error: req.query.error || null,
    success: req.query.success || null
  });
};

/**
 * Process change password
 * @route POST /admin/auth/change-password
 */
export const changePassword = async (req: Request, res: Response) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    // Check if passwords match
    if (newPassword !== confirmPassword) {
      return res.redirect('/admin/auth/change-password?error=New passwords do not match');
    }
    
    // Check minimum password length
    if (newPassword.length < authConfig.password.minLength) {
      return res.redirect(`/admin/auth/change-password?error=Password must be at least ${authConfig.password.minLength} characters`);
    }
    
    // Get user from database
    const result = await db.query(
      'SELECT * FROM users WHERE id = $1 AND role = $2',
      [req.user?.id, 'admin']
    );
    
    const user = result.rows[0];
    
    if (!user) {
      return res.redirect('/admin/auth/login?error=User not found');
    }
    
    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password_hash);
    
    if (!isPasswordValid) {
      return res.redirect('/admin/auth/change-password?error=Current password is incorrect');
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(authConfig.password.saltRounds);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update password
    await db.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [hashedPassword, req.user?.id]
    );
    
    // Redirect with success message
    res.redirect('/admin/auth/change-password?success=Password changed successfully');
  } catch (error) {
    logger.error('Change password error:', error);
    res.redirect('/admin/auth/change-password?error=An error occurred. Please try again.');
  }
};