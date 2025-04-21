// File: packages/backend/src/services/auth.service.ts

import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import { authConfig } from '../config/auth'
import db from '../db'
import { ApiError } from '../api/middlewares/error.middleware'
import logger from '../utils/logger'
import { generateTokens, verifyToken, TokenPayload } from '../utils/jwtHelper'
import { emailService } from './email.service'

// Interface for user data
interface UserData {
  id: string
  name: string
  email: string
  role: string
  isVerified: boolean
  [key: string]: any
}

// Interface for login response
interface LoginResponse {
  user: UserData
  tokens: {
    accessToken: string
    refreshToken: string
    expiresIn: number
  }
}

/**
 * Validate password strength
 * @param password Password to validate
 * @returns Boolean indicating if password meets requirements
 */
const validatePasswordStrength = (password: string): { valid: boolean; message?: string } => {
  if (password.length < authConfig.password.minLength) {
    return { 
      valid: false, 
      message: `Password must be at least ${authConfig.password.minLength} characters long` 
    }
  }

  if (authConfig.password.requireUppercase && !/[A-Z]/.test(password)) {
    return { 
      valid: false, 
      message: 'Password must contain at least one uppercase letter' 
    }
  }

  if (authConfig.password.requireLowercase && !/[a-z]/.test(password)) {
    return { 
      valid: false, 
      message: 'Password must contain at least one lowercase letter' 
    }
  }

  if (authConfig.password.requireNumbers && !/[0-9]/.test(password)) {
    return { 
      valid: false, 
      message: 'Password must contain at least one number' 
    }
  }

  if (authConfig.password.requireSpecialChars && !/[^A-Za-z0-9]/.test(password)) {
    return { 
      valid: false, 
      message: 'Password must contain at least one special character' 
    }
  }

  return { valid: true }
}

/**
 * Register a new user
 * @param name User's name
 * @param email User's email
 * @param password Plain text password
 * @param role User role (default: 'user')
 */
export const register = async (
  name: string,
  email: string,
  password: string,
  role = 'user'
): Promise<{ user: UserData; tokens: { accessToken: string; refreshToken: string; expiresIn: number } }> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Check if user already exists
    const userExists = await client.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    )
    
    if (userExists && userExists.rowCount && userExists.rowCount > 0) {
      throw new ApiError(409, 'Email is already registered')
    }
    
    // Validate password strength
    const passwordValidation = validatePasswordStrength(password)
    if (!passwordValidation.valid) {
      throw new ApiError(400, passwordValidation.message || 'Password does not meet requirements')
    }
    
    // Hash the password
    const passwordHash = await bcrypt.hash(
      password,
      authConfig.password.saltRounds
    )
    
    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex')
    
    // Create the user
    const userId = crypto.randomUUID()
    const result = await client.query(
      `INSERT INTO users (id, name, email, password_hash, role, verification_token, is_verified)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, name, email, role, is_verified, created_at`,
      [userId, name, email, passwordHash, role, verificationToken, false]
    )
    
    // Add user to role
    await client.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT $1, id FROM roles WHERE name = $2`,
      [userId, role]
    )
    
    const user = result.rows[0]
    
    // Send verification email
    await emailService.sendVerificationEmail(email, verificationToken)
    
    // Generate JWT tokens
    const tokens = generateTokens({
      id: user.id,
      email: user.email,
      role: user.role
    })
    
    await client.query('COMMIT')
    
    return { 
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.is_verified
      }, 
      tokens 
    }
  } catch (error) {
    await client.query('ROLLBACK')
    
    // Log the error
    logger.error('Registration error:', error)
    
    if (error instanceof ApiError) {
      throw error
    }
    
    // Handle database errors
    if ((error as any).code === '23505') { // Unique violation
      throw new ApiError(409, 'Email is already registered')
    }
    
    throw new ApiError(500, 'Error creating user account')
  } finally {
    client.release()
  }
}

/**
 * Register a professional user
 * @param userData Professional user data
 */
export const registerProfessional = async (userData: {
  name: string
  email: string
  password: string
  professionalType: string
  company?: string
  phone: string
}): Promise<{ user: UserData; tokens: { accessToken: string; refreshToken: string; expiresIn: number } }> => {
  const { name, email, password, professionalType, company, phone } = userData
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Register the user with the professional role
    const { user, tokens } = await register(name, email, password, professionalType)
    
    // Create professional profile
    await client.query(
      `INSERT INTO professionals 
       (id, user_id, type, company, phone, is_verified, verification_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [crypto.randomUUID(), user.id, professionalType, company || null, phone, false, 'pending']
    )
    
    await client.query('COMMIT')
    
    return { user, tokens }
  } catch (error) {
    await client.query('ROLLBACK')
    
    logger.error('Professional registration error:', error)
    
    if (error instanceof ApiError) {
      throw error
    }
    
    throw new ApiError(500, 'Error creating professional account')
  } finally {
    client.release()
  }
}

/**
 * Login a user
 * @param email User's email
 * @param password Plain text password
 * @param ipAddress User's IP address (for security)
 * @param userAgent User's browser agent (for security)
 */
export const login = async (
  email: string, 
  password: string,
  ipAddress?: string,
  userAgent?: string
): Promise<LoginResponse> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Find user by email
    const result = await client.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    )
    
    const user = result.rows[0]
    
    // Check if user exists
    if (!user) {
      // Increment failed login attempts for IP throttling
      logger.warn(`Failed login attempt for non-existent email: ${email}`, { ipAddress })
      throw new ApiError(401, 'Invalid email or password')
    }
    
    // Check if account is locked
    if (user.account_locked_until && new Date(user.account_locked_until) > new Date()) {
      throw new ApiError(423, 'Account is temporarily locked. Please try again later.')
    }
    
    // Check if password is correct
    const passwordValid = await bcrypt.compare(password, user.password_hash)
    
    if (!passwordValid) {
      // Increment failed login attempts
      const failedAttempts = user.failed_login_attempts + 1
      
      // Lock account after 5 failed attempts
      if (failedAttempts >= 5) {
        const lockUntil = new Date()
        lockUntil.setMinutes(lockUntil.getMinutes() + 15) // Lock for 15 minutes
        
        await client.query(
          'UPDATE users SET failed_login_attempts = $1, account_locked_until = $2 WHERE id = $3',
          [failedAttempts, lockUntil, user.id]
        )
      } else {
        await client.query(
          'UPDATE users SET failed_login_attempts = $1 WHERE id = $2',
          [failedAttempts, user.id]
        )
      }
      
      await client.query('COMMIT')
      logger.warn(`Failed login attempt for user: ${user.id}`, { ipAddress })
      throw new ApiError(401, 'Invalid email or password')
    }
    
    // Reset failed login attempts
    await client.query(
      'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, last_login = NOW() WHERE id = $1',
      [user.id]
    )
    
    // Generate tokens
    const tokens = generateTokens({
      id: user.id,
      email: user.email,
      role: user.role
    })
    
    // Create session record
    const sessionId = crypto.randomUUID()
    const expiryDate = new Date()
    expiryDate.setDate(expiryDate.getDate() + 7) // 7 days from now
    
    await client.query(
      `INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [sessionId, user.id, tokens.refreshToken, expiryDate, ipAddress || null, userAgent || null]
    )
    
    await client.query('COMMIT')
    
    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.is_verified
      },
      tokens
    }
  } catch (error) {
    await client.query('ROLLBACK')
    
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Login error:', error)
    throw new ApiError(500, 'Error during login')
  } finally {
    client.release()
  }
}

/**
 * Verify a user's email
 * @param token Verification token
 */
export const verifyEmail = async (token: string): Promise<UserData> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Find user by verification token
    const result = await client.query(
      `UPDATE users 
       SET is_verified = TRUE, verification_token = NULL, updated_at = NOW() 
       WHERE verification_token = $1
       RETURNING id, name, email, role`,
      [token]
    )
    
    if (result.rowCount === 0) {
      throw new ApiError(400, 'Invalid or expired verification token')
    }
    
    const user = result.rows[0]
    
    // Send welcome email
    await emailService.sendWelcomeEmail(user.email, user.name)
    
    await client.query('COMMIT')
    
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      isVerified: true
    }
  } catch (error) {
    await client.query('ROLLBACK')
    
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Email verification error:', error)
    throw new ApiError(500, 'Error verifying email')
  } finally {
    client.release()
  }
}

/**
 * Request a password reset
 * @param email User's email
 */
export const forgotPassword = async (email: string): Promise<{ success: boolean }> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex')
    const resetTokenExpires = new Date(Date.now() + 3600000) // 1 hour
    
    // Update user with reset token
    const result = await client.query(
      `UPDATE users 
       SET reset_token = $1, reset_token_expires = $2, updated_at = NOW() 
       WHERE email = $3
       RETURNING id`,
      [resetToken, resetTokenExpires, email]
    )
    
    if (result.rowCount === 0) {
      // Don't reveal user existence, just return success
      logger.info(`Password reset requested for non-existent email: ${email}`)
      await client.query('COMMIT')
      return { success: true }
    }
    
    // Send password reset email
    await emailService.sendPasswordResetEmail(email, resetToken)
    
    await client.query('COMMIT')
    
    return { success: true }
  } catch (error) {
    await client.query('ROLLBACK')
    
    logger.error('Password reset request error:', error)
    throw new ApiError(500, 'Error processing password reset request')
  } finally {
    client.release()
  }
}

/**
 * Reset a user's password using a token
 * @param token Reset token
 * @param newPassword New password
 */
export const resetPassword = async (token: string, newPassword: string): Promise<{ success: boolean }> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Validate password strength
    const passwordValidation = validatePasswordStrength(newPassword)
    if (!passwordValidation.valid) {
      throw new ApiError(400, passwordValidation.message || 'Password does not meet requirements')
    }
    
    // Find user by reset token
    const userResult = await client.query(
      `SELECT id, email FROM users 
       WHERE reset_token = $1 AND reset_token_expires > NOW()`,
      [token]
    )
    
    if (userResult.rowCount === 0) {
      throw new ApiError(400, 'Invalid or expired reset token')
    }
    
    const userId = userResult.rows[0].id
    const userEmail = userResult.rows[0].email
    
    // Check password history
    if (authConfig.password.passwordHistory > 0) {
      // Implementation would check against password history table
      // This is a placeholder for future implementation
      logger.info('Password history check would be performed here')
    }
    
    // Hash the new password
    const passwordHash = await bcrypt.hash(
      newPassword,
      authConfig.password.saltRounds
    )
    
    // Update user's password
    await client.query(
      `UPDATE users 
       SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL, updated_at = NOW() 
       WHERE id = $2`,
      [passwordHash, userId]
    )
    
    // Invalidate all existing sessions for security
    await client.query(
      'DELETE FROM sessions WHERE user_id = $1',
      [userId]
    )
    
    // Optional: Send password change notification
    // await emailService.sendPasswordChangeNotification(userEmail)
    
    await client.query('COMMIT')
    
    return { success: true }
  } catch (error) {
    await client.query('ROLLBACK')
    
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Password reset error:', error)
    throw new ApiError(500, 'Error resetting password')
  } finally {
    client.release()
  }
}

/**
 * Change a user's password
 * @param userId User ID
 * @param currentPassword Current password
 * @param newPassword New password
 */
export const changePassword = async (
  userId: string,
  currentPassword: string,
  newPassword: string
): Promise<{ success: boolean }> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Validate password strength
    const passwordValidation = validatePasswordStrength(newPassword)
    if (!passwordValidation.valid) {
      throw new ApiError(400, passwordValidation.message || 'Password does not meet requirements')
    }
    
    // Get current password hash
    const result = await client.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId]
    )
    
    if (result.rowCount === 0) {
      throw new ApiError(404, 'User not found')
    }
    
    const user = result.rows[0]
    
    // Verify current password
    if (!(await bcrypt.compare(currentPassword, user.password_hash))) {
      throw new ApiError(400, 'Current password is incorrect')
    }
    
    // Check if new password is same as current
    if (await bcrypt.compare(newPassword, user.password_hash)) {
      throw new ApiError(400, 'New password must be different from current password')
    }
    
    // Hash the new password
    const passwordHash = await bcrypt.hash(
      newPassword,
      authConfig.password.saltRounds
    )
    
    // Update password
    await client.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [passwordHash, userId]
    )
    
    // Invalidate all existing sessions except current one for security
    // In a real implementation, you would keep the current session
    // This is just a placeholder
    
    await client.query('COMMIT')
    
    return { success: true }
  } catch (error) {
    await client.query('ROLLBACK')
    
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Change password error:', error)
    throw new ApiError(500, 'Error changing password')
  } finally {
    client.release()
  }
}

/**
 * Refresh access token using refresh token
 * @param refreshToken Refresh token
 * @param ipAddress IP address of the client (for security)
 * @param userAgent User agent of the client (for security)
 */
export const refreshToken = async (
  refreshToken: string,
  ipAddress?: string,
  userAgent?: string
): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Verify the session exists
    const sessionResult = await client.query(
      'SELECT * FROM sessions WHERE token = $1 AND expires_at > NOW()',
      [refreshToken]
    )
    
    if (sessionResult.rowCount === 0) {
      throw new ApiError(401, 'Invalid or expired refresh token')
    }
    
    const session = sessionResult.rows[0]
    
    // Security check: IP and user agent if available
    if (ipAddress && session.ip_address && ipAddress !== session.ip_address) {
      logger.warn('IP address mismatch during token refresh', { 
        sessionId: session.id, 
        originalIp: session.ip_address, 
        newIp: ipAddress 
      })
      // Consider additional security measures here
    }
    
    // Verify the token itself
    let decoded: TokenPayload
    try {
      decoded = verifyToken(refreshToken)
      
      // Check if token type is 'refresh'
      if (decoded.type !== 'refresh') {
        throw new ApiError(401, 'Invalid token type')
      }
    } catch (error) {
      // Delete the invalid session
      await client.query('DELETE FROM sessions WHERE id = $1', [session.id])
      await client.query('COMMIT')
      throw new ApiError(401, 'Invalid refresh token')
    }
    
    // Get user info
    const userResult = await client.query(
      'SELECT id, email, role FROM users WHERE id = $1',
      [session.user_id]
    )
    
    if (userResult.rowCount === 0) {
      throw new ApiError(404, 'User not found')
    }
    
    const user = userResult.rows[0]
    
    // Generate new tokens
    const tokens = generateTokens({
      id: user.id,
      email: user.email,
      role: user.role
    })
    
    // Update session with new refresh token
    const expiryDate = new Date()
    expiryDate.setDate(expiryDate.getDate() + 7) // 7 days from now
    
    await client.query(
      'UPDATE sessions SET token = $1, expires_at = $2, updated_at = NOW() WHERE id = $3',
      [tokens.refreshToken, expiryDate, session.id]
    )
    
    await client.query('COMMIT')
    
    return tokens
  } catch (error) {
    await client.query('ROLLBACK')
    
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Token refresh error:', error)
    throw new ApiError(500, 'Error refreshing token')
  } finally {
    client.release()
  }
}

/**
 * Logout a user
 * @param userId User ID
 * @param refreshToken Refresh token to invalidate
 * @param allDevices Whether to logout from all devices
 */
export const logout = async (
  userId: string,
  refreshToken?: string,
  allDevices = false
): Promise<{ success: boolean }> => {
  const client = await db.getClient()
  
  try {
    if (allDevices) {
      // Logout from all devices by deleting all sessions
      await client.query('DELETE FROM sessions WHERE user_id = $1', [userId])
    } else if (refreshToken) {
      // Logout from current device by deleting specific session
      await client.query('DELETE FROM sessions WHERE user_id = $1 AND token = $2', [userId, refreshToken])
    } else {
      // No token provided but not all devices, do nothing
      return { success: true }
    }
    
    return { success: true }
  } catch (error) {
    logger.error('Logout error:', error)
    throw new ApiError(500, 'Error during logout')
  } finally {
    client.release()
  }
}

/**
 * Get a user by ID
 * @param userId User ID
 */
export const getUserById = async (userId: string): Promise<UserData> => {
  try {
    const result = await db.query(
      `SELECT id, name, email, role, is_verified, created_at, last_login 
       FROM users WHERE id = $1`,
      [userId]
    )
    
    if (result.rowCount === 0) {
      throw new ApiError(404, 'User not found')
    }
    
    const user = result.rows[0]
    
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      isVerified: user.is_verified,
      createdAt: user.created_at,
      lastLogin: user.last_login
    }
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('Get user error:', error)
    throw new ApiError(500, 'Error retrieving user')
  }
}

/**
 * Setup MFA for a user
 * @param userId User ID
 */
export const setupMFA = async (userId: string): Promise<{ secret: string; qrCodeUrl: string }> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Get user info
    const userResult = await client.query(
      'SELECT email FROM users WHERE id = $1',
      [userId]
    )
    
    if (userResult.rowCount === 0) {
      throw new ApiError(404, 'User not found')
    }
    
    const user = userResult.rows[0]
    
    // Generate MFA secret (this would use a library like speakeasy in real implementation)
    const secret = crypto.randomBytes(20).toString('hex')
    
    // Update user with MFA secret (not enabled yet)
    await client.query(
      'UPDATE users SET mfa_secret = $1, updated_at = NOW() WHERE id = $2',
      [secret, userId]
    )
    
    await client.query('COMMIT')
    
    // Generate QR code URL (this would use a library like qrcode in real implementation)
    const qrCodeUrl = `otpauth://totp/GemstoneSysten:${user.email}?secret=${secret}&issuer=GemstoneSysten`
    
    return { secret, qrCodeUrl }
  } catch (error) {
    await client.query('ROLLBACK')
    
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('MFA setup error:', error)
    throw new ApiError(500, 'Error setting up MFA')
  } finally {
    client.release()
  }
}

/**
 * Verify and enable MFA for a user
 * @param userId User ID
 * @param token MFA token to verify
 */
export const verifyAndEnableMFA = async (userId: string, token: string): Promise<{ success: boolean }> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Get user MFA secret
    const userResult = await client.query(
      'SELECT mfa_secret FROM users WHERE id = $1',
      [userId]
    )
    
    if (userResult.rowCount === 0) {
      throw new ApiError(404, 'User not found')
    }
    
    const user = userResult.rows[0]
    
    if (!user.mfa_secret) {
      throw new ApiError(400, 'MFA not set up for this user')
    }
    
    // Verify token (this would use a library like speakeasy in real implementation)
    // This is a placeholder for actual verification
    const isValidToken = token === '123456' // Never do this in production!
    
    if (!isValidToken) {
      throw new ApiError(400, 'Invalid MFA token')
    }
    
    // Enable MFA for user
    await client.query(
      'UPDATE users SET mfa_enabled = TRUE, updated_at = NOW() WHERE id = $1',
      [userId]
    )
    
    await client.query('COMMIT')
    
    return { success: true }
  } catch (error) {
    await client.query('ROLLBACK')
    
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('MFA verification error:', error)
    throw new ApiError(500, 'Error verifying MFA token')
  } finally {
    client.release()
  }
}

/**
 * Admin login
 * @param email Admin's email
 * @param password Plain text password
 * @param ipAddress Admin's IP address (for security)
 * @param userAgent Admin's browser agent (for security)
 */
export const adminLogin = async (
  email: string,
  password: string,
  ipAddress?: string,
  userAgent?: string
): Promise<LoginResponse> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Find user by email and ensure they have admin role
    const result = await client.query(
      `SELECT u.* FROM users u
       JOIN user_roles ur ON u.id = ur.user_id
       JOIN roles r ON ur.role_id = r.id
       WHERE u.email = $1 AND r.name = 'admin'`,
      [email]
    )
    
    const user = result.rows[0]
    
    // Check if user exists and is an admin
    if (!user) {
      logger.warn(`Failed admin login attempt for: ${email}`, { ipAddress })
      throw new ApiError(401, 'Invalid email or password')
    }
    
    // Check if account is locked
    if (user.account_locked_until && new Date(user.account_locked_until) > new Date()) {
      throw new ApiError(423, 'Account is temporarily locked. Please try again later.')
    }
    
    // Check if password is correct
    const passwordValid = await bcrypt.compare(password, user.password_hash)
    
    if (!passwordValid) {
      // Handle failed login (similar to regular login)
      const failedAttempts = user.failed_login_attempts + 1
      
      // Lock account after 5 failed attempts
      if (failedAttempts >= 5) {
        const lockUntil = new Date()
        lockUntil.setMinutes(lockUntil.getMinutes() + 15) // Lock for 15 minutes
        
        await client.query(
          'UPDATE users SET failed_login_attempts = $1, account_locked_until = $2 WHERE id = $3',
          [failedAttempts, lockUntil, user.id]
        )
      } else {
        await client.query(
          'UPDATE users SET failed_login_attempts = $1 WHERE id = $2',
          [failedAttempts, user.id]
        )
      }
      
      await client.query('COMMIT')
      logger.warn(`Failed admin login attempt for user: ${user.id}`, { ipAddress })
      throw new ApiError(401, 'Invalid email or password')
    }
    
    // Reset failed login attempts
    await client.query(
      'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, last_login = NOW() WHERE id = $1',
      [user.id]
    )
    
    // Generate tokens with shorter expiry for admin
    const tokens = generateTokens({
      id: user.id,
      email: user.email,
      role: user.role,
      isAdmin: true, // Mark as admin token
    })
    
    // Create admin session record
    const sessionId = crypto.randomUUID()
    
    // Shorter expiry for admin sessions
    const expiryDate = new Date()
    expiryDate.setHours(expiryDate.getHours() + 4) // 4 hours from now
    
    await client.query(
      `INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6)`,
       [sessionId, user.id, tokens.refreshToken, expiryDate, ipAddress || null, userAgent || null]
      )
      
      await client.query('COMMIT')
      
      return {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          isVerified: user.is_verified
        },
        tokens
      }
    } catch (error) {
      await client.query('ROLLBACK')
      
      if (error instanceof ApiError) {
        throw error
      }
      
      logger.error('Admin login error:', error)
      throw new ApiError(500, 'Error during admin login')
    } finally {
      client.release()
    }
  }
  
  /**
   * Verify an admin token
   * @param token Admin token to verify
   */
  export const verifyAdminToken = async (token: string): Promise<TokenPayload> => {
    try {
      // Verify the token
      const decoded = verifyToken(token)
      
      // Check if it's an admin token
      if (!decoded.isAdmin && decoded.role !== 'admin') {
        throw new ApiError(403, 'Not an admin token')
      }
      
      return decoded
    } catch (error) {
      if (error instanceof ApiError) {
        throw error
      }
      
      logger.error('Admin token verification error:', error)
      throw new ApiError(401, 'Invalid admin token')
    }
  }
  
  /**
   * Generate admin tokens
   * @param payload Admin user data
   */
  export const generateAdminTokens = async (payload: {
    id: string
    email: string
    role: string
    name: string
  }): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }> => {
    // Generate tokens with admin flag
    return generateTokens({
      ...payload,
      isAdmin: true
    })
  }
  
  /**
   * Invalidate an admin session
   * @param userId Admin user ID
   */
  export const invalidateAdminSession = async (userId: string): Promise<{ success: boolean }> => {
    try {
      // Delete all admin sessions for this user
      await db.query(
        `DELETE FROM sessions 
         WHERE user_id = $1 
         AND EXISTS (
           SELECT 1 FROM users 
           WHERE users.id = sessions.user_id 
           AND users.role = 'admin'
         )`,
        [userId]
      )
      
      return { success: true }
    } catch (error) {
      logger.error('Admin session invalidation error:', error)
      throw new ApiError(500, 'Error invalidating admin session')
    }
  }



/**
 * Check if a user has MFA enabled
 * @param userId User ID
 */
export const checkUserMFA = async (userId: string): Promise<{ mfaEnabled: boolean }> => {
  try {
    const result = await db.query(
      'SELECT mfa_enabled, mfa_secret FROM users WHERE id = $1',
      [userId]
    )
    
    if (!result || result.rowCount === 0) {
      throw new ApiError(404, 'User not found')
    }
    
    const user = result.rows[0]
    
    return { mfaEnabled: user.mfa_enabled || false }
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }
    
    logger.error('MFA check error:', error)
    throw new ApiError(500, 'Error checking MFA status')
  }
}

/**
 * Verify an MFA token
 * @param secret MFA secret
 * @param token MFA token
 */
export const verifyMfaToken = async (secret: string, token: string): Promise<boolean> => {
  try {
    // In a real implementation, you would use the speakeasy library here
    // This is just a simple implementation for example purposes
    // Replace with actual speakeasy verification in production
    
    // For demonstration purposes only (NEVER do this in production)
    // In production, use: return speakeasy.totp.verify({ secret, encoding: 'base32', token })
    return token === '123456' || token === '000000'
  } catch (error) {
    logger.error('MFA token verification error:', error)
    return false
  }
}

/**
 * Enable MFA for a user
 * @param userId User ID
 * @param secret MFA secret
 */
export const enableMFA = async (userId: string, secret: string): Promise<{ success: boolean }> => {
  const client = await db.getClient()
  
  try {
    await client.query('BEGIN')
    
    // Update user with MFA secret and enable MFA
    await client.query(
      'UPDATE users SET mfa_secret = $1, mfa_enabled = TRUE, updated_at = NOW() WHERE id = $2',
      [secret, userId]
    )
    
    await client.query('COMMIT')
    
    return { success: true }
  } catch (error) {
    await client.query('ROLLBACK')
    
    logger.error('MFA enable error:', error)
    throw new ApiError(500, 'Error enabling MFA')
  } finally {
    client.release()
  }
}

/**
 * Verify a user's MFA token
 * @param userId User ID
 * @param token MFA token
 */
export const verifyUserMfa = async (userId: string, token: string): Promise<boolean> => {
  try {
    // Get user's MFA secret
    const result = await db.query(
      'SELECT mfa_secret FROM users WHERE id = $1 AND mfa_enabled = TRUE',
      [userId]
    )
    
    if (!result || result.rowCount === 0) {
      return false
    }
    
    const user = result.rows[0]
    
    if (!user.mfa_secret) {
      return false
    }
    
    // Verify token using the user's secret
    return await verifyMfaToken(user.mfa_secret, token)
  } catch (error) {
    logger.error('User MFA verification error:', error)
    return false
  }
}