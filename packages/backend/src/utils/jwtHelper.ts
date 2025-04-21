// File: packages/backend/src/utils/jwtHelper.ts

import jwt, { SignOptions, Secret, JwtPayload } from 'jsonwebtoken'
import { authConfig } from '@/config/auth'
import logger from './logger'
import crypto from 'crypto'

// Interface for token payload
export interface TokenPayload extends JwtPayload {
  id: string
  email: string
  role: string
  [key: string]: any
}

// Interface for token response
export interface TokenResponse {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

// Get JWT secret and validate it
const getJwtSecret = (): Secret => {
  const secret = authConfig.jwt.secret
  if (typeof secret !== 'string' || !secret) {
    logger.error('JWT secret is not properly configured')
    throw new Error('JWT secret is not properly configured')
  }
  return secret
}

// Helper function to ensure expiresIn is the correct type
const getExpiresIn = (value: string | number | undefined): jwt.SignOptions['expiresIn'] => {
  return value as jwt.SignOptions['expiresIn']
}

/**
 * Generate a JWT access token
 * @param payload Data to include in the token
 * @param expiresIn Expiration time (default: from config)
 * @returns JWT token
 */
export const generateAccessToken = (
  payload: Omit<TokenPayload, 'jti' | 'iat' | 'exp' | 'type'>,
  expiresIn = getExpiresIn(authConfig.jwt.accessTokenExpiration)
): string => {
  // Add token type and unique identifier
  const tokenPayload = {
    ...payload,
    type: 'access',
    jti: crypto.randomUUID()
  }

  const options: SignOptions = { 
    expiresIn,
    algorithm: 'HS256'
  }

  return jwt.sign(tokenPayload, getJwtSecret(), options)
}

/**
 * Generate a JWT refresh token
 * @param payload Data to include in the token
 * @param expiresIn Expiration time (default: from config)
 * @returns JWT token
 */
export const generateRefreshToken = (
  payload: Omit<TokenPayload, 'jti' | 'iat' | 'exp' | 'type'>,
  expiresIn = getExpiresIn(authConfig.jwt.refreshTokenExpiration)
): string => {
  // Add token type and unique identifier
  const tokenPayload = {
    ...payload,
    type: 'refresh',
    jti: crypto.randomUUID()
  }

  const options: SignOptions = { 
    expiresIn,
    algorithm: 'HS256'
  }

  return jwt.sign(tokenPayload, getJwtSecret(), options)
}

/**
 * Generate both access and refresh tokens
 * @param payload User data to include in tokens
 * @returns Access and refresh tokens with expiry
 */
export const generateTokens = (
  payload: Omit<TokenPayload, 'jti' | 'iat' | 'exp' | 'type'>
): TokenResponse => {
  const accessToken = generateAccessToken(payload)
  const refreshToken = generateRefreshToken(payload)
  
  // Calculate expiry in seconds for client
  const decoded = jwt.decode(accessToken) as jwt.JwtPayload
  const expiresIn = decoded.exp ? decoded.exp - Math.floor(Date.now() / 1000) : 3600
  
  return {
    accessToken,
    refreshToken,
    expiresIn
  }
}

/**
 * Verify a JWT token
 * @param token JWT token to verify
 * @param ignoreExpiration Whether to ignore token expiration (default: false)
 * @returns Decoded token payload
 */
export const verifyToken = (token: string, ignoreExpiration = false): TokenPayload => {
  try {
    const options = ignoreExpiration ? { ignoreExpiration: true } : undefined
    return jwt.verify(token, getJwtSecret(), options) as TokenPayload
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      logger.debug('Token expired:', { error })
      throw error
    }
    if (error instanceof jwt.JsonWebTokenError) {
      logger.debug('Invalid token:', { error })
      throw error
    }
    logger.error('Token verification error:', { error })
    throw error
  }
}

/**
 * Decode a JWT token without verification
 * @param token JWT token to decode
 * @returns Decoded token payload or null if invalid
 */
export const decodeToken = (token: string): TokenPayload | null => {
  return jwt.decode(token) as TokenPayload | null
}