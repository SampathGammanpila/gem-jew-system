// File: packages/backend/src/api/validators/auth.validator.ts

import Joi from 'joi'
import { authConfig } from '../../config/auth'

/**
 * Password validation schema
 */
const passwordSchema = Joi.string()
  .min(authConfig.password.minLength)
  .regex(/[A-Z]/, 'uppercase')
  .regex(/[a-z]/, 'lowercase')
  .regex(/[0-9]/, 'numbers')
  .regex(/[^A-Za-z0-9]/, 'special')
  .messages({
    'string.empty': 'Password is required',
    'string.min': `Password must be at least ${authConfig.password.minLength} characters long`,
    'string.pattern.name': 'Password must contain at least one {#name} character',
  })

/**
 * Validator for user registration
 */
export const registerValidator = Joi.object({
  body: Joi.object({
    name: Joi.string().required().min(2).max(100).trim()
      .messages({
        'string.empty': 'Name is required',
        'string.min': 'Name must be at least 2 characters long',
        'string.max': 'Name cannot exceed 100 characters',
      }),
    email: Joi.string().required().email().lowercase().trim()
      .messages({
        'string.empty': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
    password: passwordSchema.required(),
    confirmPassword: Joi.string().required().valid(Joi.ref('password'))
      .messages({
        'string.empty': 'Please confirm your password',
        'any.only': 'Passwords do not match',
      }),
  }).required(),
  query: Joi.object({}),
  params: Joi.object({}),
})

/**
 * Validator for professional registration
 */
export const registerProfessionalValidator = Joi.object({
  body: Joi.object({
    name: Joi.string().required().min(2).max(100).trim()
      .messages({
        'string.empty': 'Name is required',
        'string.min': 'Name must be at least 2 characters long',
        'string.max': 'Name cannot exceed 100 characters',
      }),
    email: Joi.string().required().email().lowercase().trim()
      .messages({
        'string.empty': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
    password: passwordSchema.required(),
    confirmPassword: Joi.string().required().valid(Joi.ref('password'))
      .messages({
        'string.empty': 'Please confirm your password',
        'any.only': 'Passwords do not match',
      }),
    professionalType: Joi.string().required().valid('dealer', 'cutter', 'appraiser')
      .messages({
        'string.empty': 'Professional type is required',
        'any.only': 'Professional type must be dealer, cutter, or appraiser',
      }),
    company: Joi.string().allow('').max(100).trim(),
    phone: Joi.string().required().pattern(/^\+?[0-9\s\-\(\)]{8,20}$/)
      .messages({
        'string.empty': 'Phone number is required',
        'string.pattern.base': 'Please provide a valid phone number',
      }),
  }).required(),
  query: Joi.object({}),
  params: Joi.object({}),
})

/**
 * Validator for user login
 */
export const loginValidator = Joi.object({
  body: Joi.object({
    email: Joi.string().required().email().lowercase().trim()
      .messages({
        'string.empty': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
    password: Joi.string().required()
      .messages({
        'string.empty': 'Password is required',
      }),
    rememberMe: Joi.boolean().default(false),
  }).required(),
  query: Joi.object({}),
  params: Joi.object({}),
})

/**
 * Validator for forgot password request
 */
export const forgotPasswordValidator = Joi.object({
  body: Joi.object({
    email: Joi.string().required().email().lowercase().trim()
      .messages({
        'string.empty': 'Email is required',
        'string.email': 'Please provide a valid email address',
      }),
  }).required(),
  query: Joi.object({}),
  params: Joi.object({}),
})

/**
 * Validator for reset password
 */
export const resetPasswordValidator = Joi.object({
  body: Joi.object({
    token: Joi.string().required()
      .messages({
        'string.empty': 'Reset token is required',
      }),
    newPassword: passwordSchema.required(),
    confirmPassword: Joi.string().required().valid(Joi.ref('newPassword'))
      .messages({
        'string.empty': 'Please confirm your password',
        'any.only': 'Passwords do not match',
      }),
  }).required(),
  query: Joi.object({}),
  params: Joi.object({}),
})

/**
 * Validator for verify email
 */
export const verifyEmailValidator = Joi.object({
  body: Joi.object({
    token: Joi.string().required()
      .messages({
        'string.empty': 'Verification token is required',
      }),
  }).required(),
  query: Joi.object({
    token: Joi.string().optional(),
  }),
  params: Joi.object({}),
})

/**
 * Validator for change password
 */
export const changePasswordValidator = Joi.object({
  body: Joi.object({
    currentPassword: Joi.string().required()
      .messages({
        'string.empty': 'Current password is required',
      }),
    newPassword: passwordSchema.required(),
    confirmPassword: Joi.string().required().valid(Joi.ref('newPassword'))
      .messages({
        'string.empty': 'Please confirm your password',
        'any.only': 'Passwords do not match',
      }),
  }).required(),
  query: Joi.object({}),
  params: Joi.object({}),
})

/**
 * Validator for token refresh
 */
export const refreshTokenValidator = Joi.object({
  body: Joi.object({
    refreshToken: Joi.string()
      .messages({
        'string.empty': 'Refresh token is required',
      }),
  }),
  query: Joi.object({}),
  params: Joi.object({}),
})

/**
 * Validator for logout
 */
export const logoutValidator = Joi.object({
  body: Joi.object({
    refreshToken: Joi.string().optional(),
    allDevices: Joi.boolean().default(false),
  }),
  query: Joi.object({}),
  params: Joi.object({}),
})

/**
 * Validator for MFA verification
 */
export const verifyMfaValidator = Joi.object({
  body: Joi.object({
    token: Joi.string().required().length(6).pattern(/^[0-9]+$/)
      .messages({
        'string.empty': 'MFA token is required',
        'string.length': 'MFA token must be 6 digits',
        'string.pattern.base': 'MFA token must only contain digits',
      }),
  }).required(),
  query: Joi.object({}),
  params: Joi.object({}),
})