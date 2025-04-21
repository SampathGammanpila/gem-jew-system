-- File: database/migrations/001_initial_schema.sql
-- Fix: Add more comprehensive initial schema setup

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Schema initialization timestamp
CREATE TABLE IF NOT EXISTS schema_migrations (
  version VARCHAR(255) NOT NULL,
  applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  PRIMARY KEY (version)
);

-- Insert migration version
INSERT INTO schema_migrations (version) VALUES ('001_initial_schema');

-- Set up updated_at trigger function
CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create users table with enhanced security
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) NOT NULL,
  email CITEXT NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'user',
  is_verified BOOLEAN NOT NULL DEFAULT FALSE,
  verification_token VARCHAR(255),
  reset_token VARCHAR(255),
  reset_token_expires TIMESTAMP WITH TIME ZONE,
  mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_secret VARCHAR(255),
  last_login TIMESTAMP WITH TIME ZONE,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  account_locked_until TIMESTAMP WITH TIME ZONE,
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create index on email for faster lookups
CREATE INDEX idx_users_email ON users(email);

-- Create index on role for filtering
CREATE INDEX idx_users_role ON users(role);

-- Apply updated_at trigger to users table
CREATE TRIGGER set_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();

-- Create admin user (password: admin123)
INSERT INTO users (name, email, password_hash, role, is_verified)
VALUES (
  'System Admin',
  'admin@example.com',
  crypt('admin123', gen_salt('bf', 10)),
  'admin',
  TRUE
)
ON CONFLICT (email) DO NOTHING;

-- Create sessions table for better session management
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token VARCHAR(255) NOT NULL UNIQUE,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create index on token for faster lookups
CREATE INDEX idx_sessions_token ON sessions(token);

-- Create index on user_id for faster lookups
CREATE INDEX idx_sessions_user_id ON sessions(user_id);

-- Apply updated_at trigger to sessions table
CREATE TRIGGER set_sessions_updated_at
BEFORE UPDATE ON sessions
FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();

-- File: database/migrations/002_user_roles.sql
-- Fix: Enhance roles and permissions

-- Insert migration version
INSERT INTO schema_migrations (version) VALUES ('002_user_roles');

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(50) NOT NULL UNIQUE,
  description TEXT,
  is_system BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Apply updated_at trigger to roles table
CREATE TRIGGER set_roles_updated_at
BEFORE UPDATE ON roles
FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();

-- Create permissions table
CREATE TABLE IF NOT EXISTS permissions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) NOT NULL UNIQUE,
  description TEXT,
  resource VARCHAR(50) NOT NULL,
  action VARCHAR(50) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Apply updated_at trigger to permissions table
CREATE TRIGGER set_permissions_updated_at
BEFORE UPDATE ON permissions
FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();

-- Create role_permissions join table
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  PRIMARY KEY (role_id, permission_id)
);

-- Create user_roles join table for users with multiple roles
CREATE TABLE IF NOT EXISTS user_roles (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, role_id)
);

-- Create index for faster lookups
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- Insert default roles
INSERT INTO roles (name, description, is_system) VALUES
  ('admin', 'System administrator with full access', TRUE),
  ('user', 'Regular user with basic access', TRUE),
  ('dealer', 'Gemstone dealer who can sell items', TRUE),
  ('cutter', 'Gemstone cutter who can provide cutting services', TRUE),
  ('appraiser', 'Gemstone appraiser who can provide valuation services', TRUE)
ON CONFLICT (name) DO NOTHING;

-- Insert default permissions
INSERT INTO permissions (name, description, resource, action) VALUES
  ('user:read', 'Can view user information', 'user', 'read'),
  ('user:write', 'Can create and update user information', 'user', 'write'),
  ('user:delete', 'Can delete users', 'user', 'delete'),
  ('gemstone:read', 'Can view gemstone information', 'gemstone', 'read'),
  ('gemstone:write', 'Can create and update gemstone information', 'gemstone', 'write'),
  ('gemstone:delete', 'Can delete gemstones', 'gemstone', 'delete'),
  ('rough_stone:read', 'Can view rough stone information', 'rough_stone', 'read'),
  ('rough_stone:write', 'Can create and update rough stone information', 'rough_stone', 'write'),
  ('rough_stone:delete', 'Can delete rough stones', 'rough_stone', 'delete'),
  ('jewelry:read', 'Can view jewelry information', 'jewelry', 'read'),
  ('jewelry:write', 'Can create and update jewelry information', 'jewelry', 'write'),
  ('jewelry:delete', 'Can delete jewelry', 'jewelry', 'delete'),
  ('marketplace:read', 'Can view marketplace listings', 'marketplace', 'read'),
  ('marketplace:write', 'Can create and update marketplace listings', 'marketplace', 'write'),
  ('marketplace:delete', 'Can delete marketplace listings', 'marketplace', 'delete'),
  ('certificate:read', 'Can view certificates', 'certificate', 'read'),
  ('certificate:write', 'Can create and update certificates', 'certificate', 'write'),
  ('certificate:delete', 'Can delete certificates', 'certificate', 'delete'),
  ('admin:access', 'Can access admin panel', 'admin', 'access'),
  ('professional:verified', 'Professional with verified status', 'professional', 'verified')
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin';

-- Assign basic permissions to user role
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
  r.id, 
  p.id
FROM 
  roles r, 
  permissions p
WHERE 
  r.name = 'user' AND 
  p.name IN (
    'user:read', 
    'gemstone:read', 
    'rough_stone:read', 
    'jewelry:read', 
    'marketplace:read', 
    'certificate:read'
  );

-- Assign permissions to dealer role
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
  r.id, 
  p.id
FROM 
  roles r, 
  permissions p
WHERE 
  r.name = 'dealer' AND 
  p.name IN (
    'user:read', 
    'gemstone:read', 
    'gemstone:write', 
    'rough_stone:read', 
    'rough_stone:write', 
    'jewelry:read', 
    'jewelry:write', 
    'marketplace:read', 
    'marketplace:write', 
    'certificate:read'
  );

-- Assign permissions to cutter role
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
  r.id, 
  p.id
FROM 
  roles r, 
  permissions p
WHERE 
  r.name = 'cutter' AND 
  p.name IN (
    'user:read', 
    'gemstone:read', 
    'gemstone:write', 
    'rough_stone:read', 
    'rough_stone:write', 
    'marketplace:read', 
    'marketplace:write', 
    'certificate:read'
  );

-- Assign permissions to appraiser role
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
  r.id, 
  p.id
FROM 
  roles r, 
  permissions p
WHERE 
  r.name = 'appraiser' AND 
  p.name IN (
    'user:read', 
    'gemstone:read', 
    'rough_stone:read', 
    'jewelry:read', 
    'certificate:read', 
    'certificate:write'
  );

-- Insert admin user into admin role
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'admin@example.com' AND r.name = 'admin'
ON CONFLICT DO NOTHING;