import dotenv from 'dotenv';
import path from 'path';
import crypto from 'crypto';

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

// Dynamically generate a random 256-bit cryptographic secret if JWT_SECRET is omitted or default
const resolvedJwtSecret = (process.env.JWT_SECRET && process.env.JWT_SECRET !== 'your-secure-jwt-secret')
  ? process.env.JWT_SECRET
  : crypto.randomBytes(32).toString('hex');

export const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  upstreamPort: parseInt(process.env.UPSTREAM_PORT || '5001', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  jwtSecret: resolvedJwtSecret,
  databaseUrl: process.env.DATABASE_URL || 'file:./dev.db',
  wafMode: (process.env.WAF_MODE || 'PREVENTION') as 'PREVENTION' | 'DETECTION' | 'DISABLED',
  trustedProxies: (process.env.TRUSTED_PROXIES || '127.0.0.1,::1').split(','),
};
