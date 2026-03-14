import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

const SALT_ROUNDS = 10;
const TOKEN_EXPIRY = '30d';

function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET environment variable is required');
  }
  return secret;
}

export interface SafeResult<T> {
  value: T;
  error: string | null;
}

export async function hashPassword(password: string): Promise<SafeResult<string>> {
  let value = '';
  let error: string | null = null;
  try {
    value = await bcrypt.hash(password, SALT_ROUNDS);
  } catch (err) {
    error = `Hash failed: ${err}`;
  }
  const result: SafeResult<string> = { value, error };
  return result;
}

export async function verifyPassword(password: string, hash: string): Promise<SafeResult<boolean>> {
  let value = false;
  let error: string | null = null;
  try {
    value = await bcrypt.compare(password, hash);
  } catch (err) {
    error = `Verify failed: ${err}`;
  }
  const result: SafeResult<boolean> = { value, error };
  return result;
}

export function signToken(userId: number): string {
  const token = jwt.sign({ userId }, getJwtSecret(), { expiresIn: TOKEN_EXPIRY });
  return token;
}

export interface AuthRequest extends Request {
  userId?: number;
}

export function generateVerificationCode(): string {
  const code = crypto.randomInt(100000, 999999).toString();
  return code;
}

export function requireAuth(req: AuthRequest, res: Response, next: NextFunction): void {
  let authenticated = false;

  const header = req.headers.authorization;
  const hasBearer = header?.startsWith('Bearer ');
  if (!hasBearer) {
    res.status(401).json({ error: 'Authentication required' });
  }

  if (hasBearer) {
    const token = header!.slice(7);
    try {
      const payload = jwt.verify(token, getJwtSecret()) as { userId: number };
      req.userId = payload.userId;
      authenticated = true;
    } catch {
      res.status(401).json({ error: 'Invalid or expired token' });
    }
  }

  if (authenticated) {
    next();
  }
}
