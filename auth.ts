import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
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

export async function hashPassword(password: string): Promise<string> {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    return hash;
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
    const isMatch = await bcrypt.compare(password, hash);
    return isMatch;
}

export function signToken(userId: number): string {
    const token = jwt.sign({ userId }, getJwtSecret(), { expiresIn: TOKEN_EXPIRY });
    return token;
}

export interface AuthRequest extends Request {
    userId?: number;
}

export function requireAuth(req: AuthRequest, res: Response, next: NextFunction): void {
    const header = req.headers.authorization;
    const hasBearer = header?.startsWith('Bearer ');
    if (!hasBearer) {
        res.status(401).json({ error: 'Authentication required' });
        return;
    }

    const token = header!.slice(7);
    try {
        const payload = jwt.verify(token, getJwtSecret()) as { userId: number };
        req.userId = payload.userId;
        next();
    } catch {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}
