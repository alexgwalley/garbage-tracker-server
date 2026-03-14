import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';

// --- Mocks (must be before app import) ---

const mockQuery = vi.fn();
vi.mock('pg', () => {
  function Pool() {
    // @ts-ignore
    this.query = mockQuery;
  }
  return { default: { Pool } };
});

vi.mock('bcryptjs', () => ({
  default: {
    hash: vi.fn((_pw: string, _rounds: number) => Promise.resolve('hashed_password')),
    compare: vi.fn((pw: string, hash: string) => Promise.resolve(pw === hash)),
  },
}));

const mockSendVerificationEmail = vi.fn(() => Promise.resolve({ value: '', error: null }));
vi.mock('./email/email.js', () => ({
  sendVerificationEmail: mockSendVerificationEmail,
}));

vi.mock('crypto', async () => {
  const actual = await vi.importActual<typeof import('crypto')>('crypto');
  return {
    ...actual,
    default: {
      ...actual,
      randomInt: () => 123456,
    },
  };
});

// Set env vars before importing app
process.env.JWT_SECRET = 'test-secret';

const { app } = await import('./server.js');
const { signToken } = await import('./auth.js');

// --- Helpers ---

function makeEmptyQueryResult(rows: any[] = []) {
  return {
    rows,
    rowCount: rows.length,
    command: '',
    oid: 0,
    fields: [],
  };
}

function authHeader(userId: number) {
  const token = signToken(userId);
  return { Authorization: `Bearer ${token}` };
}

// --- Tests ---

describe('Auth endpoints', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // 1. Register success
  it('POST /auth/register → 201, returns token + user', async () => {
    // First query: check existing user (none found)
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([]));
    // Second query: INSERT returning user
    const insertedUser = { id: 1, name: 'alice', email: 'alice@example.com', email_verified: false, avatar_url: null };
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([insertedUser]));

    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'alice@example.com', password: 'hashed_password', name: 'alice' });

    expect(res.status).toBe(201);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.email).toBe('alice@example.com');
    expect(res.body.user.email_verified).toBe(false);
    expect(mockSendVerificationEmail).toHaveBeenCalledWith('alice@example.com', '123456');
  });

  // 2. Register duplicate email
  it('POST /auth/register duplicate email → 409', async () => {
    const existingUser = { id: 99 };
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([existingUser]));

    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'taken@example.com', password: 'pass123' });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('Email already registered');
  });

  // 3. Register DB error
  it('POST /auth/register DB error → 500', async () => {
    mockQuery.mockRejectedValueOnce(new Error('connection refused'));

    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'fail@example.com', password: 'pass123' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Registration failed');
  });

  // 4. Login success
  it('POST /auth/login → 200, returns token + user with email_verified', async () => {
    const dbUser = {
      id: 1, name: 'alice', email: 'alice@example.com',
      password_hash: 'correct_pw', email_verified: true, avatar_url: null,
    };
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([dbUser]));

    const res = await request(app)
      .post('/auth/login')
      .send({ email: 'alice@example.com', password: 'correct_pw' });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.email_verified).toBe(true);
    expect(res.body.user.password_hash).toBeUndefined();
  });

  // 5. Login wrong password
  it('POST /auth/login wrong password → 401', async () => {
    const dbUser = {
      id: 1, name: 'alice', email: 'alice@example.com',
      password_hash: 'correct_pw', email_verified: false, avatar_url: null,
    };
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([dbUser]));

    const res = await request(app)
      .post('/auth/login')
      .send({ email: 'alice@example.com', password: 'wrong_pw' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid email or password');
  });

  // 6. Login nonexistent user
  it('POST /auth/login nonexistent user → 401', async () => {
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([]));

    const res = await request(app)
      .post('/auth/login')
      .send({ email: 'nobody@example.com', password: 'pass' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid email or password');
  });

  // 7. Verify correct code
  it('POST /auth/verify correct code → 200, email_verified: true', async () => {
    // SELECT verification_token, email_verified
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([
      { verification_token: '123456', email_verified: false },
    ]));
    // UPDATE
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult());

    const res = await request(app)
      .post('/auth/verify')
      .set(authHeader(1))
      .send({ code: '123456' });

    expect(res.status).toBe(200);
    expect(res.body.email_verified).toBe(true);
  });

  // 8. Verify wrong code
  it('POST /auth/verify wrong code → 400', async () => {
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([
      { verification_token: '123456', email_verified: false },
    ]));

    const res = await request(app)
      .post('/auth/verify')
      .set(authHeader(1))
      .send({ code: '000000' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid verification code');
  });

  // 9. Verify already verified (idempotent)
  it('POST /auth/verify already verified → 200', async () => {
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([
      { verification_token: null, email_verified: true },
    ]));

    const res = await request(app)
      .post('/auth/verify')
      .set(authHeader(1))
      .send({ code: '123456' });

    expect(res.status).toBe(200);
    expect(res.body.email_verified).toBe(true);
  });

  // 10. Resend verification
  it('POST /auth/resend-verification → 200, calls sendVerificationEmail', async () => {
    // SELECT email, email_verified
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([
      { email: 'alice@example.com', email_verified: false },
    ]));
    // UPDATE verification_token
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult());

    const res = await request(app)
      .post('/auth/resend-verification')
      .set(authHeader(1));

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Verification email sent');
    expect(mockSendVerificationEmail).toHaveBeenCalledWith('alice@example.com', '123456');
  });

  // 11. Resend already verified
  it('POST /auth/resend-verification already verified → 200 "Already verified"', async () => {
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([
      { email: 'alice@example.com', email_verified: true },
    ]));

    const res = await request(app)
      .post('/auth/resend-verification')
      .set(authHeader(1));

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Already verified');
    expect(mockSendVerificationEmail).not.toHaveBeenCalled();
  });

  // 12. GET /auth/me returns user with email_verified
  it('GET /auth/me → 200, returns user with email_verified', async () => {
    const dbUser = {
      id: 1, name: 'alice', email: 'alice@example.com',
      email_verified: true, avatar_url: null,
      total_paths: 5, total_distance_meters: 1000, total_duration_seconds: 3600,
    };
    mockQuery.mockResolvedValueOnce(makeEmptyQueryResult([dbUser]));

    const res = await request(app)
      .get('/auth/me')
      .set(authHeader(1));

    expect(res.status).toBe(200);
    expect(res.body.email_verified).toBe(true);
    expect(res.body.email).toBe('alice@example.com');
  });

  // 13. GET /auth/me unauthenticated
  it('GET /auth/me unauthenticated → 401', async () => {
    const res = await request(app).get('/auth/me');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Authentication required');
  });
});
