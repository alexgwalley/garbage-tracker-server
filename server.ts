import 'dotenv/config';
import express from 'express'
import pg from 'pg';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { encodePathList, encodeMarkerList } from './protobuf.js';
import { hashPassword, verifyPassword, signToken, requireAuth, AuthRequest, generateVerificationCode, SafeResult } from './auth.js';
import { sendVerificationEmail } from './email.js';
import jwt from 'jsonwebtoken';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

const uploadsDir = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'uploads')
  : path.join(__dirname, 'uploads');

fs.mkdirSync(uploadsDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (_req, file, cb) => {
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      cb(null, unique + path.extname(file.originalname));
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.use('/uploads', express.static(uploadsDir));

const isProduction = !!process.env.RAILWAY_VOLUME_MOUNT_PATH;
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false,
});

async function safeQuery(text: string, params?: any[]): Promise<SafeResult<pg.QueryResult>> {
  let value: pg.QueryResult = { rows: [], rowCount: 0, command: '', oid: 0, fields: [] };
  let error: string | null = null;
  try {
    value = await pool.query(text, params);
  } catch (err) {
    error = `Query failed: ${err}`;
  }
  const result: SafeResult<pg.QueryResult> = { value, error };
  return result;
}

app.get('/', (req, res) => {
  res.send('Hello There! The server is running.');
});

const isDirectRun = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'));
if (isDirectRun) {
  app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
  });
}

// --- Auth endpoints ---

app.post('/auth/register', async (req, res) => {
  let responseStatus = 0;
  let responseBody: any = null;

  const { email, password, name } = req.body;

  const existing = await safeQuery('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.error) {
    responseStatus = 500;
    responseBody = { error: 'Registration failed' };
  }

  const emailTaken = responseStatus === 0 && existing.value.rows.length > 0;
  if (emailTaken) {
    responseStatus = 409;
    responseBody = { error: 'Email already registered' };
  }

  if (responseStatus === 0) {
    const hashed = await hashPassword(password);
    if (hashed.error) {
      responseStatus = 500;
      responseBody = { error: 'Registration failed' };
    }

    if (responseStatus === 0) {
      const displayName = name || email.split('@')[0];
      const verificationCode = generateVerificationCode();
      const inserted = await safeQuery(
        `INSERT INTO users (name, email, password_hash, verification_token) VALUES ($1, $2, $3, $4)
         RETURNING id, name, email, email_verified,
         CASE WHEN avatar_filename IS NOT NULL THEN '/uploads/' || avatar_filename END AS avatar_url`,
        [displayName, email, hashed.value, verificationCode]
      );

      if (inserted.error) {
        responseStatus = 500;
        responseBody = { error: 'Registration failed' };
      }

      if (responseStatus === 0) {
        const user = inserted.value.rows[0];
        const token = signToken(user.id);
        await sendVerificationEmail(email, verificationCode);
        responseStatus = 201;
        responseBody = { token, user };
      }
    }
  }

  res.status(responseStatus).json(responseBody);
});

app.post('/auth/login', async (req, res) => {
  let responseStatus = 0;
  let responseBody: any = null;

  const { email, password } = req.body;

  const result = await safeQuery(
    `SELECT id, name, email, password_hash, email_verified,
     CASE WHEN avatar_filename IS NOT NULL THEN '/uploads/' || avatar_filename END AS avatar_url
     FROM users WHERE email = $1`,
    [email]
  );
  if (result.error) {
    responseStatus = 500;
    responseBody = { error: 'Login failed' };
  }

  if (responseStatus === 0) {
    const user = result.value.rows[0];
    const userNotFound = !user || !user.password_hash;

    if (userNotFound) {
      responseStatus = 401;
      responseBody = { error: 'Invalid email or password' };
    }

    if (responseStatus === 0) {
      const verified = await verifyPassword(password, user.password_hash);
      if (verified.error || !verified.value) {
        responseStatus = 401;
        responseBody = { error: 'Invalid email or password' };
      }
    }

    if (responseStatus === 0) {
      const token = signToken(user.id);
      const { password_hash: _, ...safeUser } = user;
      responseStatus = 200;
      responseBody = { token, user: safeUser };
    }
  }

  res.status(responseStatus).json(responseBody);
});

app.post('/auth/apple', async (req, res) => {
  let responseStatus = 0;
  let responseBody: any = null;

  const { identity_token, name } = req.body;

  const decoded = jwt.decode(identity_token) as { sub?: string; email?: string } | null;
  const isValidAppleToken = decoded?.sub;
  if (!isValidAppleToken) {
    responseStatus = 400;
    responseBody = { error: 'Invalid identity token' };
  }

  if (responseStatus === 0) {
    const appleId = decoded!.sub!;
    const appleEmail = decoded!.email;

    let userResult = await safeQuery(
      `SELECT id, name, email, email_verified,
       CASE WHEN avatar_filename IS NOT NULL THEN '/uploads/' || avatar_filename END AS avatar_url
       FROM users WHERE apple_id = $1`,
      [appleId]
    );
    if (userResult.error) {
      responseStatus = 500;
      responseBody = { error: 'Apple sign-in failed' };
    }

    // If not found by apple_id, try by email and link the Apple ID
    const notFoundByApple = responseStatus === 0 && userResult.value.rows.length === 0 && appleEmail;
    if (notFoundByApple) {
      userResult = await safeQuery(
        `UPDATE users SET apple_id = $1, email_verified = TRUE WHERE email = $2
         RETURNING id, name, email, email_verified,
         CASE WHEN avatar_filename IS NOT NULL THEN '/uploads/' || avatar_filename END AS avatar_url`,
        [appleId, appleEmail]
      );
      if (userResult.error) {
        responseStatus = 500;
        responseBody = { error: 'Apple sign-in failed' };
      }
    }

    // If still no user, create a new one
    const needsCreate = responseStatus === 0 && userResult.value.rows.length === 0;
    if (needsCreate) {
      const displayName = name || appleEmail?.split('@')[0] || 'User';
      userResult = await safeQuery(
        `INSERT INTO users (name, email, apple_id, email_verified) VALUES ($1, $2, $3, TRUE)
         RETURNING id, name, email, email_verified,
         CASE WHEN avatar_filename IS NOT NULL THEN '/uploads/' || avatar_filename END AS avatar_url`,
        [displayName, appleEmail, appleId]
      );
      if (userResult.error) {
        responseStatus = 500;
        responseBody = { error: 'Apple sign-in failed' };
      }
    }

    if (responseStatus === 0) {
      // Ensure Apple users are always verified
      const appleUser = userResult.value.rows[0];
      const needsVerify = appleUser && !appleUser.email_verified;
      if (needsVerify) {
        await safeQuery('UPDATE users SET email_verified = TRUE WHERE id = $1', [appleUser.id]);
        appleUser.email_verified = true;
      }

      const user = userResult.value.rows[0];
      const token = signToken(user.id);
      responseStatus = 200;
      responseBody = { token, user };
    }
  }

  res.status(responseStatus).json(responseBody);
});

app.get('/auth/me', requireAuth, async (req: AuthRequest, res) => {
  let responseStatus = 0;
  let responseBody: any = null;

  const result = await safeQuery(
    `SELECT id, name, email, email_verified,
     CASE WHEN avatar_filename IS NOT NULL THEN '/uploads/' || avatar_filename END AS avatar_url,
     total_paths, total_distance_meters, total_duration_seconds
     FROM users WHERE id = $1`,
    [req.userId]
  );
  if (result.error) {
    responseStatus = 500;
    responseBody = { error: 'Failed to fetch user' };
  }

  if (responseStatus === 0) {
    const userNotFound = result.value.rows.length === 0;
    if (userNotFound) {
      responseStatus = 404;
      responseBody = { error: 'User not found' };
    }
  }

  if (responseStatus === 0) {
    responseStatus = 200;
    responseBody = result.value.rows[0];
  }

  res.status(responseStatus).json(responseBody);
});

app.post('/auth/verify', requireAuth, async (req: AuthRequest, res) => {
  let responseStatus = 0;
  let responseBody: any = null;

  const { code } = req.body;

  const result = await safeQuery(
    'SELECT verification_token, email_verified FROM users WHERE id = $1',
    [req.userId]
  );
  if (result.error) {
    responseStatus = 500;
    responseBody = { error: 'Verification failed' };
  }

  if (responseStatus === 0) {
    const user = result.value.rows[0];
    const userNotFound = !user;
    if (userNotFound) {
      responseStatus = 404;
      responseBody = { error: 'User not found' };
    }

    const alreadyVerified = !userNotFound && user.email_verified;
    if (alreadyVerified) {
      responseStatus = 200;
      responseBody = { email_verified: true };
    }

    const codeMatches = responseStatus === 0 && user.verification_token === code;
    if (responseStatus === 0 && !codeMatches) {
      responseStatus = 400;
      responseBody = { error: 'Invalid verification code' };
    }

    if (responseStatus === 0) {
      const updated = await safeQuery(
        'UPDATE users SET email_verified = TRUE, verification_token = NULL WHERE id = $1',
        [req.userId]
      );
      if (updated.error) {
        responseStatus = 500;
        responseBody = { error: 'Verification failed' };
      }
    }

    if (responseStatus === 0) {
      responseStatus = 200;
      responseBody = { email_verified: true };
    }
  }

  res.status(responseStatus).json(responseBody);
});

app.post('/auth/resend-verification', requireAuth, async (req: AuthRequest, res) => {
  let responseStatus = 0;
  let responseBody: any = null;

  const result = await safeQuery(
    'SELECT email, email_verified FROM users WHERE id = $1',
    [req.userId]
  );
  if (result.error) {
    responseStatus = 500;
    responseBody = { error: 'Failed to resend verification' };
  }

  if (responseStatus === 0) {
    const user = result.value.rows[0];
    const userNotFound = !user;
    if (userNotFound) {
      responseStatus = 404;
      responseBody = { error: 'User not found' };
    }

    const alreadyVerified = !userNotFound && user.email_verified;
    if (alreadyVerified) {
      responseStatus = 200;
      responseBody = { message: 'Already verified' };
    }

    if (responseStatus === 0) {
      const newCode = generateVerificationCode();
      const updated = await safeQuery(
        'UPDATE users SET verification_token = $1 WHERE id = $2',
        [newCode, req.userId]
      );
      if (updated.error) {
        responseStatus = 500;
        responseBody = { error: 'Failed to resend verification' };
      }

      if (responseStatus === 0) {
        await sendVerificationEmail(user.email, newCode);
        responseStatus = 200;
        responseBody = { message: 'Verification email sent' };
      }
    }
  }

  res.status(responseStatus).json(responseBody);
});

const PATH_SELECT = `SELECT p.id, p.user_id, u.name AS user_name,
  CASE WHEN u.avatar_filename IS NOT NULL THEN '/uploads/' || u.avatar_filename END AS user_avatar_url,
  ST_AsGeoJSON(p.path) AS path,
  ST_Length(p.path::geography) AS distance_meters,
  p.description, p.litter_level,
  to_char(p.started_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as started_at,
  to_char(p.ended_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as ended_at
  FROM paths p LEFT JOIN users u ON p.user_id = u.id`;

function parsePaths(rows: any[]) {
  rows.forEach(r => r.path = JSON.parse(r.path));
  return rows;
}

app.post('/paths', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { coordinates, started_at, ended_at, description, litter_level } = req.body;
    if (!coordinates || !Array.isArray(coordinates) || coordinates.length < 2) {
      return res.status(400).json({ error: 'coordinates array with at least 2 points is required' });
    }
    const geojson = JSON.stringify({ type: 'LineString', coordinates });
    const uid = req.userId!;
    const result = await pool.query(
      `INSERT INTO paths (user_id, path, started_at, ended_at, description, litter_level)
       VALUES ($1, ST_SetSRID(ST_GeomFromGeoJSON($2), 4326), $3, $4, $5, $6)
       RETURNING id, ST_Length(path::geography) AS distance_meters`,
      [uid, geojson, started_at, ended_at, description || null, litter_level || null]
    );
    const row = result.rows[0];
    const durationSeconds = (started_at && ended_at)
      ? (new Date(ended_at).getTime() - new Date(started_at).getTime()) / 1000
      : 0;
    await pool.query(
      `UPDATE users SET
        total_paths = total_paths + 1,
        total_distance_meters = total_distance_meters + $1,
        total_duration_seconds = total_duration_seconds + $2
       WHERE id = $3`,
      [row.distance_meters, durationSeconds, uid]
    );
    res.status(201).json({ id: row.id });
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.get('/paths', async (req, res) => {
  try {
    const result = await pool.query(`${PATH_SELECT} ORDER BY p.started_at DESC LIMIT 50`);
    parsePaths(result.rows);
    const buffer = encodePathList(result.rows);
    res.set('Content-Type', 'application/x-protobuf');
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.get('/paths/:id', async (req, res) => {
  try {
    const result = await pool.query(`${PATH_SELECT} WHERE p.id = $1`, [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Walk not found' });
    parsePaths(result.rows);

    const photos = await pool.query(
      'SELECT id, filename, created_at FROM path_photos WHERE path_id = $1 ORDER BY created_at',
      [req.params.id]
    );
    const row = result.rows[0];
    row.photos = photos.rows.map((p: any) => ({
      id: p.id,
      url: `/uploads/${p.filename}`,
      created_at: p.created_at
    }));

    const buffer = encodePathList([row]);
    res.set('Content-Type', 'application/x-protobuf');
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.delete('/paths/:id', requireAuth, async (req: AuthRequest, res) => {
  try {
    const ownerCheck = await pool.query('SELECT user_id FROM paths WHERE id = $1', [req.params.id]);
    const pathNotFound = ownerCheck.rows.length === 0;
    if (pathNotFound) return res.status(404).json({ error: 'Path not found' });
    const isOwner = ownerCheck.rows[0].user_id === req.userId;
    if (!isOwner) return res.status(403).json({ error: 'Not authorized' });

    await pool.query('DELETE FROM path_photos WHERE path_id = $1', [req.params.id]);
    const result = await pool.query(
      `DELETE FROM paths WHERE id = $1
       RETURNING id, user_id, ST_Length(path::geography) AS distance_meters,
       COALESCE(EXTRACT(EPOCH FROM (ended_at - started_at)), 0)::float AS duration_seconds`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Path not found' });
    const deleted = result.rows[0];
    await pool.query(
      `UPDATE users SET
        total_paths = GREATEST(total_paths - 1, 0),
        total_distance_meters = GREATEST(total_distance_meters - $1, 0),
        total_duration_seconds = GREATEST(total_duration_seconds - $2, 0)
       WHERE id = $3`,
      [deleted.distance_meters, deleted.duration_seconds, deleted.user_id]
    );
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.put('/paths/:id', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { description, litter_level } = req.body;
    const result = await pool.query(
      `UPDATE paths SET
        description = COALESCE($1, description),
        litter_level = COALESCE($2, litter_level)
       WHERE id = $3
       RETURNING id, description, litter_level`,
      [description ?? null, litter_level ?? null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Path not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.post('/paths/:id/photos', requireAuth, upload.array('photos', 10), async (req: AuthRequest, res) => {
  try {
    const files = req.files as Express.Multer.File[];
    if (!files || files.length === 0) return res.status(400).json({ error: 'No files uploaded' });

    const inserted = [];
    for (const file of files) {
      const result = await pool.query(
        'INSERT INTO path_photos (path_id, filename) VALUES ($1, $2) RETURNING id, filename, created_at',
        [req.params.id, file.filename]
      );
      const row = result.rows[0];
      inserted.push({ id: row.id, url: `/uploads/${row.filename}`, created_at: row.created_at });
    }
    res.json(inserted);
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.get('/users/:id', async (req, res) => {
  try {
    const userResult = await pool.query(
      `SELECT id, name,
        CASE WHEN avatar_filename IS NOT NULL THEN '/uploads/' || avatar_filename END AS avatar_url,
        created_at, total_paths, total_distance_meters, total_duration_seconds
       FROM users WHERE id = $1`,
      [req.params.id]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(userResult.rows[0]);
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.put('/users/:id', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { name } = req.body;
    if (typeof name !== 'string') return res.status(400).json({ error: 'name is required' });
    const result = await pool.query('UPDATE users SET name = $1 WHERE id = $2 RETURNING id, name, created_at', [name, req.userId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.post('/users/:id/avatar', requireAuth, upload.single('avatar'), async (req: AuthRequest, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    const result = await pool.query(
      'UPDATE users SET avatar_filename = $1 WHERE id = $2 RETURNING id, name',
      [file.filename, req.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ avatar_url: `/uploads/${file.filename}` });
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.get('/users/:id/paths', async (req, res) => {
  try {
    const result = await pool.query(`${PATH_SELECT} WHERE p.user_id = $1 ORDER BY p.started_at DESC LIMIT 50`, [req.params.id]);
    parsePaths(result.rows);
    const buffer = encodePathList(result.rows);
    res.set('Content-Type', 'application/x-protobuf');
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.post('/markers', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { latitude, longitude, amenity } = req.body;
    const hasRequiredFields = typeof latitude === 'number' && typeof longitude === 'number';
    if (!hasRequiredFields) {
      res.status(400).json({ error: 'latitude and longitude are required numbers' });
      return;
    }
    const amenityValue = typeof amenity === 'number' ? amenity : 1;
    const result = await pool.query(
      `INSERT INTO markers (id, latitude, longitude, amenity)
       VALUES (-nextval('user_marker_id_seq'), $1, $2, $3)
       RETURNING id, latitude, longitude, amenity`,
      [latitude, longitude, amenityValue]
    );
    await pool.query(`UPDATE marker_version SET version = (EXTRACT(EPOCH FROM NOW()))::bigint::text`);
    const buffer = encodeMarkerList(result.rows);
    res.status(201).set('Content-Type', 'application/x-protobuf').send(buffer);
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.get('/markers/version', async (req, res) => {
  try {
    const result = await pool.query('SELECT version FROM marker_version WHERE id = 1');
    const version = result.rows.length > 0 ? result.rows[0].version : '0';
    res.json({ version });
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.get('/markers', async (req, res) => {
  try {
    const south = parseFloat(req.query.south as string);
    const north = parseFloat(req.query.north as string);
    const west = parseFloat(req.query.west as string);
    const east = parseFloat(req.query.east as string);
    const hasAllParams = !isNaN(south) && !isNaN(north) && !isNaN(west) && !isNaN(east);
    if (!hasAllParams) {
      res.status(400).json({ error: 'south, north, west, east query params required' });
      return;
    }
    const result = await pool.query(
      'SELECT id, latitude, longitude, amenity FROM markers WHERE latitude >= $1 AND latitude <= $2 AND longitude >= $3 AND longitude <= $4',
      [south, north, west, east]
    );
    const buffer = encodeMarkerList(result.rows);
    res.set('Content-Type', 'application/x-protobuf');
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ err });
  }
});
