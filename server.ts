import 'dotenv/config';
import express from 'express'
import pg from 'pg';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { encodePathList, encodeMarkerList } from './protobuf.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
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

app.get('/', (req, res) => {
  res.send('Hello There! The server is running.');
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
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

app.post('/paths', async (req, res) => {
  try {
    const { user_id, coordinates, started_at, ended_at, description, litter_level } = req.body;
    if (!coordinates || !Array.isArray(coordinates) || coordinates.length < 2) {
      return res.status(400).json({ error: 'coordinates array with at least 2 points is required' });
    }
    const geojson = JSON.stringify({ type: 'LineString', coordinates });
    const uid = user_id || 1;
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

app.delete('/paths/:id', async (req, res) => {
  try {
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

app.put('/paths/:id', async (req, res) => {
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

app.post('/paths/:id/photos', upload.array('photos', 10), async (req, res) => {
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

app.put('/users/:id', async (req, res) => {
  try {
    const { name } = req.body;
    if (typeof name !== 'string') return res.status(400).json({ error: 'name is required' });
    const result = await pool.query('UPDATE users SET name = $1 WHERE id = $2 RETURNING id, name, created_at', [name, req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ err });
  }
});

app.post('/users/:id/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    const result = await pool.query(
      'UPDATE users SET avatar_filename = $1 WHERE id = $2 RETURNING id, name',
      [file.filename, req.params.id]
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

app.post('/markers', async (req, res) => {
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
