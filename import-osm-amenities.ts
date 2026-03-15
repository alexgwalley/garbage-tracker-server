import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const OVERPASS_URL = "https://overpass-api.de/api/interpreter";

const STATE_QUERIES = [
  /*
  {
    name: "Vermont",
    query: `[out:json][timeout:120];
area["name"="Vermont"]["admin_level"="4"]->.a;
(node["amenity"="waste_basket"](area.a);node["amenity"="waste_disposal"](area.a););
out body;`,
  },
  {
    name: "Massachusetts",
    query: `[out:json][timeout:120];
area["name"="Massachusetts"]["admin_level"="4"]->.a;
(node["amenity"="waste_basket"](area.a);node["amenity"="waste_disposal"](area.a););
out body;`,
  },
  */
  {
    name: "New York",
    query: `[out:json][timeout:180];
area["name"="New York"]["admin_level"="4"]->.a;
(node["amenity"="waste_basket"](area.a);node["amenity"="waste_disposal"](area.a););
out body;`,
  },
];

const AMENITY_MAP: Record<string, number> = {
  waste_basket: 1,
  waste_disposal: 2,
};

interface OverpassNode {
  type: string;
  id: number;
  lat: number;
  lon: number;
  tags?: Record<string, string>;
}

interface OverpassResponse {
  elements: OverpassNode[];
}

async function fetchStateData(
  stateName: string,
  query: string
): Promise<{ value: OverpassNode[]; error: string | null }> {
  let value: OverpassNode[] = [];
  let error: string | null = null;

  console.log(`Fetching ${stateName}...`);
  const response = await fetch(OVERPASS_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `data=${encodeURIComponent(query)}`,
  });

  const isOk = response.ok;
  if (!isOk) {
    error = `Overpass API returned ${response.status} for ${stateName}: ${response.statusText}`;
  }

  if (error === null) {
    const json = (await response.json()) as OverpassResponse;
    value = json.elements.filter((el) => el.type === "node");
    console.log(`  ${stateName}: ${value.length} nodes`);
  }

  return { value, error };
}

async function importAmenities() {
  let insertedCount = 0;
  let skippedCount = 0;
  let errorMessage: string | null = null;

  const allNodes: OverpassNode[] = [];
  for (let i = 0; i < STATE_QUERIES.length; i++) {
    if (errorMessage !== null) {
      break;
    }
    const isNotFirstRequest = i > 0;
    if (isNotFirstRequest) {
      console.log("  Waiting 15s (rate limit)...");
      await new Promise((r) => setTimeout(r, 15000));
    }
    const state = STATE_QUERIES[i];
    const fetchResult = await fetchStateData(state.name, state.query);
    if (fetchResult.error !== null) {
      errorMessage = fetchResult.error;
    }
    if (errorMessage === null) {
      allNodes.push(...fetchResult.value);
    }
  }

  console.log(`Total: ${allNodes.length} nodes`);

  if (errorMessage === null) {
    const nodes = allNodes;
    const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

    const BATCH_SIZE = 500;
    let batchIndex = 0;

    while (batchIndex < nodes.length && errorMessage === null) {
      const batchEnd = Math.min(batchIndex + BATCH_SIZE, nodes.length);
      const batch = nodes.slice(batchIndex, batchEnd);

      const values: (number | string)[] = [];
      const placeholders: string[] = [];

      for (let i = 0; i < batch.length; i++) {
        const node = batch[i];
        const amenityTag = node.tags?.amenity ?? "waste_basket";
        const amenityCode = AMENITY_MAP[amenityTag] ?? 1;
        const offset = i * 4;
        placeholders.push(
          `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4})`
        );
        values.push(node.id, node.lat, node.lon, amenityCode);
      }

      const sql = `
        INSERT INTO markers (id, latitude, longitude, amenity)
        VALUES ${placeholders.join(", ")}
        ON CONFLICT (id) DO NOTHING
      `;

      try {
        const result = await pool.query(sql, values);
        const batchInserted = result.rowCount ?? 0;
        const batchSkipped = batch.length - batchInserted;
        insertedCount += batchInserted;
        skippedCount += batchSkipped;
      } catch (err) {
        errorMessage = `DB insert failed: ${err}`;
      }

      batchIndex = batchEnd;
    }

    await pool.end();
  }

  if (errorMessage !== null) {
    console.error(errorMessage);
    process.exit(1);
  }

  console.log(
    `Done. Inserted: ${insertedCount}, Skipped (already existed): ${skippedCount}`
  );
}

importAmenities();
