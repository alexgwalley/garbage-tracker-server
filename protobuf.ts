import protobuf from 'protobufjs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const root = protobuf.loadSync(path.join(__dirname, 'proto', 'garbage_tracker.proto'));
const PathList = root.lookupType('garbage_tracker.PathList');
const MarkerList = root.lookupType('garbage_tracker.MarkerList');

export function encodePathList(rows: any[]): Buffer {
    const paths = rows.map(row => {
        const geojson = row.path;
        const coordinates = geojson.coordinates.map((c: number[]) => ({
            longitude: c[0],
            latitude: c[1],
        }));

        const message: Record<string, any> = {
            id: row.id,
            userId: row.user_id,
            userName: row.user_name || '',
            userAvatarUrl: row.user_avatar_url || '',
            coordinates,
            distanceMeters: row.distance_meters || 0,
            description: row.description || '',
            litterLevel: row.litter_level || '',
            startedAt: row.started_at || '',
            endedAt: row.ended_at || '',
        };

        const hasPhotos = row.photos && row.photos.length > 0;
        if (hasPhotos) {
            message.photos = row.photos.map((p: any) => ({
                id: p.id,
                url: p.url,
                createdAt: p.created_at || '',
            }));
        }

        return message;
    });

    const payload = PathList.create({ paths });
    const buffer = Buffer.from(PathList.encode(payload).finish());
    return buffer;
}

export function encodeMarkerList(rows: any[]): Buffer {
    const markers = rows.map(row => ({
        id: row.id,
        latitude: row.latitude,
        longitude: row.longitude,
        amenity: row.amenity,
    }));

    const payload = MarkerList.create({ markers });
    const buffer = Buffer.from(MarkerList.encode(payload).finish());
    return buffer;
}
