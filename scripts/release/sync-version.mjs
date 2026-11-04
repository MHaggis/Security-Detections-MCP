import { writeFileSync } from 'node:fs';
import { readMetadata, verifyRelease } from './verify-release.mjs';
const metadata = readMetadata();
metadata.server.version = metadata.pkg.version;
metadata.server.packages[0].version = metadata.pkg.version;
verifyRelease(metadata);
writeFileSync('server.json', JSON.stringify(metadata.server, null, 2) + '\n');
