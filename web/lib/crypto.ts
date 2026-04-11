import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

// AES-256-GCM encryption for BYOK API keys
// Uses ENCRYPTION_KEY env var (32-byte hex string) as the master key
// Format: iv(12 bytes hex):authTag(16 bytes hex):ciphertext(hex)

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function getKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY;
  if (!key || key.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be a 64-char hex string (32 bytes). Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }
  return Buffer.from(key, 'hex');
}

export function encrypt(plaintext: string): string {
  const key = getKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  // Format: iv:tag:ciphertext
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

export function decrypt(encryptedText: string): string {
  // Handle legacy plaintext keys (no colons = not encrypted)
  if (!encryptedText.includes(':')) {
    return encryptedText;
  }

  const parts = encryptedText.split(':');
  if (parts.length !== 3) {
    // Not in our format — treat as plaintext (legacy)
    return encryptedText;
  }

  const key = getKey();
  const [ivHex, tagHex, ciphertext] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(tagHex, 'hex');

  if (iv.length !== IV_LENGTH || authTag.length !== TAG_LENGTH) {
    // Malformed — treat as plaintext (legacy)
    return encryptedText;
  }

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
