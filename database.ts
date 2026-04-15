/**
 * SimpleDiscordCrypt - Database Module (SDC 3.4 FINAL)
 * Clean architecture: seed + identity + metadata only
 * Fully compatible with Double Ratchet crypto layer
 */

import { DataStore } from "@api/index";
import {
  generateECDHKeyPair,
  generateSeed,
  deriveChannelKey,
  importPrivateKeyBytes,
  importPublicKeyBytes,
  exportPrivateKeyBytes,
  exportPublicKeyBytes,
  uint8ToBase64 as cryptoUint8ToBase64,
  base64ToUint8 as cryptoBase64ToUint8,
} from "./crypto";

// ─────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────

export type KeyType = "PERSONAL" | "GROUP" | "DM";

export interface StoredKey {
  id: string;
  type: KeyType;
  name: string;
  descriptor: string;
  lastseen: number;
  registered: number;
  
  // Optional fields for different key types
  hidden?: boolean;
  rawKeyB64?: string;  // for GROUP keys (raw AES key)
  sharedKeyB64?: string;  // for DM keys (derived shared secret)
}

export interface PendingHandshake {
  id: string;
  from: string;
  to: string;

  theirPubKeyB64: string;
  myEphemeralPubKeyB64?: string;

  rootSecretB64?: string;

  status: "pending" | "accepted" | "rejected";

  createdAt: number;
  updatedAt: number;
}

export interface ChannelSettings {
  id: string;
  encryptionEnabled: boolean;
  activeKeyId: string | null;
  descriptor: string;
  lastseen: number;
  isSecondary: boolean;
}

// Optional: future-proof ratchet persistence (safe stub)
export interface RatchetSession {
  rootKeyB64: string;
  sendChainKeyB64: string;
  recvChainKeyB64: string;
  sendIndex: number;
  recvIndex: number;
  theirPubKeyB64?: string;
}

export interface SdcDatabase {
  version: number;

  // core security material
  seedB64: string;

  // identity keypair (WebCrypto objects restored at runtime)
  privateKeyB64?: string;
  publicKeyB64?: string;

  // user data
  keys: Record<string, StoredKey>;
  channels: Record<string, ChannelSettings>;

  // (ratchet persistence)
  ratchets?: Record<string, RatchetSession>;
  pendingHandshakes?: Record<string, PendingHandshake>;

  isSecondary?: boolean;
  passwordProtected?: boolean;
  
  // ping pattern for notifications
  pingPattern?: string;
}

// ─────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────

const DB_KEY = "SimpleDiscordCrypt_db";
const DB_STAGING_KEY = DB_KEY + "_staging";
const DB_JOURNAL_KEY = DB_KEY + "_journal";
const DB_VERSION = 3;

// ─────────────────────────────────────────────
// RUNTIME STATE
// ─────────────────────────────────────────────

let _db: SdcDatabase | null = null;
let _dbKey: CryptoKey | null = null;
let _seed: Uint8Array | null = null;
let _identity: CryptoKeyPair | null = null;
let _initPromise: Promise<boolean> | null = null;
let _unlocked = false;

// ─────────────────────────────────────────────
// ATOMIC WRITE QUEUE (NO LOCKS, NO POLLING)
// ─────────────────────────────────────────────

let _writeQueue: Promise<void> = Promise.resolve();

function enqueueWrite(task: () => Promise<void>): Promise<void> {
  // chain every write sequentially
  _writeQueue = _writeQueue.then(() =>
    task().catch(err => {
      console.error("[SDC] queued write failed:", err);
      // DO NOT break queue
    })
  );

  return _writeQueue;
}

async function safeWrite(): Promise<void> {
  return enqueueWrite(async () => {
    await saveDatabase();
  });
}

// ─────────────────────────────────────────────
// BASE64 UTILITIES
// ─────────────────────────────────────────────

function uint8ToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function base64ToUint8(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ─────────────────────────────────────────────
// DB ENCRYPTION UTILITIES
// ─────────────────────────────────────────────

async function deriveDbKey(seed: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    seed,
    "AES-CBC",
    false,
    ["encrypt", "decrypt"]
  );
}

// ─────────────────────────────────────────────
// LOAD / SAVE
// ─────────────────────────────────────────────

export async function loadDatabase(): Promise<SdcDatabase | null> {
  try {
    const raw = await DataStore.get(DB_KEY);
    if (!raw) return null;

    const { iv, data } = raw;

    if (!_dbKey) {
      throw new Error("DB key not initialized before load");
    }

    const ivBytes = base64ToUint8(iv);
    const encrypted = base64ToUint8(data);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: ivBytes },
      _dbKey,
      encrypted
    );

    const json = new TextDecoder().decode(decrypted);

    _db = JSON.parse(json);

    // safety normalization (important for upgrades)
    _db!.version ??= DB_VERSION;
    _db!.keys ??= {};
    _db!.channels ??= {};
    _db!.ratchets ??= {};
    _db!.pendingHandshakes ??= {};

    return _db;

  } catch (e) {
    console.error("[SDC] DB decrypt/load failed", e);
    return null;
  }
}

export async function saveDatabase(): Promise<void> {
  if (!_db || !_dbKey) return;

  try {
    const plaintext = new TextEncoder().encode(JSON.stringify(_db));
    const iv = crypto.getRandomValues(new Uint8Array(16));

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      _dbKey,
      plaintext
    );

    const journalPayload: any = {
      iv: uint8ToBase64(iv),
      data: uint8ToBase64(new Uint8Array(ciphertext)),
      version: _db.version,
      timestamp: Date.now()
    };

    // If not password protected, we MUST store the seed in the root to decrypt next time
    if (!_db.passwordProtected && _db.seedB64) {
      journalPayload.seedB64 = _db.seedB64;
    }

    const mainPayload: any = {
      iv: journalPayload.iv,
      data: journalPayload.data
    };
    
    if (journalPayload.seedB64) {
      mainPayload.seedB64 = journalPayload.seedB64;
    }

    // STEP 1: journal first
    await DataStore.set(DB_JOURNAL_KEY, journalPayload);

    // STEP 2: verify journal integrity
    const journalOk = await DataStore.get(DB_JOURNAL_KEY);
    if (journalOk?.iv && journalOk?.data) {
      await DataStore.set(DB_KEY, mainPayload);
    } else {
      console.warn("[SDC] Journal missing or invalid — skipping main write");
    }

    // STEP 3: clear journal
    await DataStore.set(DB_JOURNAL_KEY, null);

  } catch (e) {
    console.error("[SDC] saveDatabase failed:", e);
  }
}

export async function hasStoredDatabase(): Promise<boolean> {
  const raw = await DataStore.get(DB_KEY);
  return !!(raw?.iv && raw?.data);
}

// ─────────────────────────────────────────────
// INITIALIZATION
// ─────────────────────────────────────────────

async function persistIdentity(identity: CryptoKeyPair) {
  if (!_db) return;

  const priv = await exportPrivateKeyBytes(identity.privateKey);
  const pub = await exportPublicKeyBytes(identity.publicKey);

  _db.privateKeyB64 = uint8ToBase64(priv);
  _db.publicKeyB64 = uint8ToBase64(pub);

  await safeWrite();
}

async function createFreshDatabase(): Promise<SdcDatabase> {
  const seed = await generateSeed();
  const identity = await generateECDHKeyPair();

  _seed = seed;
  _identity = identity;

  const db: SdcDatabase = {
    version: DB_VERSION,
    seedB64: uint8ToBase64(seed),
    keys: {},
    channels: {},
    ratchets: {},
    pendingHandshakes: {},
    passwordProtected: false,
  };

  _db = db;

  await persistIdentity(identity);

  const personalKeyId =
    "personal_" +
    Date.now() +
    "_" +
    Math.random().toString(36).slice(2);

  db.keys[personalKeyId] = {
    id: personalKeyId,
    type: "PERSONAL",
    name: "My Personal Key",
    descriptor: "My Personal Key",
    lastseen: Date.now(),
    registered: Date.now()
  };

  await safeWrite();

  return db;
}

export async function initializeDatabase(password?: string): Promise<boolean> {
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    // ─────────────────────────────────────────────
    // CRASH RECOVERY CHECK
    // ─────────────────────────────────────────────

    const journal = await DataStore.get(DB_JOURNAL_KEY);
    const main = await DataStore.get(DB_KEY);

    if (journal && !main) {
      console.warn("[SDC] Recovering from crash journal");

      // validate journal structure before restore
      if (journal?.iv && journal?.data && _dbKey) {
        try {
          // attempt decrypt BEFORE commit
          const ivBytes = base64ToUint8(journal.iv);
          const encrypted = base64ToUint8(journal.data);

          await crypto.subtle.decrypt(
            { name: "AES-CBC", iv: ivBytes },
            _dbKey,
            encrypted
          );

          await DataStore.set(DB_KEY, {
            iv: journal.iv,
            data: journal.data
          });

        } catch {
          console.warn("[SDC] Corrupt journal ignored");
        }
      }
    }

    // clear journal safely
    await DataStore.set(DB_JOURNAL_KEY, null);

    if (journal && main) {
      // possible partial overwrite → compare timestamps if available
      await DataStore.set(DB_JOURNAL_KEY, null);
    }

    // STEP 1: try load raw DB first
    const raw = await DataStore.get(DB_KEY);

    let db: SdcDatabase | null = null;

    // STEP 2: derive seed + key BEFORE decrypt
    if (raw) {
      // Check if we have a plaintext seedB64 (unencrypted initial state)
      if (raw.seedB64) {
        _seed = base64ToUint8(raw.seedB64);
        _dbKey = await deriveDbKey(_seed);
      }
      
      // If data is encrypted, load it
      if (raw.iv && raw.data) {
        db = await loadDatabase();
      }
    }

    // STEP 3: fallback create
    if (!db) {
      db = await createFreshDatabase();
    }

    _db = db;

    // STEP 4: ensure seed/key exist
    if (!db.seedB64) throw new Error("Missing seed");
    
    _seed = base64ToUint8(db.seedB64);
    _dbKey = await deriveDbKey(_seed);

    // STEP 5: identity restore
    if (db.privateKeyB64 && db.publicKeyB64) {
      try {
        const privBytes = base64ToUint8(db.privateKeyB64);
        const pubBytes = base64ToUint8(db.publicKeyB64);

        const privateKey = await importPrivateKeyBytes(privBytes);
        const publicKey = await importPublicKeyBytes(pubBytes);

        if (!privateKey || !publicKey) throw new Error("Invalid identity restore");

        _identity = { privateKey, publicKey };

      } catch {
        _identity = await generateECDHKeyPair();
        await persistIdentity(_identity);
      }
    } else {
      _identity = await generateECDHKeyPair();
      await persistIdentity(_identity);
    }

    _unlocked = true;
    return true;
  })();

  return _initPromise;
}

// ─────────────────────────────────────────────
// ACCESSORS
// ─────────────────────────────────────────────

export function isUnlocked(): boolean {
  return _unlocked;
}

export function getSeed(): Uint8Array | null {
  return _seed;
}

export function getIdentity(): CryptoKeyPair | null {
  return _identity;
}

export function getIdentityPrivateKey(): CryptoKey | null {
  return _identity?.privateKey ?? null;
}

export function getDatabase(): SdcDatabase | null {
  return _db;
}

// ─────────────────────────────────────────────
// CHANNEL DERIVATION (ROOT KEY INPUT ONLY)
// ─────────────────────────────────────────────

export async function getChannelRootKey(channelId: string): Promise<Uint8Array | null> {
  if (!_seed) return null;
  return deriveChannelKey(_seed, channelId);
}

// ─────────────────────────────────────────────
// CHANNEL SETTINGS
// ─────────────────────────────────────────────

export function getChannel(id: string): ChannelSettings | null {
  return _db?.channels?.[id] ?? null;
}

export async function setChannelEncryption(
  channelId: string,
  enabled: boolean,
  descriptor = channelId
): Promise<ChannelSettings> {

  if (!_db) throw new Error("DB not initialized");

  const existing = _db.channels[channelId];

  const ch: ChannelSettings = existing ?? {
    id: channelId,
    encryptionEnabled: enabled,
    activeKeyId: null,
    descriptor,
    lastseen: Date.now(),
    isSecondary: false
  };

  ch.encryptionEnabled = enabled;
  ch.descriptor = descriptor;
  ch.lastseen = Date.now();

  _db.channels[channelId] = ch;
  await safeWrite();

  return ch;
}

export async function setChannelKey(
  channelId: string,
  keyId: string | null
): Promise<void> {

  if (!_db) return;

  if (!_db.channels[channelId]) {
    _db.channels[channelId] = {
      id: channelId,
      encryptionEnabled: true,
      activeKeyId: keyId,
      descriptor: channelId,
      lastseen: Date.now(),
      isSecondary: false
    };
  } else {
    _db.channels[channelId].activeKeyId = keyId;
    _db.channels[channelId].lastseen = Date.now();
  }

  await safeWrite();
}

export async function touchChannel(channelId: string): Promise<void> {
  if (!_db?.channels?.[channelId]) return;
  
  _db.channels[channelId].lastseen = Date.now();
  await safeWrite();
}

export function getActiveKeyIdForChannel(channelId: string): string | null {
  return _db?.channels?.[channelId]?.activeKeyId ?? null;
}

export function isEncryptionEnabled(channelId: string): boolean {
  return _db?.channels?.[channelId]?.encryptionEnabled ?? false;
}

// ─────────────────────────────────────────────
// GET AES KEY FOR ENCRYPTION/DECRYPTION
// ─────────────────────────────────────────────

export async function getAesKeyForId(keyId: string, channelId?: string): Promise<Uint8Array | null> {
  const key = getKey(keyId);
  if (!key) return null;
  
  // For PERSONAL keys, derive from channelRootKey
  if (key.type === "PERSONAL" && channelId) {
    return getChannelRootKey(channelId);
  }
  
  // For GROUP keys, use rawKeyB64
  if (key.rawKeyB64) {
    return base64ToUint8(key.rawKeyB64);
  }
  
  // For DM keys, use sharedKeyB64
  if (key.sharedKeyB64) {
    return base64ToUint8(key.sharedKeyB64);
  }
  
  return null;
}

// ─────────────────────────────────────────────
// RATCHET STORAGE (OPTIONAL FUTURE USE)
// ─────────────────────────────────────────────

export function getRatchet(channelId: string): RatchetSession | null {
  return _db?.ratchets?.[channelId] ?? null;
}

export async function setRatchet(
  channelId: string,
  state: RatchetSession
): Promise<void> {
  if (!_db) return;

  _db.ratchets ??= {};
  _db.ratchets[channelId] = state;

  await safeWrite();
}

// ─────────────────────────────────────────────
// KEY MANAGEMENT (MINIMAL METADATA ONLY)
// ─────────────────────────────────────────────

export function getHandshake(id: string): PendingHandshake | null {
  return _db?.pendingHandshakes?.[id] ?? null;
}

export async function setHandshake(h: PendingHandshake): Promise<void> {
  if (!_db) return;

  _db.pendingHandshakes ??= {};
  _db.pendingHandshakes[h.id] = h;

  await safeWrite();
}

export async function deleteHandshake(id: string): Promise<void> {
  if (!_db?.pendingHandshakes) return;

  delete _db.pendingHandshakes[id];
  await safeWrite();
}

export function listKeys(includeHidden = true): StoredKey[] {
  if (!_db?.keys) return [];
  const keys = Object.values(_db.keys).filter(Boolean);
  return includeHidden ? keys : keys.filter(k => !k.hidden);
}

export function getKey(id: string): StoredKey | null {
  return _db?.keys?.[id] ?? null;
}

// create minimal metadata key (NO RAW CRYPTO STORAGE)
export async function createKey(name: string, type: KeyType): Promise<StoredKey> {
  if (!_db) throw new Error("DB not initialized");

  const id =
    type.toLowerCase() + "_" + Date.now() + "_" + Math.random().toString(36).slice(2);

  const key: StoredKey = {
    id,
    type,
    name,
    descriptor: name,
    lastseen: Date.now(),
    registered: Date.now()
  };

  _db.keys[id] = key;
  await safeWrite();

  return key;
}

export async function updateKey(id: string, patch: Partial<StoredKey>): Promise<void> {
  if (!_db?.keys[id]) return;

  Object.assign(_db.keys[id], patch);
  await safeWrite();
}

export async function deleteKey(id: string): Promise<void> {
  if (!_db) return;

  delete _db.keys[id];
  await safeWrite();
}

// ─────────────────────────────────────────────
// GROUP KEY GENERATION
// ─────────────────────────────────────────────

export async function addGroupKey(name: string): Promise<StoredKey> {
  if (!_db) throw new Error("DB not initialized");
  
  const id = "group_" + Date.now() + "_" + Math.random().toString(36).slice(2);
  
  // Generate random 32-byte AES key
  const rawKey = new Uint8Array(32);
  crypto.getRandomValues(rawKey);
  
  const key: StoredKey = {
    id,
    type: "GROUP",
    name,
    descriptor: name,
    lastseen: Date.now(),
    registered: Date.now(),
    rawKeyB64: uint8ToBase64(rawKey),
    hidden: false,
  };
  
  _db.keys[id] = key;
  await safeWrite();
  
  return key;
}

// ─────────────────────────────────────────────
// KEY EXCHANGE
// ─────────────────────────────────────────────

export async function startKX(channelId: string): Promise<{ keyId: string; pubKeyB64: string }> {
  if (!_identity) throw new Error("Identity not initialized");
  
  const pubBytes = await exportPublicKeyBytes(_identity.publicKey);
  const pubKeyB64 = uint8ToBase64(pubBytes);
  
  // Create a pending DM key entry
  const keyId = "dm_" + Date.now() + "_" + Math.random().toString(36).slice(2);
  
  return { keyId, pubKeyB64 };
}

export async function getPublicKeyBytes(): Promise<Uint8Array> {
  if (!_identity) throw new Error("Identity not initialized");
  return exportPublicKeyBytes(_identity.publicKey);
}

export async function rotateKey(keyId: string): Promise<void> {
  // Placeholder for future key rotation implementation
  console.warn("[SDC] Key rotation not yet implemented");
}

// ─────────────────────────────────────────────
// DATABASE MANAGEMENT
// ─────────────────────────────────────────────

export async function regenerateMasterSeed(): Promise<void> {
  if (!_db) return;
  
  const newSeed = await generateSeed();
  _seed = newSeed;
  _db.seedB64 = uint8ToBase64(newSeed);
  _dbKey = await deriveDbKey(newSeed);
  
  // All PERSONAL keys derived from the old seed are now effectively "lost" 
  // for new messages, but the entries in db.keys remain.
  // We touch all personal keys to show they've been "rotated"
  for (const k of Object.values(_db.keys)) {
    if (k.type === "PERSONAL") {
      k.lastseen = Date.now();
    }
  }
  
  await safeWrite();
}

export async function clearChannels(): Promise<void> {
  if (!_db) return;
  
  _db.channels = {};
  await safeWrite();
}

export async function clearKeys(): Promise<void> {
  if (!_db) return;
  
  // Keep PERSONAL keys only
  const personal = Object.values(_db.keys).filter(k => k.type === "PERSONAL");
  _db.keys = {};
  
  for (const key of personal) {
    _db.keys[key.id] = key;
  }
  
  await safeWrite();
}

export function setPingPattern(pattern: string): void {
  if (!_db) return;
  _db.pingPattern = pattern;
  safeWrite();
}

export function getPingPattern(): string {
  return _db?.pingPattern ?? "";
}

export function exportDatabaseJson(): string {
  if (!_db) return "{}";
  return JSON.stringify(_db, null, 2);
}

export async function importDatabaseJson(json: string, asSecondary: boolean): Promise<void> {
  const imported: SdcDatabase = JSON.parse(json);
  
  if (asSecondary) {
    imported.isSecondary = true;
  }
  
  _db = imported;
  
  // Restore seed and identity
  if (imported.seedB64) {
    _seed = base64ToUint8(imported.seedB64);
    _dbKey = await deriveDbKey(_seed);
  }
  
  if (imported.privateKeyB64 && imported.publicKeyB64) {
    const privBytes = base64ToUint8(imported.privateKeyB64);
    const pubBytes = base64ToUint8(imported.publicKeyB64);
    
    const privateKey = await importPrivateKeyBytes(privBytes);
    const publicKey = await importPublicKeyBytes(pubBytes);
    
    _identity = { privateKey, publicKey };
  }
  
  await safeWrite();
  _unlocked = true;
}

// ─────────────────────────────────────────────
// LOCK (CLEAR RUNTIME ONLY)
// ─────────────────────────────────────────────

export function lock(): void {
  _seed = null;
  _identity = null;
  _db = null;
  _unlocked = false;
}
