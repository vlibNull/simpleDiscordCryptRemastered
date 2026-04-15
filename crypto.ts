/**
 * SimpleDiscordCrypt - Crypto Module (SDC 3.4 FINAL FIXED)
 * Double Ratchet + HMAC authentication (CBC-safe)
 */

export const PROTOCOL = Object.freeze({
    BRAILLE_BASE: 0x2800,

    MSG_MAGIC: 0xec,

    AES_KEY_LEN: 32,
    IV_LEN: 16,
    MAC_LEN: 32,

    MIN_ENCRYPTED_LEN: 2 + 16 + 32
} as const);

// ─────────────────────────────────────────────
// BASE64 UTILS
// ─────────────────────────────────────────────

export function uint8ToBase64(bytes: Uint8Array): string {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
}

export function base64ToUint8(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

// ─────────────────────────────────────────────
// BRAILLE
// ─────────────────────────────────────────────

export function bytesToBraille(bytes: Uint8Array): string {
    let out = "";
    for (const b of bytes) {
        out += String.fromCodePoint(PROTOCOL.BRAILLE_BASE + b);
    }
    return out;
}

export function brailleToBytes(text: string): Uint8Array | null {
    const matches = text.match(/[\u2800-\u28FF]+/g);
    if (!matches) return null;

    const s = matches.join("");
    const out = new Uint8Array(s.length);

    for (let i = 0; i < s.length; i++) {
        const val = s.charCodeAt(i) - PROTOCOL.BRAILLE_BASE;
        if (val < 0 || val > 255) return null;
        out[i] = val;
    }

    return out;
}

export function isBrailleMessage(text: string): boolean {
    return /[\u2800-\u28FF]/.test(text);
}

export function isEncryptedMessage(text: string): boolean {
    return typeof text === "string" && text.startsWith(":ENC:");
}

// ─────────────────────────────────────────────
// MESSAGE PARSING
// ─────────────────────────────────────────────

export interface SdcMessage {
    type: "encrypted" | "kx_init" | "kx_response" | "share_keys";
    data: Uint8Array;
    metadata?: any;
}

export function parseSdcMessage(content: string): SdcMessage | null {
    const braille = brailleToBytes(content);
    if (!braille || braille.length < 2) return null;

    const magic = braille[0];
    const type = braille[1];

    if (magic !== PROTOCOL.MSG_MAGIC) return null;

    const payload = braille.slice(2);

    switch (type) {
        case 0x01: // encrypted message
            return { type: "encrypted", data: payload };
        case 0x02: // KX init
            return { type: "kx_init", data: payload };
        case 0x03: // KX response
            return { type: "kx_response", data: payload };
        case 0x04: // share keys
            return { type: "share_keys", data: payload };
        default:
            return null;
    }
}

// ─────────────────────────────────────────────
// KEY EXCHANGE MESSAGE BUILDING
// ─────────────────────────────────────────────

export function buildKxInitMessage(pubKey: Uint8Array): string {
    const msg = new Uint8Array(2 + pubKey.length);
    msg[0] = PROTOCOL.MSG_MAGIC;
    msg[1] = 0x02; // KX init type
    msg.set(pubKey, 2);
    return bytesToBraille(msg);
}

export function buildKxResponseMessage(pubKey: Uint8Array): string {
    const msg = new Uint8Array(2 + pubKey.length);
    msg[0] = PROTOCOL.MSG_MAGIC;
    msg[1] = 0x03; // KX response type
    msg.set(pubKey, 2);
    return bytesToBraille(msg);
}

export function buildEncryptedMessage(ciphertext: Uint8Array): string {
    const msg = new Uint8Array(2 + ciphertext.length);
    msg[0] = PROTOCOL.MSG_MAGIC;
    msg[1] = 0x01; // encrypted message type
    msg.set(ciphertext, 2);
    return bytesToBraille(msg);
}

// ─────────────────────────────────────────────
// KEY FINGERPRINTING
// ─────────────────────────────────────────────

export async function keyFingerprint(keyBytes: Uint8Array): Promise<string> {
    const hash = await crypto.subtle.digest("SHA-256", keyBytes);
    const bytes = new Uint8Array(hash);
    
    // Take first 8 bytes and format as hex pairs
    let result = "";
    for (let i = 0; i < 8; i++) {
        if (i > 0) result += ":";
        result += bytes[i].toString(16).padStart(2, "0").toUpperCase();
    }
    return result;
}

// ─────────────────────────────────────────────
// CRYPTO CORE
// ─────────────────────────────────────────────

const subtle = crypto.subtle;

export async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
    return subtle.generateKey(
        { name: "ECDH", namedCurve: "P-521" },
        true,
        ["deriveBits"]
    );
}

export async function exportPublicKeyBytes(key: CryptoKey): Promise<Uint8Array> {
    return new Uint8Array(await subtle.exportKey("spki", key));
}

export async function exportPrivateKeyBytes(key: CryptoKey): Promise<Uint8Array> {
    return new Uint8Array(await subtle.exportKey("pkcs8", key));
}

export async function importPublicKeyBytes(bytes: Uint8Array): Promise<CryptoKey> {
    return subtle.importKey(
        "spki",
        bytes,
        { name: "ECDH", namedCurve: "P-521" },
        true,
        []
    );
}

export async function importPrivateKeyBytes(bytes: Uint8Array): Promise<CryptoKey> {
    return subtle.importKey(
        "pkcs8",
        bytes,
        { name: "ECDH", namedCurve: "P-521" },
        true,
        ["deriveBits"]
    );
}

export async function deriveSharedSecret(
    priv: CryptoKey,
    pub: CryptoKey
): Promise<Uint8Array> {
    const bits = await subtle.deriveBits(
        { name: "ECDH", public: pub },
        priv,
        521
    );
    return new Uint8Array(bits);
}

// ─────────────────────────────────────────────
// HKDF
// ─────────────────────────────────────────────

async function hkdf(
    input: Uint8Array,
    info: string,
    len: number
): Promise<Uint8Array> {
    const key = await subtle.importKey("raw", input, "HKDF", false, ["deriveBits"]);

    const bits = await subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(32),
            info: new TextEncoder().encode(info)
        },
        key,
        len * 8
    );

    return new Uint8Array(bits);
}

// ─────────────────────────────────────────────
// RATCHET STATE (SERIALIZABLE)
// ─────────────────────────────────────────────

export interface RatchetState {
    rootKeyB64: string;

    sendChainKeyB64: string;
    recvChainKeyB64: string;

    dhPrivKeyB64: string;
    dhPubKeyB64: string;

    theirPubKeyB64?: string;

    sendCount: number;
    recvCount: number;
}

// ─────────────────────────────────────────────
// INTERNAL HELPERS
// ─────────────────────────────────────────────

async function kdfChain(chainKey: Uint8Array) {
    const next = await hkdf(chainKey, "chain", 32);
    const msgKey = await hkdf(chainKey, "msg", 32);
    const macKey = await hkdf(chainKey, "mac", 32);
    return { next, msgKey, macKey };
}

async function importAes(key: Uint8Array): Promise<CryptoKey> {
    return subtle.importKey("raw", key, "AES-CBC", false, ["encrypt", "decrypt"]);
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const k = await subtle.importKey(
        "raw",
        key,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    return new Uint8Array(await subtle.sign("HMAC", k, data));
}

function constantEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let res = 0;
    for (let i = 0; i < a.length; i++) res |= a[i] ^ b[i];
    return res === 0;
}

// ─────────────────────────────────────────────
// SIMPLE AES ENCRYPT/DECRYPT (for group keys)
// ─────────────────────────────────────────────

export async function encryptMessage(
    plaintext: string | Uint8Array,
    aesKey: Uint8Array
): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(PROTOCOL.IV_LEN));
    const key = await importAes(aesKey);

    const data = typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
    const ct = new Uint8Array(
        await subtle.encrypt({ name: "AES-CBC", iv }, key, data)
    );

    const payload = new Uint8Array(iv.length + ct.length);
    payload.set(iv, 0);
    payload.set(ct, iv.length);

    const mac = await hmac(aesKey, payload);

    const out = new Uint8Array(payload.length + mac.length);
    out.set(payload, 0);
    out.set(mac, payload.length);

    return buildEncryptedMessage(out);
}

export async function decryptMessage(
    brailleText: string,
    aesKey: Uint8Array,
    asUint8Array = false
): Promise<any> {
    const parsed = parseSdcMessage(brailleText);
    if (!parsed || parsed.type !== "encrypted") return null;

    const data = parsed.data;
    
    if (data.length < PROTOCOL.MIN_ENCRYPTED_LEN) return null;

    const macStart = data.length - PROTOCOL.MAC_LEN;

    const payload = data.slice(0, macStart);
    const mac = data.slice(macStart);

    const expected = await hmac(aesKey, payload);
    if (!constantEqual(mac, expected)) return null;

    const iv = payload.slice(0, PROTOCOL.IV_LEN);
    const ct = payload.slice(PROTOCOL.IV_LEN);

    try {
        const key = await importAes(aesKey);
        const pt = await subtle.decrypt({ name: "AES-CBC", iv }, key, ct);
        const ptBytes = new Uint8Array(pt);
        return asUint8Array ? ptBytes : new TextDecoder().decode(ptBytes);
    } catch {
        return null;
    }
}

// ─────────────────────────────────────────────
// RATCHET INIT
// ─────────────────────────────────────────────

export async function initializeRatchet(
    sharedSecret: Uint8Array,
    myKeyPair: CryptoKeyPair,
    theirPubKey: CryptoKey
): Promise<RatchetState> {

    const root = await hkdf(sharedSecret, "root", 32);

    const sendChain = await hkdf(root, "send", 32);
    const recvChain = await hkdf(root, "recv", 32);

    return {
        rootKeyB64: uint8ToBase64(root),

        sendChainKeyB64: uint8ToBase64(sendChain),
        recvChainKeyB64: uint8ToBase64(recvChain),

        dhPrivKeyB64: uint8ToBase64(
            await exportPrivateKeyBytes(myKeyPair.privateKey)
        ),
        dhPubKeyB64: uint8ToBase64(
            await exportPublicKeyBytes(myKeyPair.publicKey)
        ),

        theirPubKeyB64: uint8ToBase64(
            await exportPublicKeyBytes(theirPubKey)
        ),

        sendCount: 0,
        recvCount: 0
    };
}

// ─────────────────────────────────────────────
// RATCHET SEND
// ─────────────────────────────────────────────

export async function ratchetEncrypt(
    state: RatchetState,
    plaintext: string
) {

    const sendChain = base64ToUint8(state.sendChainKeyB64);

    const { next, msgKey, macKey } = await kdfChain(sendChain);

    state.sendChainKeyB64 = uint8ToBase64(next);

    const iv = crypto.getRandomValues(new Uint8Array(PROTOCOL.IV_LEN));
    const aes = await importAes(msgKey);

    const data = new TextEncoder().encode(plaintext);
    const ct = new Uint8Array(
        await subtle.encrypt({ name: "AES-CBC", iv }, aes, data)
    );

    const payload = new Uint8Array(iv.length + ct.length);
    payload.set(iv, 0);
    payload.set(ct, iv.length);

    const mac = await hmac(macKey, payload);

    const ciphertext = new Uint8Array(payload.length + mac.length);
    ciphertext.set(payload, 0);
    ciphertext.set(mac, payload.length);

    const header = {
        pub: state.dhPubKeyB64,
        index: state.sendCount++
    };

    return { state, header, ciphertext };
}

// ─────────────────────────────────────────────
// RATCHET RECEIVE
// ─────────────────────────────────────────────

export async function ratchetDecrypt(
    state: RatchetState,
    header: any,
    ciphertext: Uint8Array
): Promise<{ state: RatchetState; plaintext: string | null }> {

    let recvChain = base64ToUint8(state.recvChainKeyB64);

    while (state.recvCount < header.index) {
        const { next } = await kdfChain(recvChain);
        recvChain = next;
        state.recvCount++;
    }

    const { next, msgKey, macKey } = await kdfChain(recvChain);

    state.recvChainKeyB64 = uint8ToBase64(next);
    state.recvCount++;

    // Decrypt with MAC verification
    const macStart = ciphertext.length - PROTOCOL.MAC_LEN;
    const payload = ciphertext.slice(0, macStart);
    const mac = ciphertext.slice(macStart);

    const expected = await hmac(macKey, payload);
    if (!constantEqual(mac, expected)) return { state, plaintext: null };

    const iv = payload.slice(0, PROTOCOL.IV_LEN);
    const ct = payload.slice(PROTOCOL.IV_LEN);

    try {
        const aes = await importAes(msgKey);
        const pt = await subtle.decrypt({ name: "AES-CBC", iv }, aes, ct);
        return { state, plaintext: new TextDecoder().decode(pt) };
    } catch {
        return { state, plaintext: null };
    }
}

// ─────────────────────────────────────────────
// SEED + CHANNEL
// ─────────────────────────────────────────────

export async function generateSeed(): Promise<Uint8Array> {
    const s = new Uint8Array(32);
    crypto.getRandomValues(s);
    return s;
}

export async function deriveChannelKey(
    seed: Uint8Array,
    label: string
): Promise<Uint8Array> {
    return hkdf(seed, "SDC3.4::" + label, 32);
}
