const VERSION = "CE1";
const PBKDF2_ITERATIONS = 600_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export const MAX_TEXT_BYTES = 64 * 1024;
export const MAX_PASSPHRASE_BYTES = 1024;
export const MAX_ENVELOPE_LENGTH = VERSION.length + 3
  + Math.ceil(SALT_BYTES * 4 / 3) + Math.ceil(IV_BYTES * 4 / 3)
  + Math.ceil((MAX_TEXT_BYTES + TAG_BYTES) * 4 / 3);

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const versionBytes = encoder.encode(VERSION);

function getWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("浏览器未启用 Web Crypto。请通过 localhost 或 HTTPS 打开本工具。");
  }
  return globalThis.crypto;
}

function encodeText(text, label, maxBytes) {
  if (typeof text !== "string" || text.length === 0) {
    throw new Error(`请输入${label}。`);
  }
  if (text.length > maxBytes) {
    throw new Error(`${label}最多 ${maxBytes} 个 UTF-8 字节。`);
  }
  const bytes = encoder.encode(text);
  if (bytes.length > maxBytes) {
    throw new Error(`${label}最多 ${maxBytes} 个 UTF-8 字节。`);
  }
  if (decoder.decode(bytes) !== text) {
    throw new Error(`${label}包含无效的 Unicode 字符。`);
  }
  return bytes;
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decodeBase64Url(value) {
  if (!value || /[^A-Za-z0-9_-]/.test(value) || value.length % 4 === 1) {
    throw new Error("信封包含无效的 Base64url 字段。");
  }
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) {
    throw new Error("信封包含无效的 Base64url 字段。");
  }
  return bytes;
}

function parseEnvelope(envelope) {
  const value = typeof envelope === "string" ? envelope.trim() : "";
  if (!value) {
    throw new Error("请输入密文信封。");
  }
  if (value.length > MAX_ENVELOPE_LENGTH) {
    throw new Error("密文信封超出长度限制。");
  }
  const parts = value.split(".");
  if (parts.length !== 4) {
    throw new Error("密文信封格式不正确。");
  }
  const [version, encodedSalt, encodedIv, encodedCiphertext] = parts;
  if (version !== VERSION) {
    throw new Error("不支持此密文信封版本。");
  }
  const salt = decodeBase64Url(encodedSalt);
  const iv = decodeBase64Url(encodedIv);
  const ciphertext = decodeBase64Url(encodedCiphertext);
  if (salt.length !== SALT_BYTES || iv.length !== IV_BYTES
      || ciphertext.length <= TAG_BYTES || ciphertext.length > MAX_TEXT_BYTES + TAG_BYTES) {
    throw new Error("密文信封字段长度不正确。");
  }
  return { salt, iv, ciphertext };
}

async function deriveKey(subtle, passphrase, salt, usage) {
  const keyMaterial = await subtle.importKey("raw", passphrase, "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

function gcmParams(iv) {
  return { name: "AES-GCM", iv, additionalData: versionBytes, tagLength: TAG_BYTES * 8 };
}

export async function encryptText(plaintext, passphrase) {
  const bytes = encodeText(plaintext, "明文", MAX_TEXT_BYTES);
  const passphraseBytes = encodeText(passphrase, "口令", MAX_PASSPHRASE_BYTES);
  const webCrypto = getWebCrypto();
  const salt = webCrypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = webCrypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(webCrypto.subtle, passphraseBytes, salt, "encrypt");
  const ciphertext = await webCrypto.subtle.encrypt(gcmParams(iv), key, bytes);
  return [VERSION, encodeBase64Url(salt), encodeBase64Url(iv),
    encodeBase64Url(new Uint8Array(ciphertext))].join(".");
}

export async function decryptText(envelope, passphrase) {
  const { salt, iv, ciphertext } = parseEnvelope(envelope);
  const passphraseBytes = encodeText(passphrase, "口令", MAX_PASSPHRASE_BYTES);
  const { subtle } = getWebCrypto();
  const key = await deriveKey(subtle, passphraseBytes, salt, "decrypt");
  let plaintext;
  try {
    plaintext = await subtle.decrypt(gcmParams(iv), key, ciphertext);
  } catch {
    throw new Error("解密失败，口令错误或密文已被篡改。");
  }
  try {
    return decoder.decode(plaintext);
  } catch {
    throw new Error("解密结果不是有效的 UTF-8 文本。");
  }
}
