import assert from "node:assert/strict";
import test from "node:test";
import {
  decryptText,
  encryptText,
  MAX_ENVELOPE_LENGTH,
  MAX_PASSPHRASE_BYTES,
  MAX_TEXT_BYTES,
} from "../src/crypto.mjs";

const passphrase = " classroom test 密钥 ";

// Generated independently with Node's pbkdf2Sync and createCipheriv.
const fixture = "CE1.AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRob."
  + "gIQ4IZMBbQV4F874KjzOaOboPpT5cnNmT6BO7kY96_W5F5uF";

test("Unicode text round trips, including a leading BOM and line breaks", async () => {
  const plaintext = "\uFEFF给明天的自己 📬\n保留换行和末尾空格。 ";
  const envelope = await encryptText(plaintext, passphrase);
  assert.equal(await decryptText(`  ${envelope}\r\n`, passphrase), plaintext);
});

test("CE1 decodes an independent fixed test vector", async () => {
  assert.equal(await decryptText(fixture, "classroom fixture"), "密文信封 fixture");
});

test("each encryption generates a fresh salt and IV", async () => {
  const [first, second] = await Promise.all([
    encryptText("same message", passphrase),
    encryptText("same message", passphrase),
  ]);
  assert.match(first, /^CE1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
  const [, firstSalt, firstIv, firstCiphertext] = first.split(".");
  const [, secondSalt, secondIv, secondCiphertext] = second.split(".");
  assert.notEqual(firstSalt, secondSalt);
  assert.notEqual(firstIv, secondIv);
  assert.notEqual(firstCiphertext, secondCiphertext);
});

test("wrong passphrase or modification to any authenticated field fails", async () => {
  const envelope = await encryptText("authenticate this", passphrase);
  await assert.rejects(decryptText(envelope, passphrase.trim()), /口令错误或密文已被篡改/);

  const fields = envelope.split(".");
  for (const [fieldIndex, byteIndex] of [[1, 0], [2, 0], [3, 0], [3, -1]]) {
    const modified = fields.slice();
    const bytes = Buffer.from(modified[fieldIndex], "base64url");
    bytes[byteIndex < 0 ? bytes.length - 1 : byteIndex] ^= 1;
    modified[fieldIndex] = bytes.toString("base64url");
    await assert.rejects(decryptText(modified.join("."), passphrase), /口令错误或密文已被篡改/);
  }
});

test("malformed, unsupported, and non-canonical envelopes are rejected", async () => {
  const [version, salt, iv, ciphertext] = fixture.split(".");
  await assert.rejects(decryptText("", passphrase), /请输入密文信封/);
  await assert.rejects(decryptText(fixture + ".", passphrase), /格式不正确/);
  await assert.rejects(decryptText(fixture.replace("CE1", "CE2"), passphrase), /不支持.*版本/);
  await assert.rejects(decryptText(fixture.replace(salt, salt + "="), passphrase), /Base64url/);
  await assert.rejects(decryptText(fixture.replace(salt, salt.slice(0, -1) + "x"), passphrase), /Base64url/);
  await assert.rejects(decryptText(fixture.replace(iv, "AAAA"), passphrase), /字段长度/);
  const tagOnly = Buffer.alloc(16).toString("base64url");
  await assert.rejects(decryptText([version, salt, iv, tagOnly].join("."), passphrase), /字段长度/);
  await assert.rejects(decryptText(fixture.replace(ciphertext, "A".repeat(MAX_ENVELOPE_LENGTH)), passphrase), /超出长度/);
});

test("limits use UTF-8 byte counts and allow the full advertised size", async () => {
  const plaintext = "密".repeat(Math.floor(MAX_TEXT_BYTES / 3)) + "x";
  const maxPassphrase = "🗝".repeat(MAX_PASSPHRASE_BYTES / 4);
  const envelope = await encryptText(plaintext, maxPassphrase);
  assert.equal(envelope.length, MAX_ENVELOPE_LENGTH);
  assert.equal(await decryptText(envelope, maxPassphrase), plaintext);
  await assert.rejects(encryptText(plaintext + "x", passphrase), /明文最多 65536/);
  await assert.rejects(encryptText("message", maxPassphrase + "x"), /口令最多 1024/);
  await assert.rejects(decryptText(envelope, maxPassphrase + "x"), /口令最多 1024/);
  await assert.rejects(encryptText("", passphrase), /请输入明文/);
  await assert.rejects(encryptText("message", ""), /请输入口令/);
  await assert.rejects(encryptText("\uD800", passphrase), /无效的 Unicode/);
});
