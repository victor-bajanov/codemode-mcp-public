// Blockwise AES-GCM at-rest format (v2).
//
// A staged file of `byteLen` bytes is split into `n = blockCount(byteLen)`
// plaintext blocks of BLOCK_BYTES (the last one shorter, and a zero-byte file
// is one empty block). Each block is sealed independently with AES-256-GCM:
//
//   nonce_i = ivBase (8 random bytes, stored in the row's `iv`) ‖ BE32(i)
//   aad_i   = BE16(len(handle)) ‖ handle ‖ version ‖ BE32(i) ‖ BE32(n) ‖ BE64(byteLen)
//
// and the R2 object is the concatenation of every `ct_i ‖ tag_i`. Binding the
// position, the block count and the total length into the AAD means a
// reordered, truncated, extended, duplicated or cross-file-spliced object
// fails authentication on the first block that is out of place, so a reader
// can deliver each block as soon as it verifies.

export const ENC_VERSION_V2 = 2;
export const BLOCK_BYTES = 1_048_576;
export const HKDF_INFO_V2 = "codemode/staging/v2";

const GCM_TAG_BYTES = 16;
const IV_BASE_BYTES = 8;
const MAX_INDEX = 0xffff_ffff;
const TEXT_ENCODER = new TextEncoder();

function assertLength(byteLen: number): void {
  if (!Number.isSafeInteger(byteLen) || byteLen < 0) {
    throw new RangeError("block-format: byte length must be a non-negative integer");
  }
}

export function blockCount(byteLen: number): number {
  assertLength(byteLen);
  return Math.max(1, Math.ceil(byteLen / BLOCK_BYTES));
}

export function ciphertextLength(byteLen: number): number {
  return byteLen + blockCount(byteLen) * GCM_TAG_BYTES;
}

/** Plaintext length of block `index` of a `byteLen`-byte file. */
export function blockPlainLength(byteLen: number, index: number): number {
  const n = blockCount(byteLen);
  if (!Number.isInteger(index) || index < 0 || index >= n) {
    throw new RangeError("block-format: block index out of range");
  }
  return index < n - 1 ? BLOCK_BYTES : byteLen - (n - 1) * BLOCK_BYTES;
}

export function blockNonce(ivBase: Uint8Array, index: number): Uint8Array {
  if (ivBase.byteLength !== IV_BASE_BYTES) {
    throw new RangeError("block-format: iv prefix must be 8 bytes");
  }
  if (!Number.isInteger(index) || index < 0 || index > MAX_INDEX) {
    throw new RangeError("block-format: block index out of range");
  }
  const nonce = new Uint8Array(IV_BASE_BYTES + 4);
  nonce.set(ivBase, 0);
  new DataView(nonce.buffer).setUint32(IV_BASE_BYTES, index, false);
  return nonce;
}

export function blockAad(fileHandle: string, index: number, n: number, byteLen: number): Uint8Array {
  assertLength(byteLen);
  const handle = TEXT_ENCODER.encode(fileHandle);
  if (handle.byteLength > 0xffff) throw new RangeError("block-format: handle too long");
  const aad = new Uint8Array(2 + handle.byteLength + 1 + 4 + 4 + 8);
  const view = new DataView(aad.buffer);
  let off = 0;
  view.setUint16(off, handle.byteLength, false);
  off += 2;
  aad.set(handle, off);
  off += handle.byteLength;
  aad[off] = ENC_VERSION_V2;
  off += 1;
  view.setUint32(off, index, false);
  off += 4;
  view.setUint32(off, n, false);
  off += 4;
  view.setBigUint64(off, BigInt(byteLen), false);
  return aad;
}

function checkPosition(index: number, n: number, byteLen: number): number {
  if (n !== blockCount(byteLen)) throw new RangeError("block-format: block count does not match length");
  return blockPlainLength(byteLen, index);
}

export async function encryptBlock(
  key: CryptoKey,
  ivBase: Uint8Array,
  fileHandle: string,
  index: number,
  n: number,
  byteLen: number,
  plain: Uint8Array,
): Promise<Uint8Array> {
  if (plain.byteLength !== checkPosition(index, n, byteLen)) {
    throw new RangeError("block-format: plaintext block has the wrong length for its position");
  }
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: blockNonce(ivBase, index), additionalData: blockAad(fileHandle, index, n, byteLen) },
    key,
    plain,
  );
  return new Uint8Array(ct);
}

export async function decryptBlock(
  key: CryptoKey,
  ivBase: Uint8Array,
  fileHandle: string,
  index: number,
  n: number,
  byteLen: number,
  cipher: Uint8Array,
): Promise<Uint8Array> {
  if (cipher.byteLength !== checkPosition(index, n, byteLen) + GCM_TAG_BYTES) {
    throw new RangeError("block-format: ciphertext block has the wrong length for its position");
  }
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blockNonce(ivBase, index), additionalData: blockAad(fileHandle, index, n, byteLen) },
    key,
    cipher,
  );
  return new Uint8Array(pt);
}
