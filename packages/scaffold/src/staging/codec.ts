// Block-aligned base64 codec for file-sized data.
//
// The encoder is fed one plaintext block at a time and must produce exactly
// the same text as a one-shot encoding of the whole file: 1 MiB ≡ 1 (mod 3),
// so naive per-block encoding would put `=` padding mid-stream. It carries a
// 0–56-byte remainder between pushes and only ever encodes whole units —
// 3 bytes in `plain` mode, 57 bytes (one 76-char line) in `lines` mode — then
// pads once, in `finish`. `lines` mode is RFC 2045 body text: CRLF after every
// line, including the last.
//
// The decoder is strict (alphabet, padding position, length) and writes
// straight into a caller-owned destination, so a 50 MiB attachment string is
// decoded block by block without ever materialising the whole plaintext.
//
// Native `Uint8Array.prototype.toBase64` / `setFromBase64` (present in workerd
// and recent Node) are used when available; the pure-JS paths are the
// reference and the fallback.

export type Base64Mode = "plain" | "lines";
export type Base64Alphabet = "std" | "url";
export interface CodecOptions {
  /** Test seam: ignore the native codec even when the platform has it. */
  forceJs?: boolean;
}

interface NativeBase64Proto {
  toBase64?: (this: Uint8Array, opts?: { alphabet?: "base64" | "base64url"; omitPadding?: boolean }) => string;
  setFromBase64?: (
    this: Uint8Array,
    s: string,
    opts?: { alphabet?: "base64" | "base64url"; lastChunkHandling?: "loose" | "strict" | "stop-before-partial" },
  ) => { read: number; written: number };
}

const PROTO = Uint8Array.prototype as unknown as NativeBase64Proto;
const HAS_NATIVE_ENCODE = typeof PROTO.toBase64 === "function";
const HAS_NATIVE_DECODE = typeof PROTO.setFromBase64 === "function";

const STD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const ENC_STD = new Uint8Array(64);
for (let i = 0; i < 64; i++) ENC_STD[i] = STD_CHARS.charCodeAt(i);

function decodeTable(chars: string): Int8Array {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < 64; i++) t[chars.charCodeAt(i)] = i;
  return t;
}
const DEC_STD = decodeTable(STD_CHARS);
const DEC_URL = decodeTable(URL_CHARS);

const LINE_BYTES = 57; // 57 bytes → 76 base64 chars
const LINE_CHARS = 76;
const PAD = 0x3d; // "="
const TEXT_ENCODER = new TextEncoder();

export function base64Length(byteLen: number, mode: Base64Mode): number {
  if (!Number.isSafeInteger(byteLen) || byteLen < 0) throw new RangeError("base64Length: bad length");
  if (mode === "plain") return Math.ceil(byteLen / 3) * 4;
  const full = Math.floor(byteLen / LINE_BYTES);
  const rest = byteLen - full * LINE_BYTES;
  return full * (LINE_CHARS + 2) + (rest > 0 ? Math.ceil(rest / 3) * 4 + 2 : 0);
}

/** Plain base64 of `src` (any length; padded) into `out` at `pos` via the JS table. */
function encodeJsInto(src: Uint8Array, out: Uint8Array, pos: number): number {
  const n = src.byteLength;
  const whole = n - (n % 3);
  let o = pos;
  for (let i = 0; i < whole; i += 3) {
    const v = (src[i]! << 16) | (src[i + 1]! << 8) | src[i + 2]!;
    out[o++] = ENC_STD[v >>> 18]!;
    out[o++] = ENC_STD[(v >>> 12) & 63]!;
    out[o++] = ENC_STD[(v >>> 6) & 63]!;
    out[o++] = ENC_STD[v & 63]!;
  }
  const rest = n - whole;
  if (rest === 1) {
    const v = src[whole]! << 16;
    out[o++] = ENC_STD[v >>> 18]!;
    out[o++] = ENC_STD[(v >>> 12) & 63]!;
    out[o++] = PAD;
    out[o++] = PAD;
  } else if (rest === 2) {
    const v = (src[whole]! << 16) | (src[whole + 1]! << 8);
    out[o++] = ENC_STD[v >>> 18]!;
    out[o++] = ENC_STD[(v >>> 12) & 63]!;
    out[o++] = ENC_STD[(v >>> 6) & 63]!;
    out[o++] = PAD;
  }
  return o - pos;
}

function encodePlainInto(src: Uint8Array, out: Uint8Array, pos: number, native: boolean): number {
  if (native) {
    const s = PROTO.toBase64!.call(src);
    return TEXT_ENCODER.encodeInto(s, out.subarray(pos)).written;
  }
  return encodeJsInto(src, out, pos);
}

export class Base64Encoder {
  private readonly mode: Base64Mode;
  private readonly unit: number;
  private readonly native: boolean;
  private readonly rem = new Uint8Array(LINE_BYTES);
  private remLen = 0;
  // Reused scratch for `lines` mode (plain text before CRLF insertion).
  private scratch: Uint8Array | null = null;
  private finished = false;

  constructor(mode: Base64Mode, alphabet: "std" = "std", opts: CodecOptions = {}) {
    if (alphabet !== "std") throw new RangeError("Base64Encoder: only the std alphabet is supported");
    this.mode = mode;
    this.unit = mode === "plain" ? 3 : LINE_BYTES;
    this.native = HAS_NATIVE_ENCODE && !opts.forceJs;
  }

  /**
   * Encode as many whole units of `rem ‖ bytes` as possible and emit them as
   * one fresh ASCII chunk (the callee may keep it: sinks enqueue by reference).
   */
  async push(bytes: Uint8Array, emit: (ascii: Uint8Array) => Promise<void>): Promise<void> {
    if (this.finished) throw new Error("Base64Encoder: push after finish");
    let src = bytes;
    const total = this.remLen + src.byteLength;
    if (total < this.unit) {
      this.rem.set(src, this.remLen);
      this.remLen = total;
      return;
    }
    const units = Math.floor(total / this.unit);
    const out = new Uint8Array(this.encodedSize(units * this.unit));
    let pos = 0;
    if (this.remLen > 0) {
      const take = this.unit - this.remLen;
      this.rem.set(src.subarray(0, take), this.remLen);
      pos += this.encodeUnits(this.rem.subarray(0, this.unit), out, pos);
      src = src.subarray(take);
      this.remLen = 0;
    }
    const aligned = src.byteLength - (src.byteLength % this.unit);
    if (aligned > 0) pos += this.encodeUnits(src.subarray(0, aligned), out, pos);
    const tail = src.subarray(aligned);
    this.rem.set(tail, 0);
    this.remLen = tail.byteLength;
    if (pos !== out.byteLength) throw new Error("Base64Encoder: internal length mismatch");
    await emit(out);
  }

  async finish(emit: (ascii: Uint8Array) => Promise<void>): Promise<void> {
    if (this.finished) return;
    this.finished = true;
    if (this.remLen === 0) return;
    const src = this.rem.subarray(0, this.remLen);
    const out = new Uint8Array(base64Length(this.remLen, this.mode));
    const w = encodePlainInto(src, out, 0, this.native);
    if (this.mode === "lines") {
      out[w] = 13;
      out[w + 1] = 10;
    }
    this.remLen = 0;
    await emit(out);
  }

  private encodedSize(alignedBytes: number): number {
    return this.mode === "plain"
      ? (alignedBytes / 3) * 4
      : (alignedBytes / LINE_BYTES) * (LINE_CHARS + 2);
  }

  /** Encode `src` (a whole number of units) into `out` at `pos`; returns bytes written. */
  private encodeUnits(src: Uint8Array, out: Uint8Array, pos: number): number {
    if (this.mode === "plain") return encodePlainInto(src, out, pos, this.native);
    const plainLen = (src.byteLength / 3) * 4;
    if (!this.scratch || this.scratch.byteLength < plainLen) this.scratch = new Uint8Array(plainLen);
    encodePlainInto(src, this.scratch, 0, this.native);
    let o = pos;
    for (let i = 0; i < plainLen; i += LINE_CHARS) {
      out.set(this.scratch.subarray(i, i + LINE_CHARS), o);
      o += LINE_CHARS;
      out[o++] = 13;
      out[o++] = 10;
    }
    return o - pos;
  }
}

function invalid(): never {
  // Never echo the input: it may be a file body.
  throw new Error("invalid base64");
}

function padCount(src: string, start: number, end: number): number {
  const len = end - start;
  let pads = 0;
  while (pads < len && src.charCodeAt(end - 1 - pads) === PAD) pads++;
  if (pads === 0) return 0;
  if (pads > 2 || len % 4 !== 0) invalid();
  return pads;
}

export function decodedLength(src: string, start: number, end: number, _alphabet: Base64Alphabet): number {
  if (!(start >= 0 && end >= start && end <= src.length)) throw new RangeError("decodedLength: bad range");
  const len = end - start;
  const pads = padCount(src, start, end);
  const chars = len - pads;
  if (chars % 4 === 1) invalid();
  return Math.floor((chars * 3) / 4);
}

/**
 * Decode `src[start, end)` into `dst` at `dstOffset`; returns bytes written.
 * Strict: no whitespace, `=` only as final padding, alphabet enforced,
 * length ≢ 1 (mod 4). Throws a generic error (never echoing input) on bad data.
 */
export function decodeBase64Into(
  src: string,
  start: number,
  end: number,
  dst: Uint8Array,
  dstOffset: number,
  alphabet: Base64Alphabet,
  opts: CodecOptions = {},
): number {
  const expected = decodedLength(src, start, end, alphabet);
  if (dstOffset < 0 || dstOffset + expected > dst.byteLength) throw new RangeError("decodeBase64Into: destination too small");
  if (expected === 0) return 0;
  if (HAS_NATIVE_DECODE && !opts.forceJs) {
    const target = dst.subarray(dstOffset, dstOffset + expected);
    let r: { read: number; written: number };
    try {
      r = PROTO.setFromBase64!.call(target, src.substring(start, end), {
        alphabet: alphabet === "url" ? "base64url" : "base64",
        lastChunkHandling: "loose",
      });
    } catch {
      invalid();
    }
    // The native decoder skips ASCII whitespace; any skipped character shows
    // up as fewer bytes written than the character count implies.
    if (r.read !== end - start || r.written !== expected) invalid();
    return expected;
  }
  const table = alphabet === "url" ? DEC_URL : DEC_STD;
  const chars = end - start - padCount(src, start, end);
  const whole = chars - (chars % 4);
  let o = dstOffset;
  const lookup = (i: number): number => {
    const c = src.charCodeAt(i);
    const v = c < 128 ? table[c]! : -1;
    if (v < 0) invalid();
    return v;
  };
  for (let i = start; i < start + whole; i += 4) {
    const v = (lookup(i) << 18) | (lookup(i + 1) << 12) | (lookup(i + 2) << 6) | lookup(i + 3);
    dst[o++] = v >>> 16;
    dst[o++] = (v >>> 8) & 0xff;
    dst[o++] = v & 0xff;
  }
  const rest = chars - whole;
  const i = start + whole;
  if (rest === 2) {
    dst[o++] = ((lookup(i) << 2) | (lookup(i + 1) >>> 4)) & 0xff;
  } else if (rest === 3) {
    const v = (lookup(i) << 12) | (lookup(i + 1) << 6) | lookup(i + 2);
    dst[o++] = (v >>> 10) & 0xff;
    dst[o++] = (v >>> 2) & 0xff;
  }
  return o - dstOffset;
}
