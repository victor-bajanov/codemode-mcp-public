// Exact length, inspection view, staged multipart compilation, and the
// block-by-block writer for host-assembled bodies (plan B3, D4–D6).
//
// The writer is the only place staged plaintext meets the outbound body: it
// pulls authenticated blocks from each opened file, encodes them per segment
// (base64 with a carried remainder, or identity), and writes them into a
// fixed-length sink that `fetch` consumes. Nothing here holds more than one
// block (plus one encoded chunk) at a time.

import { Base64Encoder, base64Length } from "../staging/codec";
import type { FixedLengthSink } from "../staging/sinks";
import type { OpenStagedFile, StagedFileMeta, StagedRef } from "../staging/staged-file";
import type { InspectStaged } from "@local/shared";
import { STAGED_SENTINEL, type Segment } from "./validate";

/** Largest chunk handed to the sink for text segments. Encoded staged
 *  chunks are bounded by the block size: 1 MiB → ≤ 1.44 MiB in base64-lines. */
const TEXT_CHUNK_BYTES = 1024 * 1024;
const FILENAME_MAX_CODE_POINTS = 255;
const TEXT_ENCODER = new TextEncoder();

/** A multipart part as the compiler sees it: the scaffold's `MultipartPart`
 *  plus the optional staged reference (validated at handler entry). */
export interface ComposeMultipartPart {
  name: string;
  filename?: string;
  contentType?: string;
  value?: string;
  bodyBase64?: string;
  staged?: StagedRef;
}

function stagedMetas(segments: readonly Segment[], metas: readonly StagedFileMeta[]): StagedFileMeta[] {
  const n = segments.filter((s) => s.kind === "staged").length;
  if (metas.length !== n) throw new Error(`compose: ${n} staged segment(s) but ${metas.length} file(s)`);
  return [...metas];
}

/** Exact byte length of the assembled body. `metas[k]` describes the k-th
 *  staged segment (in segment order). */
export function assembledLength(segments: readonly Segment[], metas: readonly StagedFileMeta[]): number {
  const m = stagedMetas(segments, metas);
  let total = 0;
  let k = 0;
  for (const s of segments) {
    if (s.kind === "text") {
      total += s.bytes.byteLength;
      continue;
    }
    const n = m[k++]!.byteLength;
    total +=
      s.encoding === "identity" ? n : s.encoding === "base64" ? base64Length(n, "plain") : base64Length(n, "lines");
  }
  return total;
}

/** Strip characters that could break a header or a summary line out of a
 *  row-derived filename (CR, LF, NUL and other C0/DEL controls), optionally
 *  Unicode format characters (category Cf: bidi overrides, zero-width), and
 *  cap it at 255 code points. Empty → null. */
export function sanitiseStagedFilename(
  name: string | null,
  opts: { stripFormat?: boolean } = {},
): string | null {
  if (name === null) return null;
  // eslint-disable-next-line no-control-regex
  let s = name.replace(/[\u0000-\u001f\u007f]/g, "");
  if (opts.stripFormat) s = s.replace(/\p{Cf}/gu, "");
  const cps = [...s];
  if (cps.length > FILENAME_MAX_CODE_POINTS) s = cps.slice(0, FILENAME_MAX_CODE_POINTS).join("");
  return s === "" ? null : s;
}

const MEDIA_TYPE_ESSENCE = /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/;

/** The media-type essence of a row's stored content type (it was the
 *  uploader's `Content-Type` header and may carry `;`, quotes, a `boundary=`
 *  parameter or worse). Anything that is not a clean `type/subtype` becomes
 *  `application/octet-stream`. */
export function sanitiseRowContentType(contentType: string): string {
  const essence = contentType.split(";")[0]!.trim();
  return MEDIA_TYPE_ESSENCE.test(essence) ? essence : "application/octet-stream";
}

/** The inspector's view of a composed body: text verbatim, each staged slot a
 *  single U+FFFC, plus the slots' metadata and the exact outbound length. */
export function buildInspectionView(
  segments: readonly Segment[],
  metas: readonly StagedFileMeta[],
): { rawBody: string; staged: InspectStaged[]; assembledByteLength: number } {
  const m = stagedMetas(segments, metas);
  // ignoreBOM: a leading U+FEFF must stay in the view — the wire keeps EF BB BF.
  const decoder = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });
  let rawBody = "";
  const staged: InspectStaged[] = [];
  let k = 0;
  for (const s of segments) {
    if (s.kind === "text") {
      rawBody += decoder.decode(s.bytes);
      continue;
    }
    const meta = m[k++]!;
    rawBody += STAGED_SENTINEL;
    staged.push({
      index: s.index,
      byteLength: meta.byteLength,
      // eslint-disable-next-line no-control-regex
      contentType: meta.contentType.replace(/[\u0000-\u001f\u007f]/g, ""),
      filename: sanitiseStagedFilename(meta.filename),
      encoding: s.encoding,
    });
  }
  return { rawBody, staged, assembledByteLength: assembledLength(segments, m) };
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** RFC 2046 §5.1.1: boundary is `1*70(bchars)`; 24 random bytes as hex. */
export function newMultipartBoundary(): string {
  const rb = new Uint8Array(24);
  crypto.getRandomValues(rb);
  return "----codemode-" + Array.from(rb, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** One part's delimiter + headers, exactly as `buildMultipartBody` emits it. */
export function multipartPartHead(
  boundary: string,
  name: string,
  filename: string | null | undefined,
  contentType: string,
): string {
  const filenameAttr = filename ? `; filename="${filename.replace(/"/g, "")}"` : "";
  return (
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="${name.replace(/"/g, "")}"${filenameAttr}\r\n` +
    `Content-Type: ${contentType}\r\n\r\n`
  );
}

/** The effective filename/content type of a staged part: the sandbox's own
 *  value when given (already checked at entry), else the row's, sanitised. */
export function stagedPartDefaults(
  part: ComposeMultipartPart,
  meta: StagedFileMeta,
): { filename: string | null; contentType: string } {
  return {
    filename: part.filename !== undefined ? part.filename : sanitiseStagedFilename(meta.filename),
    contentType: part.contentType ?? sanitiseRowContentType(meta.contentType),
  };
}

/**
 * Compile a multipart part list containing staged parts into segments: host
 * text (delimiters, part headers, inline values) and one identity segment per
 * staged part, behind the host-random `boundary`. `metas[k]` describes the
 * k-th staged part. Non-staged output is byte-identical to `buildMultipartBody`.
 */
export function compileStagedMultipart(
  parts: readonly ComposeMultipartPart[],
  boundary: string,
  metas: readonly StagedFileMeta[],
): Segment[] {
  const segments: Segment[] = [];
  let pending: Uint8Array[] = [];
  const flush = (): void => {
    if (pending.length === 0) return;
    let total = 0;
    for (const c of pending) total += c.byteLength;
    const bytes = new Uint8Array(total);
    let off = 0;
    for (const c of pending) {
      bytes.set(c, off);
      off += c.byteLength;
    }
    segments.push({ kind: "text", bytes });
    pending = [];
  };
  let k = 0;
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]!;
    if (p.staged !== undefined) {
      const meta = metas[k++];
      if (!meta) throw new Error("compose: missing metadata for a staged multipart part");
      const d = stagedPartDefaults(p, meta);
      pending.push(TEXT_ENCODER.encode(multipartPartHead(boundary, p.name, d.filename, d.contentType)));
      flush();
      segments.push({ kind: "staged", ref: p.staged, encoding: "identity", index: i });
    } else {
      const defaultCt = p.bodyBase64 !== undefined ? "application/octet-stream" : "text/plain";
      pending.push(TEXT_ENCODER.encode(multipartPartHead(boundary, p.name, p.filename, p.contentType ?? defaultCt)));
      if (p.bodyBase64 !== undefined) pending.push(base64ToBytes(p.bodyBase64));
      else if (typeof p.value === "string") pending.push(TEXT_ENCODER.encode(p.value));
    }
    pending.push(TEXT_ENCODER.encode("\r\n"));
  }
  if (k !== metas.length) throw new Error("compose: more metadata than staged multipart parts");
  pending.push(TEXT_ENCODER.encode(`--${boundary}--\r\n`));
  flush();
  return segments;
}

function abortReason(signal: AbortSignal): Error {
  const r: unknown = signal.reason;
  return r instanceof Error ? r : new Error("staged transfer aborted");
}

/**
 * Write the assembled body into `sink`, block by block. `files[k]` is the
 * opened file for the k-th staged segment; each is read exactly once.
 *
 * Every wait on the sink races the abort signal, so an upstream that stops
 * reading (and leaves a write blocked on backpressure) cannot pin this loop:
 * on abort or any failure the loop stops pulling blocks, the sink is aborted
 * (never closed short), and the promise rejects. The sink abort is not
 * awaited — it completes when the consumer next pulls or is cancelled.
 */
export async function writeAssembled(
  segments: readonly Segment[],
  files: readonly OpenStagedFile[],
  sink: FixedLengthSink,
  signal: AbortSignal,
): Promise<void> {
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(abortReason(signal));
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
  aborted.catch(() => {});
  const guard = <T>(p: Promise<T>): Promise<T> => {
    p.catch(() => {});
    return Promise.race([p, aborted]);
  };
  const write = async (chunk: Uint8Array): Promise<void> => {
    if (signal.aborted) throw abortReason(signal);
    await guard(sink.write(chunk));
  };
  try {
    if (signal.aborted) throw abortReason(signal);
    if (files.length !== segments.filter((s) => s.kind === "staged").length) {
      throw new Error("compose: staged segment and file counts differ");
    }
    let k = 0;
    for (const seg of segments) {
      if (seg.kind === "text") {
        for (let off = 0; off < seg.bytes.byteLength; off += TEXT_CHUNK_BYTES) {
          await write(seg.bytes.subarray(off, Math.min(seg.bytes.byteLength, off + TEXT_CHUNK_BYTES)));
        }
        continue;
      }
      const file = files[k++]!;
      if (seg.encoding === "identity") {
        await guard(file.readBlocks((plain) => write(plain)));
      } else {
        const encoder = new Base64Encoder(seg.encoding === "base64" ? "plain" : "lines");
        await guard(file.readBlocks((plain) => encoder.push(plain, write)));
        await encoder.finish(write);
      }
    }
    await guard(sink.close());
  } catch (err) {
    void sink.abort(err).catch(() => {});
    throw err;
  } finally {
    if (onAbort) signal.removeEventListener("abort", onAbort);
  }
}
