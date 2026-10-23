// packages/scaffold/src/staging/__tests__/__fixtures__/fake-r2.ts
// Minimal in-memory R2 substitute. Supports the subset of R2Bucket used by staging:
//   - put(key, body)   — body may be a ReadableStream (drained), ArrayBuffer or view
//   - get(key) -> { size, body: ReadableStream, arrayBuffer() } | null
//   - head(key) -> { size } | null
//   - delete(key)
//   - list({ prefix? }) -> { objects: [{ key }] }
//
// `putKinds` records what each put received ("stream" | "bytes") so tests can
// assert that file-sized writes go through a stream, never a whole buffer;
// `maxPutBufferBytes` is the largest Uint8Array/ArrayBuffer ever passed.
// `chunkBytes` (optional) makes `get().body` deliver the object in chunks of
// that size, to exercise readers across chunk boundaries.

export class FakeR2 {
  store = new Map<string, Uint8Array>();
  putKinds: Array<"stream" | "bytes"> = [];
  maxPutBufferBytes = 0;
  getCalls = 0;
  chunkBytes: number | null = null;

  async put(key: string, body: ArrayBuffer | ArrayBufferView | Uint8Array | ReadableStream): Promise<void> {
    if (body instanceof ReadableStream) {
      this.putKinds.push("stream");
      const reader = body.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) {
          chunks.push(value);
          total += value.byteLength;
        }
      }
      const merged = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) {
        merged.set(c, off);
        off += c.byteLength;
      }
      this.store.set(key, merged);
      return;
    }
    this.putKinds.push("bytes");
    if (body instanceof ArrayBuffer) {
      this.maxPutBufferBytes = Math.max(this.maxPutBufferBytes, body.byteLength);
      this.store.set(key, new Uint8Array(body));
      return;
    }
    if (ArrayBuffer.isView(body)) {
      this.maxPutBufferBytes = Math.max(this.maxPutBufferBytes, body.byteLength);
      this.store.set(key, new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
      return;
    }
    throw new Error("FakeR2.put: unsupported body type");
  }

  async get(key: string): Promise<{
    size: number;
    arrayBuffer(): Promise<ArrayBuffer>;
    body: ReadableStream<Uint8Array>;
  } | null> {
    this.getCalls++;
    const v = this.store.get(key);
    if (!v) return null;
    const chunk = this.chunkBytes;
    return {
      size: v.byteLength,
      arrayBuffer: async () => v.slice().buffer,
      get body() {
        let off = 0;
        return new ReadableStream<Uint8Array>({
          pull(c) {
            if (off >= v.byteLength) {
              c.close();
              return;
            }
            const end = chunk ? Math.min(v.byteLength, off + chunk) : v.byteLength;
            c.enqueue(v.slice(off, end));
            off = end;
          },
        });
      },
    };
  }

  async head(key: string): Promise<{ size: number } | null> {
    const v = this.store.get(key);
    return v ? { size: v.byteLength } : null;
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(opts?: { prefix?: string }): Promise<{ objects: { key: string }[] }> {
    const prefix = opts?.prefix ?? "";
    return { objects: Array.from(this.store.keys()).filter((k) => k.startsWith(prefix)).map((k) => ({ key: k })) };
  }
}
