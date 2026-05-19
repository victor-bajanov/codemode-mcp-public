// packages/scaffold/src/staging/__tests__/__fixtures__/fake-r2.ts
// Minimal in-memory R2 substitute. Supports the subset of R2Bucket used by staging:
//   - put(key, body)
//   - get(key) -> { body: Uint8Array, httpMetadata, customMetadata } | null
//   - delete(key)
//   - list({ prefix? }) -> { objects: [{ key }] }

export class FakeR2 {
  store = new Map<string, Uint8Array>();

  async put(key: string, body: ArrayBuffer | ArrayBufferView | Uint8Array | ReadableStream): Promise<void> {
    if (body instanceof ReadableStream) {
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
    if (body instanceof ArrayBuffer) {
      this.store.set(key, new Uint8Array(body));
      return;
    }
    if (ArrayBuffer.isView(body)) {
      this.store.set(key, new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
      return;
    }
    throw new Error("FakeR2.put: unsupported body type");
  }

  async get(key: string): Promise<{
    arrayBuffer(): Promise<ArrayBuffer>;
    body: ReadableStream<Uint8Array>;
  } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return {
      arrayBuffer: async () => v.slice().buffer,
      get body() {
        return new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(v);
            c.close();
          },
        });
      },
    };
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(opts?: { prefix?: string }): Promise<{ objects: { key: string }[] }> {
    const prefix = opts?.prefix ?? "";
    return { objects: Array.from(this.store.keys()).filter((k) => k.startsWith(prefix)).map((k) => ({ key: k })) };
  }
}
