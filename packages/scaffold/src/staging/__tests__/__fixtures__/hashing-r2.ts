// R2 stand-in for the memory ladder: keeps only each object's length and a
// running SHA-256 of what was put, never the content. `get` serves the object
// from a caller-supplied generator (the test re-derives the ciphertext block
// by block), and hashes what it serves so the test can prove the regenerated
// object equals the one that was written.
import { createHash, type Hash } from "node:crypto";

export class HashingR2 {
  objects = new Map<string, { size: number; sha256: string }>();
  served = new Map<string, Hash>();
  generate: ((key: string) => ReadableStream<Uint8Array>) | null = null;
  onChunk: () => void = () => {};

  async put(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    if (!(body instanceof ReadableStream)) throw new Error("HashingR2.put: stream bodies only");
    const h = createHash("sha256");
    let size = 0;
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      h.update(value);
      size += value.byteLength;
      this.onChunk();
    }
    this.objects.set(key, { size, sha256: h.digest("hex") });
  }

  async get(key: string): Promise<{ size: number; body: ReadableStream<Uint8Array>; arrayBuffer(): Promise<ArrayBuffer> } | null> {
    const o = this.objects.get(key);
    if (!o || !this.generate) return null;
    const src = this.generate(key).getReader();
    const h = createHash("sha256");
    this.served.set(key, h);
    const onChunk = this.onChunk;
    return {
      size: o.size,
      arrayBuffer: async () => {
        throw new Error("HashingR2: arrayBuffer() is not allowed on file-sized objects");
      },
      body: new ReadableStream<Uint8Array>({
        async pull(c) {
          const { done, value } = await src.read();
          if (done) {
            c.close();
            return;
          }
          h.update(value);
          onChunk();
          c.enqueue(value);
        },
      }),
    };
  }

  async delete(key: string): Promise<void> {
    this.objects.delete(key);
  }
}
