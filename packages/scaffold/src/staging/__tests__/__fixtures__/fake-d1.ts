// packages/scaffold/src/staging/__tests__/__fixtures__/fake-d1.ts
// Minimal in-memory D1 substitute. Supports only what staging/repo.ts uses:
//   - prepare(sql).bind(...args)
//   - .run() / .first() / .all()
//   - INSERT INTO staging (...)
//   - UPDATE staging SET state='claimed', ... WHERE token_hash=? AND state='pending' AND expires_at>? RETURNING ...
//   - UPDATE staging SET state='corrupt' WHERE token_hash=?
//   - SELECT ... FROM staging WHERE token_hash=?
//   - SELECT token_hash, r2_key FROM staging WHERE expires_at < ?
//   - DELETE FROM staging WHERE token_hash=?
//
// Strategy: keep rows in a Map keyed by hex(token_hash). Each prepare() parses the SQL
// into a small handler closure. We don't need a real query engine.

import type { StagingRow } from "../../types";

const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

interface Stored extends Omit<StagingRow, "token_hash" | "iv"> {
  token_hash_hex: string;
  iv_hex: string | null;
}

export class FakeD1 {
  rows = new Map<string, Stored>();

  prepare(sql: string): FakeD1Statement {
    return new FakeD1Statement(this, sql, []);
  }

  toRow(stored: Stored): StagingRow {
    return {
      token_hash: hexToBytes(stored.token_hash_hex),
      file_handle: stored.file_handle,
      state: stored.state,
      r2_key: stored.r2_key,
      iv: stored.iv_hex ? hexToBytes(stored.iv_hex) : null,
      content_type_hint: stored.content_type_hint,
      content_type: stored.content_type,
      expected_byte_len: stored.expected_byte_len,
      byte_len: stored.byte_len,
      filename: stored.filename,
      created_at: stored.created_at,
      claimed_at: stored.claimed_at,
      expires_at: stored.expires_at,
    };
  }
}

function hexToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

class FakeD1Statement {
  constructor(
    private db: FakeD1,
    private sql: string,
    private args: unknown[],
  ) {}

  bind(...args: unknown[]): FakeD1Statement {
    return new FakeD1Statement(this.db, this.sql, args);
  }

  async run(): Promise<{ success: boolean; meta: { rows_written: number; rows_read: number } }> {
    const result = this.exec();
    return {
      success: true,
      meta: {
        rows_written: result.written,
        rows_read: result.read,
      },
    };
  }

  async first<T = unknown>(): Promise<T | null> {
    const result = this.exec();
    return (result.rows[0] as T | undefined) ?? null;
  }

  async all<T = unknown>(): Promise<{ results: T[] }> {
    const result = this.exec();
    return { results: result.rows as T[] };
  }

  private exec(): { rows: unknown[]; written: number; read: number } {
    const sql = this.sql.replace(/\s+/g, " ").trim();
    if (sql.startsWith("INSERT INTO staging")) {
      const key = hex(this.args[0] as Uint8Array);
      if (this.db.rows.has(key)) throw new Error("UNIQUE constraint failed: staging.token_hash");

      // Support both insertPending (8 args) and insertClaimed (13 args)
      if (this.args.length === 8) {
        // insertPending: token_hash, file_handle, state, content_type_hint, expected_byte_len, filename, created_at, expires_at
        const [
          token_hash, file_handle, state, content_type_hint,
          expected_byte_len, filename, created_at, expires_at,
        ] = this.args as [Uint8Array, string, string, string | null, number | null, string | null, number, number];
        this.db.rows.set(key, {
          token_hash_hex: key,
          file_handle,
          state: state as StagingRow["state"],
          r2_key: null,
          iv_hex: null,
          content_type_hint: content_type_hint ?? null,
          content_type: null,
          expected_byte_len: expected_byte_len ?? null,
          byte_len: null,
          filename: filename ?? null,
          created_at,
          claimed_at: null,
          expires_at,
        });
      } else if (this.args.length === 13) {
        // insertClaimed: token_hash, file_handle, state, r2_key, iv, content_type_hint, content_type, expected_byte_len, byte_len, filename, created_at, claimed_at, expires_at
        const [
          token_hash, file_handle, state, r2_key, iv, content_type_hint,
          content_type, expected_byte_len, byte_len, filename, created_at, claimed_at, expires_at,
        ] = this.args as [Uint8Array, string, string, string, Uint8Array, string | null, string, number | null, number, string | null, number, number, number];
        this.db.rows.set(key, {
          token_hash_hex: key,
          file_handle,
          state: state as StagingRow["state"],
          r2_key,
          iv_hex: hex(iv),
          content_type_hint: content_type_hint ?? null,
          content_type,
          expected_byte_len: expected_byte_len ?? null,
          byte_len,
          filename: filename ?? null,
          created_at,
          claimed_at,
          expires_at,
        });
      } else {
        throw new Error(`FakeD1: unexpected INSERT argument count: ${this.args.length}`);
      }
      return { rows: [], written: 1, read: 0 };
    }
    if (sql.startsWith("UPDATE staging SET state='claimed'") || sql.startsWith("UPDATE staging SET state = 'claimed'")) {
      const [iv, content_type, byte_len, r2_key, claimed_at, new_expires, token_hash, now] =
        this.args as [Uint8Array, string, number, string, number, number, Uint8Array, number];
      const key = hex(token_hash);
      const row = this.db.rows.get(key);
      if (!row || row.state !== "pending" || row.expires_at <= now) {
        return { rows: [], written: 0, read: 0 };
      }
      row.state = "claimed";
      row.iv_hex = hex(iv);
      row.content_type = content_type;
      row.byte_len = byte_len;
      row.r2_key = r2_key;
      row.claimed_at = claimed_at;
      row.expires_at = new_expires;
      return { rows: [{ file_handle: row.file_handle }], written: 1, read: 1 };
    }
    if (sql.startsWith("UPDATE staging SET state='corrupt'") || sql.startsWith("UPDATE staging SET state = 'corrupt'")) {
      const [token_hash] = this.args as [Uint8Array];
      const row = this.db.rows.get(hex(token_hash));
      if (!row) return { rows: [], written: 0, read: 0 };
      row.state = "corrupt";
      return { rows: [], written: 1, read: 0 };
    }
    if (sql.startsWith("SELECT") && sql.includes("FROM staging WHERE token_hash")) {
      const [token_hash] = this.args as [Uint8Array];
      const row = this.db.rows.get(hex(token_hash));
      return { rows: row ? [this.db.toRow(row)] : [], written: 0, read: row ? 1 : 0 };
    }
    if (sql.startsWith("SELECT") && sql.includes("FROM staging WHERE expires_at")) {
      const [cutoff] = this.args as [number];
      const out: { token_hash: Uint8Array; r2_key: string | null }[] = [];
      for (const row of this.db.rows.values()) {
        if (row.expires_at < cutoff) {
          out.push({ token_hash: hexToBytes(row.token_hash_hex), r2_key: row.r2_key });
        }
      }
      return { rows: out, written: 0, read: out.length };
    }
    if (sql.startsWith("DELETE FROM staging WHERE token_hash")) {
      const [token_hash] = this.args as [Uint8Array];
      const had = this.db.rows.delete(hex(token_hash));
      return { rows: [], written: had ? 1 : 0, read: 0 };
    }
    throw new Error(`FakeD1: unhandled SQL: ${sql}`);
  }
}
