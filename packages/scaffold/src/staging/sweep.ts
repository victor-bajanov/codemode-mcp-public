import { listExpired, deleteByHash } from "./repo";

export interface SweepDeps {
  STAGING_D1: D1Database;
  STAGING_R2: R2Bucket;
  now?: () => number;
}

export async function runSweep(deps: SweepDeps): Promise<{ deletedRows: number; deletedObjects: number }> {
  const now = (deps.now ?? (() => Math.floor(Date.now() / 1000)))();
  const expired = await listExpired(deps.STAGING_D1, now);
  let deletedObjects = 0;
  for (const row of expired) {
    if (row.r2_key) {
      try {
        await deps.STAGING_R2.delete(row.r2_key);
        deletedObjects += 1;
      } catch {
        // If R2 delete fails, leave the row so we retry next sweep.
        continue;
      }
    }
    await deleteByHash(deps.STAGING_D1, row.token_hash);
  }
  return { deletedRows: expired.length, deletedObjects };
}
