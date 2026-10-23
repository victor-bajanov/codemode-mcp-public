// Isolate-wide slot for writes of unknown length. Such a write holds its
// plaintext blocks until the source ends (the AAD binds the total length), up
// to maxBytes, so at most one runs per isolate: `/staging/upload` without
// Content-Length and `returnAs:"stage"` without a usable length share it.
// Busy → refuse (503), never queue.

const MAX_UNKNOWN_LENGTH_WRITES = 1;
let inFlight = 0;

/** An idempotent release, or `null` when the slot is held. */
export function tryAcquireUnknownLengthSlot(): (() => void) | null {
  if (inFlight >= MAX_UNKNOWN_LENGTH_WRITES) return null;
  inFlight++;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    inFlight--;
  };
}
