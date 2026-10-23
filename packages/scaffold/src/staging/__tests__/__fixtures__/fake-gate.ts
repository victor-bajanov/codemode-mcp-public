// Records transfer-gate acquisitions; structurally a TransferGate.
export class FakeGate {
  acquired: Array<{ runKey: object; signal: AbortSignal }> = [];
  released = 0;
  inFlight = 0;
  maxInFlight = 0;
  rejectWith: Error | null = null;

  async acquire(runKey: object, signal: AbortSignal): Promise<() => void> {
    if (this.rejectWith) throw this.rejectWith;
    this.acquired.push({ runKey, signal });
    this.inFlight++;
    this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
    let done = false;
    return () => {
      if (done) return;
      done = true;
      this.inFlight--;
      this.released++;
    };
  }
}
