/** Reject responses from requests started before logout, expiry or account change.
 * The backend remains the authoritative source for session and device access.
 */
export class SessionEpoch {
  private version = 0;
  private active = false;

  start(): number {
    this.active = true;
    return ++this.version;
  }

  end(): void {
    this.active = false;
    ++this.version;
  }

  snapshot(): number {
    return this.version;
  }

  isCurrent(snapshot: number): boolean {
    return this.active && this.version === snapshot;
  }
}

export function isUnauthorized(error: unknown): boolean {
  return !!error && typeof error === 'object' && 'status' in error && error.status === 401;
}
