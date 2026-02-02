/**
 * In-Memory Escrow Store
 *
 * Simple in-memory implementation for testing and local development.
 */

import type { Escrow, EscrowStatus, EscrowStore } from '../types.js';

export class MemoryEscrowStore implements EscrowStore {
  private escrows: Map<string, Escrow> = new Map();

  async save(escrow: Escrow): Promise<void> {
    this.escrows.set(escrow.escrow_id, { ...escrow });
  }

  async get(escrow_id: string): Promise<Escrow | null> {
    const escrow = this.escrows.get(escrow_id);
    return escrow ? { ...escrow } : null;
  }

  async list(filters?: {
    requester_did?: string;
    agent_did?: string;
    status?: EscrowStatus;
  }): Promise<Escrow[]> {
    let results = Array.from(this.escrows.values());

    if (filters?.requester_did) {
      results = results.filter((e) => e.requester_did === filters.requester_did);
    }
    if (filters?.agent_did) {
      results = results.filter((e) => e.agent_did === filters.agent_did);
    }
    if (filters?.status) {
      results = results.filter((e) => e.status === filters.status);
    }

    return results.map((e) => ({ ...e }));
  }

  /** Clear all escrows (for testing) */
  clear(): void {
    this.escrows.clear();
  }
}
