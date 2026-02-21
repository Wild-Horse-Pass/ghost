// BUDS (Bitcoin Universal Data Specification) API endpoints
import { fetchApi } from './client';

export interface BudsTierStats {
  tier: string;
  count: number;
  size_vbytes?: number;
  total_fees?: number;
}

export interface BudsMempool {
  tiers?: BudsTierStats[];
  total_count?: number;
  total_size?: number;
  total_fees?: number;
  last_update?: number;
  // Backend may also return these
  transactions?: unknown[];
  by_tier?: Record<string, unknown>;
}

export interface BudsCapabilities {
  // Backend returns these
  reaper?: boolean;
  allowed_tiers?: string[];
  max_op_return_size?: number;
  allow_inscriptions?: boolean;
  allow_runes?: boolean;
  // Dashboard aliases
  tier0?: boolean;
  tier1?: boolean;
  tier2?: boolean;
  tier3?: boolean;
}

export async function getBudsMempool(): Promise<BudsMempool> {
  return fetchApi<BudsMempool>('/api/v1/buds/mempool');
}

export async function getBudsCapabilities(): Promise<BudsCapabilities> {
  return fetchApi<BudsCapabilities>('/api/v1/buds/capabilities');
}
