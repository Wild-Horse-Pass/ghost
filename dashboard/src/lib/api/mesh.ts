// Mesh Network API endpoints
import { fetchApi } from './client';

export interface MeshPeerCapabilities {
  archive_mode: boolean;    // +5
  ghost_pay: boolean;       // +4
  public_mining: boolean;   // +3
  bitcoin_pure: boolean;    // +2
  elder_rank: number | null; // +1
}

export interface MeshPeer {
  node_id: string;
  address: string;
  connected: boolean;
  latency_ms: number | null;
  last_seen: number;
  capabilities: MeshPeerCapabilities;
}

export interface ChallengeServiceStats {
  service: string;
  total_challenges: number;
  passed: number;
  failed: number;
  timeouts: number;
  pass_rate: number;
  qualified: boolean;
  min_required: number;
  threshold: number;
}

export interface ConsensusStatus {
  active: boolean;
  total_nodes: number;      // Total nodes including self
  peers_connected: number;  // Other nodes connected (not including self)
  peers_required: number;   // Minimum for quorum (67%)
  quorum_met: boolean;
  last_vote_round: number | null;
  last_vote_timestamp: number | null;
}

export interface MeshResponse {
  node_id: string;
  external_address: string | null;
  peers: MeshPeer[];
  consensus: ConsensusStatus;
  challenge_stats: ChallengeServiceStats[];
  uptime_seconds: number;
}

export async function getMeshStatus(): Promise<MeshResponse> {
  return fetchApi<MeshResponse>('/api/v1/mesh/status');
}
