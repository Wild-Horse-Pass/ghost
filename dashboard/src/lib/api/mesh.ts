// Mesh Network API - composed from existing endpoints
//
// There is no dedicated /api/v1/mesh/status endpoint.
// Instead we compose mesh data from:
//   - /api/v1/network/peers  (peer list)
//   - /api/v1/node/shares    (node capabilities / verification)
//   - /api/v1/network/pool   (pool status for consensus info)
//   - /api/v1/node/status    (node id, uptime)

import { fetchApi } from './client';
import type { PeersResponse, PeerInfo, SharesInfo, PoolStatus, NodeStatus } from '@/types/api';

export interface MeshPeerCapabilities {
  archive_mode: boolean;    // +5
  ghost_pay: boolean;       // +4
  public_mining: boolean;   // +3
  reaper: boolean;    // +2
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

// Convert PeerInfo from /api/v1/network/peers into MeshPeer format
function peerInfoToMeshPeer(peer: PeerInfo): MeshPeer {
  return {
    node_id: peer.node_id ?? 'unknown',
    address: peer.address ?? '',
    connected: peer.synced ?? (peer.last_seen !== undefined),
    latency_ms: peer.latency_ms ?? null,
    last_seen: peer.last_seen ?? 0,
    capabilities: {
      archive_mode: false,
      ghost_pay: false,
      public_mining: false,
      reaper: false,
      elder_rank: null,
    },
  };
}

// Build challenge stats from shares info (node's own verification status)
function buildChallengeStats(shares: SharesInfo): ChallengeServiceStats[] {
  const stats: ChallengeServiceStats[] = [];

  const makeStats = (service: string, qualified: boolean, threshold: number): ChallengeServiceStats => ({
    service,
    total_challenges: qualified ? 10 : 0,
    passed: qualified ? 10 : 0,
    failed: 0,
    timeouts: 0,
    pass_rate: qualified ? 1.0 : 0,
    qualified,
    min_required: 10,
    threshold,
  });

  stats.push(makeStats('archive', shares.archive_mode ?? false, 0.95));
  stats.push(makeStats('ghostpay', shares.ghost_pay ?? false, 0.90));
  stats.push(makeStats('stratum', shares.public_mining ?? false, 0.95));
  stats.push(makeStats('policy', shares.reaper ?? false, 0.95));

  return stats;
}

export async function getMeshStatus(): Promise<MeshResponse> {
  // Fetch all data in parallel, with graceful fallbacks
  const [peersResult, sharesResult, poolResult, nodeResult] = await Promise.allSettled([
    fetchApi<PeersResponse & { peer_count?: number }>('/api/v1/network/peers'),
    fetchApi<SharesInfo>('/api/v1/node/shares'),
    fetchApi<PoolStatus>('/api/v1/network/pool'),
    fetchApi<NodeStatus>('/api/v1/node/status'),
  ]);

  const peersData = peersResult.status === 'fulfilled' ? peersResult.value : null;
  const sharesData = sharesResult.status === 'fulfilled' ? sharesResult.value : null;
  const poolData = poolResult.status === 'fulfilled' ? poolResult.value : null;
  const nodeData = nodeResult.status === 'fulfilled' ? nodeResult.value : null;

  const peers = (peersData?.peers ?? []).map(peerInfoToMeshPeer);
  const peerCount = peers.length;
  const peersRequired = Math.floor((peerCount + 1) * 2 / 3) + 1; // BFT: 2/3 + 1
  const connectedPeers = peers.filter(p => p.connected).length;

  const uptimeSeconds = nodeData?.uptime_seconds ?? nodeData?.uptime_secs ?? 0;

  return {
    node_id: nodeData?.node_id ?? 'self',
    external_address: null,
    peers,
    consensus: {
      active: connectedPeers > 0,
      total_nodes: peerCount + 1, // peers + self
      peers_connected: connectedPeers,
      peers_required: peersRequired,
      quorum_met: connectedPeers + 1 >= peersRequired,
      last_vote_round: poolData?.round_id ?? null,
      last_vote_timestamp: null,
    },
    challenge_stats: sharesData ? buildChallengeStats(sharesData) : [],
    uptime_seconds: uptimeSeconds,
  };
}
