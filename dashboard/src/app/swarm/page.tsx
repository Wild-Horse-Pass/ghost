"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { getSwarm, addSwarmNode, removeSwarmNode } from "@/lib/api";
import type { SwarmNode, SwarmStats, SwarmAlert } from "@/types/api";

function truncateId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 6)}...${id.slice(-6)}`;
}

function formatBtc(btc: number): string {
  return btc.toFixed(4);
}

function formatUptime(percent: number): string {
  return `${percent.toFixed(1)}%`;
}

function formatHashrate(th: number): string {
  if (th >= 1000) {
    return `${(th / 1000).toFixed(1)} PH/s`;
  }
  return `${th.toFixed(0)} TH/s`;
}

function getAlertIcon(severity: "info" | "warning" | "error"): string {
  switch (severity) {
    case "error":
      return "x";
    case "warning":
      return "!";
    case "info":
    default:
      return "i";
  }
}

export default function SwarmPage() {
  const [nodes, setNodes] = useState<SwarmNode[]>([]);
  const [stats, setStats] = useState<SwarmStats | null>(null);
  const [alerts, setAlerts] = useState<SwarmAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newNodeName, setNewNodeName] = useState("");
  const [newNodeAddress, setNewNodeAddress] = useState("");
  const [addingNode, setAddingNode] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const data = await getSwarm();
      setNodes(data.nodes ?? []);
      setStats(data.stats ?? null);
      setAlerts(data.alerts ?? []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleAddNode = async () => {
    if (!newNodeName.trim() || !newNodeAddress.trim()) return;

    setAddingNode(true);
    try {
      await addSwarmNode(newNodeName.trim(), newNodeAddress.trim());
      setNewNodeName("");
      setNewNodeAddress("");
      setShowAddModal(false);
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add node");
    } finally {
      setAddingNode(false);
    }
  };

  const handleRemoveNode = async (nodeId: string) => {
    if (!confirm("Are you sure you want to remove this node from the swarm?")) return;

    try {
      await removeSwarmNode(nodeId);
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove node");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-2xl font-bold text-gray-100 mb-6">Swarm</h1>
          <div className="animate-pulse space-y-6">
            <div className="h-24 bg-gray-800 rounded-lg"></div>
            <div className="h-64 bg-gray-800 rounded-lg"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold text-gray-100">Swarm</h1>
          <button
            onClick={() => setShowAddModal(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium"
          >
            + Add Node
          </button>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-800 rounded-lg">
            <p className="text-red-400">{error}</p>
          </div>
        )}

        {/* Aggregate Stats */}
        <Card className="mb-6">
          <CardHeader title="Aggregate Stats" />
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-gray-100">
                {stats?.total_nodes ?? 0}
              </div>
              <div className="text-sm text-gray-400">Total Nodes</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-green-400">
                {stats?.online_nodes ?? 0}
              </div>
              <div className="text-sm text-gray-400">Online</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-red-400">
                {stats?.offline_nodes ?? 0}
              </div>
              <div className="text-sm text-gray-400">Offline</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-blue-400">
                {stats?.combined_shares ?? 0} / {stats?.max_combined_shares ?? 0}
              </div>
              <div className="text-sm text-gray-400">Combined Shares</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-yellow-400">
                {formatBtc(stats?.total_balance_btc ?? 0)} BTC
              </div>
              <div className="text-sm text-gray-400">Total Balance</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-purple-400">
                {formatUptime(stats?.avg_uptime_percent ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Avg Uptime</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg col-span-2">
              <div className="text-2xl font-bold text-orange-400">
                {formatHashrate(stats?.combined_hashrate_th ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Combined Hashrate</div>
            </div>
          </div>
        </Card>

        {/* Node Cards */}
        {nodes.length === 0 ? (
          <Card className="mb-6">
            <div className="text-center py-12">
              <p className="text-gray-400 mb-4">No nodes in your swarm yet</p>
              <button
                onClick={() => setShowAddModal(true)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
              >
                Add Your First Node
              </button>
            </div>
          </Card>
        ) : (
          <div className="space-y-4 mb-6">
            {nodes.map((node) => (
              <Card key={node.node_id}>
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <span
                      className={`w-3 h-3 rounded-full ${
                        node.online ? "bg-green-500" : "bg-red-500"
                      }`}
                    />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-lg font-semibold text-gray-100">
                          {node.name}
                        </span>
                        <span className="text-gray-500 font-mono text-sm">
                          ({truncateId(node.node_id)})
                        </span>
                        <Badge variant={node.online ? "success" : "error"}>
                          {node.online ? "Online" : "Offline"}
                        </Badge>
                      </div>
                      <div className="text-sm text-gray-400 mt-1">
                        {node.address}
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-lg font-bold text-gray-100">
                      {formatBtc(node.balance_btc ?? 0)} BTC
                    </div>
                    <div className="text-sm text-gray-400">
                      {node.shares ?? 0}/{node.max_shares ?? 0} shares
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4 text-sm">
                  <div>
                    <span className="text-gray-500">Uptime</span>
                    <div className={`font-medium ${
                      (node.uptime_percent ?? 0) >= 95 ? "text-green-400" :
                      (node.uptime_percent ?? 0) >= 90 ? "text-yellow-400" : "text-red-400"
                    }`}>
                      {formatUptime(node.uptime_percent ?? 0)}
                    </div>
                  </div>
                  <div>
                    <span className="text-gray-500">Peers</span>
                    <div className="text-gray-100">{node.peer_count ?? 0}</div>
                  </div>
                  <div>
                    <span className="text-gray-500">L1 Height</span>
                    <div className="text-gray-100 font-mono">{(node.l1_height ?? 0).toLocaleString()}</div>
                  </div>
                  <div>
                    <span className="text-gray-500">L2 Height</span>
                    <div className="text-gray-100 font-mono">{(node.l2_height ?? 0).toLocaleString()}</div>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 mt-4">
                  {node.archive_mode && (
                    <Badge variant="success">Archive +5</Badge>
                  )}
                  {node.ghost_pay && (
                    <Badge variant="info">Ghost Pay +4</Badge>
                  )}
                  {node.public_mining && (
                    <Badge variant="info">Public Mining +3</Badge>
                  )}
                  {node.bitcoin_pure && (
                    <Badge variant="info">Bitcoin Pure +2</Badge>
                  )}
                  {node.elder && (
                    <Badge variant="success">
                      Elder #{node.elder_slot} +1
                    </Badge>
                  )}
                </div>

                <div className="flex gap-2 mt-4 pt-4 border-t border-gray-800">
                  <a
                    href={`http://${node.address}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                  >
                    Open Dashboard
                  </a>
                  <button className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded text-sm">
                    Configure
                  </button>
                  <button
                    onClick={() => handleRemoveNode(node.node_id)}
                    className="px-3 py-1 bg-red-900/50 hover:bg-red-800 text-red-300 rounded text-sm"
                  >
                    Remove
                  </button>
                </div>
              </Card>
            ))}
          </div>
        )}

        {/* Alerts */}
        {alerts.length > 0 && (
          <Card>
            <CardHeader title="Alerts" />
            <div className="space-y-2">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`p-3 rounded-lg flex items-start gap-3 ${
                    alert.severity === "error"
                      ? "bg-red-900/20 border border-red-800"
                      : alert.severity === "warning"
                      ? "bg-yellow-900/20 border border-yellow-800"
                      : "bg-blue-900/20 border border-blue-800"
                  }`}
                >
                  <span
                    className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                      alert.severity === "error"
                        ? "bg-red-500 text-white"
                        : alert.severity === "warning"
                        ? "bg-yellow-500 text-black"
                        : "bg-blue-500 text-white"
                    }`}
                  >
                    {getAlertIcon(alert.severity ?? "info")}
                  </span>
                  <div className="flex-1">
                    <p
                      className={`${
                        alert.severity === "error"
                          ? "text-red-400"
                          : alert.severity === "warning"
                          ? "text-yellow-400"
                          : "text-blue-400"
                      }`}
                    >
                      {alert.message}
                    </p>
                    <p className="text-xs text-gray-500 mt-1">
                      {new Date((alert.timestamp ?? 0) * 1000).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Add Node Modal */}
        {showAddModal && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
              <h2 className="text-xl font-bold text-gray-100 mb-4">Add Node to Swarm</h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Node Name</label>
                  <input
                    type="text"
                    value={newNodeName}
                    onChange={(e) => setNewNodeName(e.target.value)}
                    placeholder="e.g., US-East, Primary"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-gray-100 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1">Node Address</label>
                  <input
                    type="text"
                    value={newNodeAddress}
                    onChange={(e) => setNewNodeAddress(e.target.value)}
                    placeholder="e.g., 192.168.1.100:8080"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-gray-100 focus:outline-none focus:border-blue-500"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    The node must have API access enabled for remote connections
                  </p>
                </div>
              </div>

              <div className="flex gap-3 mt-6">
                <button
                  onClick={() => setShowAddModal(false)}
                  className="flex-1 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAddNode}
                  disabled={addingNode || !newNodeName.trim() || !newNodeAddress.trim()}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                >
                  {addingNode ? "Adding..." : "Add Node"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
