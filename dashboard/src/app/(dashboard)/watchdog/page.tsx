"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { SkeletonCard, SkeletonTable } from "@/components/ui/Skeleton";
import { useWatchdogStatus, useWatchdogEvents, useStartService, useStopService, useRestartService, useResourceStatus } from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { clearSystemCache } from "@/lib/api/watchdog";

type ServiceAction = "start" | "stop" | "restart";


function formatTimestamp(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

function getStatusBadge(status: string): { variant: "success" | "warning" | "error" | "info" | "default"; label: string } {
  switch (status) {
    case "ok":
    case "running":
      return { variant: "success", label: "Running" };
    case "syncing":
      return { variant: "info", label: "Syncing" };
    case "stopped":
      return { variant: "default", label: "Stopped" };
    case "error":
    case "unknown":
      return { variant: "error", label: "Error" };
    default:
      return { variant: "default", label: status };
  }
}

function getEventBadge(eventType: "restart" | "failure" | "recovery" | "warning"): { variant: "success" | "warning" | "error" | "info"; label: string } {
  switch (eventType) {
    case "restart":
      return { variant: "info", label: "Restart" };
    case "failure":
      return { variant: "error", label: "Failure" };
    case "recovery":
      return { variant: "success", label: "Recovered" };
    case "warning":
      return { variant: "warning", label: "Warning" };
    default:
      return { variant: "info", label: eventType };
  }
}

function getHealthBadge(health: string): { variant: "success" | "warning" | "error"; label: string } {
  switch (health) {
    case "healthy":
      return { variant: "success", label: "Healthy" };
    case "degraded":
      return { variant: "warning", label: "Degraded" };
    case "unhealthy":
      return { variant: "error", label: "Unhealthy" };
    default:
      return { variant: "warning", label: health };
  }
}

function getResourceBadge(status: string): { variant: "success" | "warning" | "error"; label: string } {
  switch (status) {
    case "healthy":
      return { variant: "success", label: "Healthy" };
    case "warning":
      return { variant: "warning", label: "Warning" };
    case "critical":
      return { variant: "error", label: "Critical" };
    default:
      return { variant: "warning", label: status };
  }
}

export default function WatchdogPage() {
  const { data: status, isLoading: statusLoading } = useWatchdogStatus();
  const { data: eventsData, isLoading: eventsLoading } = useWatchdogEvents(50);
  const { data: resourceStatus, isLoading: resourceLoading } = useResourceStatus();
  const startService = useStartService();
  const stopService = useStopService();
  const restartService = useRestartService();
  const { success, error } = useToast();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedService, setSelectedService] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<ServiceAction>("restart");
  const [isClearingCache, setIsClearingCache] = useState(false);

  const components = status?.components ?? [];
  const services = status?.services ?? [];
  const events = eventsData?.events ?? [];
  const overallHealth = status?.overall_health ?? "unknown";

  const isPending = startService.isPending || stopService.isPending || restartService.isPending;

  const handleClearCache = async () => {
    if (isClearingCache) return;
    setIsClearingCache(true);
    try {
      const result = await clearSystemCache();
      if (result.success) {
        success("Cache Cleared", result.message);
      } else {
        error("Clear Cache Failed", result.message);
      }
    } catch (err) {
      error("Clear Cache Failed", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsClearingCache(false);
    }
  };

  const handleActionClick = (service: string, action: ServiceAction) => {
    setSelectedService(service);
    setSelectedAction(action);
    setDialogOpen(true);
  };

  const handleActionConfirm = async () => {
    if (!selectedService) return;

    try {
      let result;
      switch (selectedAction) {
        case "start":
          result = await startService.mutateAsync(selectedService);
          break;
        case "stop":
          result = await stopService.mutateAsync(selectedService);
          break;
        case "restart":
          result = await restartService.mutateAsync(selectedService);
          break;
      }
      if (result.success) {
        const actionLabels = { start: "Started", stop: "Stopped", restart: "Restarted" };
        success(`Service ${actionLabels[selectedAction]}`, `${selectedService} has been ${actionLabels[selectedAction].toLowerCase()}`);
      } else {
        error(`${selectedAction.charAt(0).toUpperCase() + selectedAction.slice(1)} Failed`, result.message);
      }
    } catch (err) {
      error(`${selectedAction.charAt(0).toUpperCase() + selectedAction.slice(1)} Failed`, err instanceof Error ? err.message : "Unknown error");
    }
    setDialogOpen(false);
    setSelectedService(null);
  };


  // Only show loading skeleton on initial load, not on refetch
  const showStatusSkeleton = statusLoading && !status;
  const showEventsSkeleton = eventsLoading && !eventsData;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Watchdog</h1>
        {status && (
          <Badge variant={getHealthBadge(overallHealth).variant}>
            {getHealthBadge(overallHealth).label}
          </Badge>
        )}
      </div>

      {/* Overview Stats */}
      {showStatusSkeleton ? (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardHeader title="Components" />
            <div className="text-3xl font-bold text-gray-100">{components.length}</div>
            <p className="text-sm text-gray-400 mt-1">Total monitored</p>
          </Card>
          <Card>
            <CardHeader title="Running" />
            <div className="text-3xl font-bold text-green-400">
              {components.filter((c) => c.status === "ok").length}
            </div>
            <p className="text-sm text-gray-400 mt-1">Healthy components</p>
          </Card>
          <Card>
            <CardHeader title="Services" />
            <div className="text-3xl font-bold text-orange-400">{services.length}</div>
            <p className="text-sm text-gray-400 mt-1">Active services</p>
          </Card>
          <Card>
            <CardHeader title="Errors" />
            <div className="text-3xl font-bold text-red-400">
              {components.filter((c) => c.status === "error" || c.status === "unknown").length}
            </div>
            <p className="text-sm text-gray-400 mt-1">Components with issues</p>
          </Card>
        </div>
      )}

      {/* Resource Monitoring */}
      <Card>
        <CardHeader
          title="Resource Monitor"
          subtitle="CPU, memory, and disk usage monitoring"
          action={
            <div className="flex items-center gap-2">
              {resourceStatus && (
                <Badge variant={getResourceBadge(resourceStatus.status).variant}>
                  {getResourceBadge(resourceStatus.status).label}
                </Badge>
              )}
              <Button
                variant="secondary"
                size="sm"
                onClick={handleClearCache}
                loading={isClearingCache}
              >
                Clear Cache
              </Button>
            </div>
          }
        />
        {resourceLoading && !resourceStatus ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
          </div>
        ) : resourceStatus ? (
          <div className="space-y-4">
            {/* Resource Bars */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* CPU */}
              <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-gray-400 text-sm">CPU Usage</span>
                  <span className={`font-mono font-bold ${
                    resourceStatus.cpu_percent >= resourceStatus.critical_threshold_cpu
                      ? "text-red-400"
                      : resourceStatus.cpu_percent >= resourceStatus.warning_threshold_cpu
                      ? "text-yellow-400"
                      : "text-green-400"
                  }`}>
                    {resourceStatus.cpu_percent.toFixed(1)}%
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full transition-all duration-300 ${
                      resourceStatus.cpu_percent >= resourceStatus.critical_threshold_cpu
                        ? "bg-red-500"
                        : resourceStatus.cpu_percent >= resourceStatus.warning_threshold_cpu
                        ? "bg-yellow-500"
                        : "bg-green-500"
                    }`}
                    style={{ width: `${Math.min(resourceStatus.cpu_percent, 100)}%` }}
                  />
                </div>
                <div className="flex justify-between mt-1 text-xs text-gray-500">
                  <span>Warning: {resourceStatus.warning_threshold_cpu}%</span>
                  <span>Critical: {resourceStatus.critical_threshold_cpu}%</span>
                </div>
              </div>

              {/* Memory */}
              <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-gray-400 text-sm">Memory Usage</span>
                  <span className={`font-mono font-bold ${
                    resourceStatus.memory_percent >= resourceStatus.critical_threshold_memory
                      ? "text-red-400"
                      : resourceStatus.memory_percent >= resourceStatus.warning_threshold_memory
                      ? "text-yellow-400"
                      : "text-green-400"
                  }`}>
                    {resourceStatus.memory_percent.toFixed(1)}%
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full transition-all duration-300 ${
                      resourceStatus.memory_percent >= resourceStatus.critical_threshold_memory
                        ? "bg-red-500"
                        : resourceStatus.memory_percent >= resourceStatus.warning_threshold_memory
                        ? "bg-yellow-500"
                        : "bg-green-500"
                    }`}
                    style={{ width: `${Math.min(resourceStatus.memory_percent, 100)}%` }}
                  />
                </div>
                <div className="flex justify-between mt-1 text-xs text-gray-500">
                  <span>{resourceStatus.memory_used_mb.toLocaleString()} / {resourceStatus.memory_total_mb.toLocaleString()} MB</span>
                </div>
              </div>

              {/* Disk */}
              <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-gray-400 text-sm">Disk Usage</span>
                  <span className={`font-mono font-bold ${
                    resourceStatus.disk_percent >= 90
                      ? "text-red-400"
                      : resourceStatus.disk_percent >= 75
                      ? "text-yellow-400"
                      : "text-green-400"
                  }`}>
                    {resourceStatus.disk_percent.toFixed(1)}%
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full transition-all duration-300 ${
                      resourceStatus.disk_percent >= 90
                        ? "bg-red-500"
                        : resourceStatus.disk_percent >= 75
                        ? "bg-yellow-500"
                        : "bg-green-500"
                    }`}
                    style={{ width: `${Math.min(resourceStatus.disk_percent, 100)}%` }}
                  />
                </div>
                <div className="flex justify-between mt-1 text-xs text-gray-500">
                  <span>{resourceStatus.disk_used_gb.toLocaleString()} / {resourceStatus.disk_total_gb.toLocaleString()} GB</span>
                </div>
              </div>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-3 bg-gray-800/30 rounded-lg">
                <div className="text-gray-500 text-xs">Connected Miners</div>
                <div className="text-lg font-bold text-gray-100">{resourceStatus.connected_miners.toLocaleString()}</div>
              </div>
              <div className="p-3 bg-gray-800/30 rounded-lg">
                <div className="text-gray-500 text-xs">Est. Capacity</div>
                <div className="text-lg font-bold text-gray-100">{resourceStatus.estimated_capacity.toLocaleString()}</div>
              </div>
              <div className="p-3 bg-gray-800/30 rounded-lg">
                <div className="text-gray-500 text-xs">Miner Capacity Used</div>
                <div className="text-lg font-bold text-gray-100">
                  {resourceStatus.estimated_capacity > 0
                    ? ((resourceStatus.connected_miners / resourceStatus.estimated_capacity) * 100).toFixed(1)
                    : 0}%
                </div>
              </div>
              <div className="p-3 bg-gray-800/30 rounded-lg">
                <div className="text-gray-500 text-xs">Last Redirect</div>
                <div className="text-lg font-bold text-gray-100">
                  {resourceStatus.last_redirect_secs_ago !== null && resourceStatus.last_redirect_secs_ago !== undefined
                    ? `${Math.floor(resourceStatus.last_redirect_secs_ago / 60)}m ago (${resourceStatus.last_redirect_count})`
                    : "Never"}
                </div>
              </div>
            </div>

            {/* Warning/Critical Info */}
            {resourceStatus.status === "warning" && (
              <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded-lg">
                <p className="text-yellow-400 text-sm">
                  Resource usage is elevated. If usage continues to increase, low-hashrate miners may be redirected to other nodes.
                </p>
              </div>
            )}
            {resourceStatus.status === "critical" && (
              <div className="p-3 bg-red-900/20 border border-red-800 rounded-lg">
                <p className="text-red-400 text-sm">
                  Resource usage is critical! Low-hashrate miners are being redirected to other nodes to reduce load.
                </p>
              </div>
            )}
          </div>
        ) : (
          <div className="text-center py-8">
            <p className="text-gray-400">Resource monitoring unavailable</p>
          </div>
        )}
      </Card>

      {/* Services Status */}
      {services.length > 0 && (
        <Card>
          <CardHeader
            title="Service Status"
            subtitle="High-level service status overview"
          />
          <div className="space-y-3">
            {services.map((service) => {
              const statusBadge = getStatusBadge(service.status);
              return (
                <div
                  key={service.name}
                  className="p-4 bg-gray-800/50 rounded-lg border border-gray-700"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-gray-100 font-medium">{service.name}</span>
                      <Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
                    </div>
                    <div className="flex gap-2">
                      {service.status === "stopped" || service.status === "error" ? (
                        <Button
                          size="sm"
                          variant="success"
                          onClick={() => handleActionClick(service.name, "start")}
                          disabled={isPending}
                        >
                          Start
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="danger"
                          onClick={() => handleActionClick(service.name, "stop")}
                          disabled={isPending}
                        >
                          Stop
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleActionClick(service.name, "restart")}
                        disabled={isPending}
                      >
                        Restart
                      </Button>
                    </div>
                  </div>
                  {service.details && Object.keys(service.details).length > 0 && (
                    <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      {Object.entries(service.details).map(([key, value]) => (
                        <div key={key}>
                          <span className="text-gray-500">{key}: </span>
                          <span className="text-gray-300">
                            {typeof value === "number"
                              ? value.toLocaleString()
                              : String(value)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* Components Health Table */}
      <Card>
        <CardHeader
          title="Component Health"
          subtitle="Real-time status of all node components"
        />
        {showStatusSkeleton ? (
          <SkeletonTable rows={7} cols={5} />
        ) : components.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-gray-400">No components registered</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="pb-3 text-gray-400 font-medium">Component</th>
                  <th className="pb-3 text-gray-400 font-medium">Port</th>
                  <th className="pb-3 text-gray-400 font-medium">Status</th>
                  <th className="pb-3 text-gray-400 font-medium">PID</th>
                  <th className="pb-3 text-gray-400 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {components.map((component) => {
                  const statusBadge = getStatusBadge(component.status);
                  return (
                    <tr
                      key={component.name}
                      className="border-b border-gray-800/50 hover:bg-gray-800/30"
                    >
                      <td className="py-3">
                        <div>
                          <div className="text-gray-100 font-medium">{component.name}</div>
                          {component.process_name && (
                            <div className="text-xs text-gray-500">{component.process_name}</div>
                          )}
                        </div>
                      </td>
                      <td className="py-3">
                        <code className="text-orange-400">{component.port}</code>
                      </td>
                      <td className="py-3">
                        <Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
                      </td>
                      <td className="py-3">
                        <code className="text-gray-400">{component.pid ?? "N/A"}</code>
                      </td>
                      <td className="py-3">
                        <div className="flex gap-2">
                          {component.status === "error" || component.status === "unknown" ? (
                            <Button
                              size="sm"
                              variant="success"
                              onClick={() => handleActionClick(component.name, "start")}
                              disabled={isPending}
                            >
                              Start
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              variant="danger"
                              onClick={() => handleActionClick(component.name, "stop")}
                              disabled={isPending}
                            >
                              Stop
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => handleActionClick(component.name, "restart")}
                            disabled={isPending}
                          >
                            Restart
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Recent Events */}
      <Card>
        <CardHeader
          title="Recent Events"
          subtitle={`${events.length} events recorded`}
        />
        {showEventsSkeleton ? (
          <SkeletonTable rows={10} cols={4} />
        ) : events.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-gray-400">No events recorded</p>
          </div>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {events.map((event, idx) => {
              const eventBadge = getEventBadge((event.event_type ?? "warning") as "warning" | "restart" | "failure" | "recovery");
              return (
                <div
                  key={`${event.timestamp}-${idx}`}
                  className={`p-3 rounded-lg border ${
                    event.event_type === "failure"
                      ? "bg-red-900/10 border-red-800/50"
                      : event.event_type === "recovery"
                      ? "bg-green-900/10 border-green-800/50"
                      : event.event_type === "warning"
                      ? "bg-yellow-900/10 border-yellow-800/50"
                      : "bg-gray-800/30 border-gray-700/50"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Badge variant={eventBadge.variant}>{eventBadge.label}</Badge>
                    <span className="text-gray-100 font-medium">{event.service}</span>
                    <span className="text-gray-500 text-sm ml-auto">
                      {formatTimestamp(event.timestamp ?? 0)}
                    </span>
                  </div>
                  <p className="text-gray-400 text-sm mt-1">{event.message}</p>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Info Card */}
      <Card>
        <div className="p-4 bg-orange-900/20 border border-orange-800 rounded-lg">
          <h4 className="text-orange-300 font-medium mb-2">About Watchdog</h4>
          <ul className="text-sm text-orange-300/80 space-y-1 list-disc list-inside">
            <li>Watchdog monitors all Ghost node components in real-time</li>
            <li>Components are automatically restarted if they crash</li>
            <li>Use the Restart button to manually restart a component</li>
            <li>Events are recorded for auditing and troubleshooting</li>
            <li>Health checks run every 5 seconds</li>
          </ul>
        </div>
      </Card>

      {/* Service Action Confirmation Dialog */}
      <Dialog
        isOpen={dialogOpen}
        onClose={() => {
          setDialogOpen(false);
          setSelectedService(null);
        }}
        title={`${selectedAction.charAt(0).toUpperCase() + selectedAction.slice(1)} Service`}
      >
        <div className="space-y-4">
          <p className="text-gray-300">
            Are you sure you want to {selectedAction} <strong className="text-white">{selectedService}</strong>?
          </p>
          <div className={`p-3 rounded border ${
            selectedAction === "stop"
              ? "bg-red-900/20 border-red-800"
              : selectedAction === "start"
              ? "bg-green-900/20 border-green-800"
              : "bg-yellow-900/20 border-yellow-800"
          }`}>
            <p className={`text-sm ${
              selectedAction === "stop"
                ? "text-red-400"
                : selectedAction === "start"
                ? "text-green-400"
                : "text-yellow-400"
            }`}>
              {selectedAction === "stop"
                ? "This will stop the service. It will not automatically restart until started manually."
                : selectedAction === "start"
                ? "This will start the service if it is currently stopped."
                : "This will temporarily interrupt the service. Any in-progress operations may be affected."}
            </p>
          </div>
          <div className="flex gap-3 pt-4 border-t border-gray-800">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => {
                setDialogOpen(false);
                setSelectedService(null);
              }}
            >
              Cancel
            </Button>
            <Button
              variant={selectedAction === "stop" ? "danger" : selectedAction === "start" ? "success" : "warning"}
              className="flex-1"
              onClick={handleActionConfirm}
              loading={isPending}
            >
              {selectedAction.charAt(0).toUpperCase() + selectedAction.slice(1)}
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
