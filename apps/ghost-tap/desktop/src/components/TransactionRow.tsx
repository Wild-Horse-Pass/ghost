import { formatGhost, formatTimestamp, type HistoryEntry } from "../api/commands";

interface Props {
  entry: HistoryEntry;
}

export default function TransactionRow({ entry }: Props) {
  const isIncoming = entry.direction === "Incoming";

  return (
    <tr>
      <td>
        <span style={{ color: isIncoming ? "var(--success)" : "var(--danger)" }}>
          {isIncoming ? "\u2193" : "\u2191"}
        </span>{" "}
        {isIncoming ? "Received" : "Sent"}
      </td>
      <td style={{ fontWeight: 600 }}>
        <span style={{ color: isIncoming ? "var(--success)" : "var(--danger)" }}>
          {isIncoming ? "+" : "-"}
          {formatGhost(entry.amount)}
        </span>{" "}
        <span style={{ color: "var(--text-muted)", fontSize: 11 }}>GHOST</span>
      </td>
      <td className="mono truncate" style={{ maxWidth: 160 }}>
        {entry.address}
      </td>
      <td>
        <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
          {entry.status}
        </span>
      </td>
      <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>
        {formatTimestamp(entry.timestamp)}
      </td>
    </tr>
  );
}
