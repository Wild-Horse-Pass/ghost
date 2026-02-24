interface FlowDiagramStep {
  label: string;
  sublabel: string;
  accent?: boolean;
}

const ACCENT_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  orange: { bg: "bg-orange-900/10", border: "border-orange-600/30", text: "text-orange-400" },
  blue:   { bg: "bg-blue-900/10",   border: "border-blue-600/30",   text: "text-blue-400" },
  red:    { bg: "bg-red-900/10",    border: "border-red-600/30",    text: "text-red-400" },
  green:  { bg: "bg-green-900/10",  border: "border-green-600/30",  text: "text-green-400" },
  purple: { bg: "bg-purple-900/10", border: "border-purple-600/30", text: "text-purple-400" },
};

function FlowArrow() {
  return (
    <div className="flex items-center px-1 text-gray-600 flex-shrink-0">
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
      </svg>
    </div>
  );
}

interface FlowDiagramProps {
  steps: FlowDiagramStep[];
  accentColor?: string;
}

export function FlowDiagram({ steps, accentColor = "blue" }: FlowDiagramProps) {
  const colors = ACCENT_COLORS[accentColor] ?? ACCENT_COLORS.blue;

  return (
    <div className="flex items-center gap-0 overflow-x-auto pb-2">
      {steps.map((step, i) => (
        <div key={i} className="contents">
          {i > 0 && <FlowArrow />}
          <div className={`flex-1 text-center px-3 py-4 rounded-lg border ${
            step.accent
              ? `${colors.bg} ${colors.border}`
              : "bg-gray-800/50 border-gray-700"
          }`}>
            <div className={`text-sm font-medium ${step.accent ? colors.text : "text-gray-100"}`}>
              {step.label}
            </div>
            <div className="text-xs text-gray-500 mt-1">{step.sublabel}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
