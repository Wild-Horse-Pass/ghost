interface WizardStepperProps {
  steps: string[];
  currentStep: number;
}

export default function WizardStepper({ steps, currentStep }: WizardStepperProps) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        marginBottom: 32,
        gap: 0,
      }}
    >
      {steps.map((label, i) => {
        const isCompleted = i < currentStep;
        const isActive = i === currentStep;
        const isFuture = i > currentStep;

        return (
          <div key={i} style={{ display: "flex", alignItems: "center" }}>
            {/* Step circle + label */}
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: 80 }}>
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: "50%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 13,
                  fontWeight: 700,
                  background: isCompleted
                    ? "var(--success)"
                    : isActive
                    ? "var(--accent)"
                    : "var(--bg-tertiary)",
                  color: isCompleted || isActive ? "#fff" : "var(--text-muted)",
                  border: isFuture ? "1px solid var(--border)" : "none",
                  transition: "all 0.2s ease",
                }}
              >
                {isCompleted ? "\u2713" : i + 1}
              </div>
              <div
                style={{
                  marginTop: 6,
                  fontSize: 11,
                  fontWeight: 500,
                  color: isActive
                    ? "var(--accent)"
                    : isCompleted
                    ? "var(--success)"
                    : "var(--text-muted)",
                  textAlign: "center",
                  whiteSpace: "nowrap",
                }}
              >
                {label}
              </div>
            </div>

            {/* Connector line */}
            {i < steps.length - 1 && (
              <div
                style={{
                  width: 40,
                  height: 2,
                  background: i < currentStep ? "var(--success)" : "var(--border)",
                  marginBottom: 18,
                  transition: "background 0.2s ease",
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
