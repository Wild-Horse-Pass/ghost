interface ProgressBarProps {
  value: number;
  max?: number;
  label?: string;
  sublabel?: string;
  color?: 'orange' | 'green' | 'blue' | 'red' | 'yellow' | 'gray';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const colorClasses = {
  orange: 'bg-orange-500',
  green: 'bg-green-500',
  blue: 'bg-blue-500',
  red: 'bg-red-500',
  yellow: 'bg-yellow-500',
  gray: 'bg-gray-500',
};

const sizeClasses = {
  sm: 'h-1.5',
  md: 'h-2.5',
  lg: 'h-4',
};

export function ProgressBar({
  value,
  max = 100,
  label,
  sublabel,
  color = 'orange',
  size = 'md',
  className = '',
}: ProgressBarProps) {
  const percent = max > 0 ? Math.min((value / max) * 100, 100) : 0;

  return (
    <div className={className}>
      {(label || sublabel) && (
        <div className="flex justify-between items-center mb-1.5">
          {label && <span className="text-sm text-gray-400">{label}</span>}
          {sublabel && <span className="text-sm text-gray-300 font-mono">{sublabel}</span>}
        </div>
      )}
      <div className={`bg-gray-800 rounded-full overflow-hidden ${sizeClasses[size]}`}>
        <div
          className={`${colorClasses[color]} rounded-full transition-all duration-500 h-full`}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}
