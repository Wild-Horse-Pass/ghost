'use client';

import type { PayoutHistoryTimeFilter } from '@/types/api';

interface TimeFilterProps {
  value: PayoutHistoryTimeFilter;
  onChange: (value: PayoutHistoryTimeFilter) => void;
  options?: PayoutHistoryTimeFilter[];
  className?: string;
}

const LABELS: Record<PayoutHistoryTimeFilter, string> = {
  '24h': '24h',
  '7d': '7d',
  all: 'All',
};

export function TimeFilter({
  value,
  onChange,
  options = ['24h', '7d', 'all'],
  className = '',
}: TimeFilterProps) {
  return (
    <div className={`inline-flex bg-gray-800 rounded-lg p-0.5 ${className}`}>
      {options.map((opt) => (
        <button
          key={opt}
          onClick={() => onChange(opt)}
          className={`
            px-3 py-1 text-sm rounded-md transition-colors
            ${value === opt
              ? 'bg-gray-700 text-gray-100 font-medium'
              : 'text-gray-400 hover:text-gray-200'
            }
          `}
        >
          {LABELS[opt]}
        </button>
      ))}
    </div>
  );
}
