'use client';

import { ReactNode } from 'react';
import { Skeleton } from './Skeleton';
import { Tooltip } from './Tooltip';

interface StatCardProps {
  label: string;
  value: string | number;
  tooltip?: string;
  icon?: ReactNode;
  sublabel?: string;
  loading?: boolean;
  className?: string;
}

export function StatCard({ label, value, tooltip, icon, sublabel, loading, className = '' }: StatCardProps) {
  if (loading) {
    return (
      <div className={`bg-gray-900 border border-gray-800 rounded-lg p-4 h-[104px] ${className}`}>
        <Skeleton className="h-4 w-20 mb-3" />
        <Skeleton className="h-7 w-24 mb-1" />
        <Skeleton className="h-3 w-16" />
      </div>
    );
  }

  const content = (
    <div className={`bg-gray-900 border border-gray-800 rounded-lg p-4 h-[104px] flex flex-col justify-between ${className}`}>
      <div className="flex items-center gap-2 text-sm text-gray-400">
        {icon && <span className="w-4 h-4 flex-shrink-0">{icon}</span>}
        <span className="truncate">{label}</span>
      </div>
      <div>
        <div className="text-2xl font-bold text-gray-100 truncate">{value}</div>
        {sublabel && <div className="text-xs text-gray-500 truncate">{sublabel}</div>}
      </div>
    </div>
  );

  if (tooltip) {
    return <Tooltip content={tooltip}>{content}</Tooltip>;
  }

  return content;
}
