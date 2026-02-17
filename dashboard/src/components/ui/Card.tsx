'use client';

import { ReactNode, useState } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
}

export function Card({ children, className = '', collapsible, defaultCollapsed = false }: CardProps) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);

  if (!collapsible) {
    return (
      <div className={`bg-gray-900 border border-gray-800 rounded-lg p-6 ${className}`}>
        {children}
      </div>
    );
  }

  // When collapsible, the first child should be a CardHeader — we render all children
  // but hide non-header content when collapsed
  return (
    <div className={`bg-gray-900 border border-gray-800 rounded-lg p-6 ${className}`}>
      <div
        className="cursor-pointer select-none"
        onClick={() => setCollapsed(!collapsed)}
      >
        <div className="flex items-center justify-between">
          <div className="flex-1">{/* CardHeader rendered by children */}</div>
          <svg
            className={`w-5 h-5 text-gray-400 transition-transform flex-shrink-0 ml-2 ${collapsed ? '' : 'rotate-180'}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>
      {!collapsed && <div className="mt-4">{children}</div>}
    </div>
  );
}

interface CardHeaderProps {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}

export function CardHeader({ title, subtitle, action }: CardHeaderProps) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div>
        <h3 className="text-lg font-semibold text-gray-100">{title}</h3>
        {subtitle && <p className="text-sm text-gray-400">{subtitle}</p>}
      </div>
      {action && <div>{action}</div>}
    </div>
  );
}
