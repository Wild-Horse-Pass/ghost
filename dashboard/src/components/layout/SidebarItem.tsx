'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ReactNode } from 'react';

interface SidebarItemProps {
  href: string;
  icon: ReactNode;
  label: string;
  collapsed?: boolean;
}

export function SidebarItem({ href, icon, label, collapsed = false }: SidebarItemProps) {
  const pathname = usePathname();
  const isActive = pathname === href || (href !== '/' && pathname.startsWith(href));

  return (
    <Link
      href={href}
      className={`
        flex items-center gap-3 px-3 py-2 rounded-lg transition-colors
        ${isActive
          ? 'bg-green-600/20 text-green-400 border border-green-600/30'
          : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
        }
        ${collapsed ? 'justify-center' : ''}
      `}
      title={collapsed ? label : undefined}
    >
      <span className="flex-shrink-0 w-5 h-5">{icon}</span>
      {!collapsed && <span className="text-sm font-medium">{label}</span>}
    </Link>
  );
}
