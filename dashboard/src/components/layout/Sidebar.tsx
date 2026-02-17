'use client';

import { useUIStore, useConfigStore } from '@/stores';
import { useNodeStore } from '@/stores';
import { SidebarItem } from './SidebarItem';
import { GhostLogo, GhostIcon } from '@/components/ui/GhostLogo';
import { StatusDot } from '@/components/ui/StatusDot';

// Icons
const HomeIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" />
  </svg>
);

const MiningIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 002.25-2.25V6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 6.75v10.5a2.25 2.25 0 002.25 2.25zm.75-12h9v9h-9v-9z" />
  </svg>
);

const RewardsIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v12m-3-2.818l.879.659c1.171.879 3.07.879 4.242 0 1.172-.879 1.172-2.303 0-3.182C13.536 12.219 12.768 12 12 12c-.725 0-1.45-.22-2.003-.659-1.106-.879-1.106-2.303 0-3.182s2.9-.879 4.006 0l.415.33M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const GhostPayIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 18.75a60.07 60.07 0 0115.797 2.101c.727.198 1.453-.342 1.453-1.096V18.75M3.75 4.5v.75A.75.75 0 013 6h-.75m0 0v-.375c0-.621.504-1.125 1.125-1.125H20.25M2.25 6v9m18-10.5v.75c0 .414.336.75.75.75h.75m-1.5-1.5h.375c.621 0 1.125.504 1.125 1.125v9.75c0 .621-.504 1.125-1.125 1.125h-.375m1.5-1.5H21a.75.75 0 00-.75.75v.75m0 0H3.75m0 0h-.375a1.125 1.125 0 01-1.125-1.125V15m1.5 1.5v-.75A.75.75 0 003 15h-.75M15 10.5a3 3 0 11-6 0 3 3 0 016 0zm3 0h.008v.008H18V10.5zm-12 0h.008v.008H6V10.5z" />
  </svg>
);

const NetworkIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
  </svg>
);

const WatchdogIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
  </svg>
);

const SwarmIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z" />
  </svg>
);

const LogsIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
  </svg>
);

const SystemIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />
  </svg>
);

const SettingsIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
  </svg>
);

const ChevronLeftIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
  </svg>
);

const MenuIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
  </svg>
);

const CloseIcon = () => (
  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
  </svg>
);

function SidebarLabel({ children, collapsed }: { children: string; collapsed: boolean }) {
  if (collapsed) return null;
  return (
    <div className="px-3 pt-4 pb-1">
      <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-600">{children}</span>
    </div>
  );
}

export function Sidebar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const mobileOpen = useUIStore((s) => s.sidebarMobileOpen);
  const toggle = useUIStore((s) => s.toggleSidebar);
  const setMobileOpen = useUIStore((s) => s.setSidebarMobileOpen);
  const nickname = useConfigStore((s) => s.nickname);
  const isConnected = useNodeStore((s) => s.isConnected);

  return (
    <>
      {/* Mobile hamburger button */}
      <button
        onClick={() => setMobileOpen(true)}
        className="fixed top-3 left-3 z-40 p-2 rounded-lg bg-gray-900 border border-gray-800 text-gray-400 hover:text-gray-200 md:hidden"
        aria-label="Open menu"
      >
        <div className="w-5 h-5"><MenuIcon /></div>
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          flex flex-col border-r border-gray-800 bg-gray-900/95 backdrop-blur-sm transition-all duration-300 ease-in-out
          fixed md:relative inset-y-0 left-0 z-50
          ${mobileOpen ? 'translate-x-0 w-64' : '-translate-x-full md:translate-x-0'}
          ${collapsed ? 'md:w-16' : 'md:w-56'}
        `}
      >
        {/* Header */}
        <div className="flex h-14 items-center justify-between px-3 border-b border-gray-800">
          {collapsed ? (
            <button
              onClick={toggle}
              className="flex justify-center w-full hover:opacity-80 transition-opacity"
              title="Expand sidebar"
            >
              <GhostIcon size={28} />
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <GhostLogo size={32} />
              <div className="flex flex-col min-w-0">
                <span className="text-sm font-semibold text-gray-100">Ghost Node</span>
                {nickname && (
                  <span className="text-xs text-gray-500 truncate">{nickname}</span>
                )}
              </div>
            </div>
          )}
          {!collapsed && (
            <button
              onClick={() => {
                if (mobileOpen) setMobileOpen(false);
                else toggle();
              }}
              className="p-1.5 text-gray-400 hover:text-gray-200 rounded-lg hover:bg-gray-800 transition-colors"
              title={mobileOpen ? 'Close menu' : 'Collapse sidebar'}
            >
              <div className="w-4 h-4">
                {mobileOpen ? <CloseIcon /> : <ChevronLeftIcon />}
              </div>
            </button>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-2 overflow-y-auto">
          {/* Primary */}
          <SidebarLabel collapsed={collapsed}>Primary</SidebarLabel>
          <div className="space-y-0.5">
            <SidebarItem href="/" icon={<HomeIcon />} label="Overview" collapsed={collapsed} />
            <SidebarItem href="/mining" icon={<MiningIcon />} label="Mining" collapsed={collapsed} />
            <SidebarItem href="/rewards" icon={<RewardsIcon />} label="Rewards" collapsed={collapsed} />
          </div>

          {/* Features */}
          <SidebarLabel collapsed={collapsed}>Features</SidebarLabel>
          <div className="space-y-0.5">
            <SidebarItem href="/ghost-pay" icon={<GhostPayIcon />} label="Ghost Pay" collapsed={collapsed} />
            <SidebarItem href="/network" icon={<NetworkIcon />} label="Network" collapsed={collapsed} />
          </div>

          {/* Operations */}
          <SidebarLabel collapsed={collapsed}>Operations</SidebarLabel>
          <div className="space-y-0.5">
            <SidebarItem href="/watchdog" icon={<WatchdogIcon />} label="Watchdog" collapsed={collapsed} />
            <SidebarItem href="/swarm" icon={<SwarmIcon />} label="Swarm" collapsed={collapsed} />
            <SidebarItem href="/logs" icon={<LogsIcon />} label="Logs" collapsed={collapsed} />
          </div>

          {/* Bottom section */}
          <div className="mt-auto pt-2 border-t border-gray-800 mt-4">
            <div className="space-y-0.5">
              <SidebarItem href="/system" icon={<SystemIcon />} label="System" collapsed={collapsed} />
              <SidebarItem href="/settings" icon={<SettingsIcon />} label="Settings" collapsed={collapsed} />
            </div>
          </div>
        </nav>

        {/* Footer - Connection Status */}
        <div className="p-3 border-t border-gray-800">
          {collapsed ? (
            <div className="flex justify-center">
              <StatusDot
                status={isConnected ? 'online' : 'offline'}
                pulse={isConnected}
                size="sm"
              />
            </div>
          ) : (
            <StatusDot
              status={isConnected ? 'online' : 'offline'}
              pulse={isConnected}
              label={isConnected ? 'Connected' : 'Disconnected'}
              size="sm"
            />
          )}
        </div>
      </aside>
    </>
  );
}
