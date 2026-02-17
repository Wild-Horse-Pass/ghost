import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface DialogData {
  [key: string]: unknown;
}

// Predefined accent colors (black base + accent)
export const ACCENT_COLORS = {
  orange: { name: 'Ghost Orange', hex: '#f97316', rgb: '249, 115, 22' },
  green: { name: 'Matrix Green', hex: '#22c55e', rgb: '34, 197, 94' },
  blue: { name: 'Electric Blue', hex: '#3b82f6', rgb: '59, 130, 246' },
  purple: { name: 'Phantom Purple', hex: '#a855f7', rgb: '168, 85, 247' },
  red: { name: 'Blood Red', hex: '#ef4444', rgb: '239, 68, 68' },
  cyan: { name: 'Cyber Cyan', hex: '#06b6d4', rgb: '6, 182, 212' },
  yellow: { name: 'Warning Yellow', hex: '#eab308', rgb: '234, 179, 8' },
  pink: { name: 'Neon Pink', hex: '#ec4899', rgb: '236, 72, 153' },
} as const;

export type AccentColorKey = keyof typeof ACCENT_COLORS;

interface UIState {
  // Sidebar
  sidebarCollapsed: boolean;
  sidebarMobileOpen: boolean;

  // Dialogs/Modals
  activeDialog: string | null;
  dialogData: DialogData | null;

  // Theme
  theme: 'dark' | 'light';
  accentColor: AccentColorKey;

  // Tooltips
  tooltipsEnabled: boolean;

  // Actions
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setSidebarMobileOpen: (open: boolean) => void;
  openDialog: (id: string, data?: DialogData) => void;
  closeDialog: () => void;
  setTheme: (theme: 'dark' | 'light') => void;
  setAccentColor: (color: AccentColorKey) => void;
  setTooltipsEnabled: (enabled: boolean) => void;
  toggleTooltips: () => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      sidebarMobileOpen: false,
      activeDialog: null,
      dialogData: null,
      theme: 'dark',
      accentColor: 'orange',
      tooltipsEnabled: true,

      toggleSidebar: () => set((state) => ({
        sidebarCollapsed: !state.sidebarCollapsed
      })),

      setSidebarCollapsed: (sidebarCollapsed) => set({ sidebarCollapsed }),

      setSidebarMobileOpen: (sidebarMobileOpen) => set({ sidebarMobileOpen }),

      openDialog: (activeDialog, dialogData) => set({
        activeDialog,
        dialogData: dialogData ?? null
      }),

      closeDialog: () => set({
        activeDialog: null,
        dialogData: null
      }),

      setTheme: (theme) => set({ theme }),

      setAccentColor: (accentColor) => set({ accentColor }),

      setTooltipsEnabled: (tooltipsEnabled) => set({ tooltipsEnabled }),
      toggleTooltips: () => set((state) => ({ tooltipsEnabled: !state.tooltipsEnabled })),
    }),
    {
      name: 'ghost-node-ui',
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
        theme: state.theme,
        accentColor: state.accentColor,
        tooltipsEnabled: state.tooltipsEnabled,
      }),
    }
  )
);

// Helper hooks for common patterns
export const useDialog = () => {
  const activeDialog = useUIStore((state) => state.activeDialog);
  const dialogData = useUIStore((state) => state.dialogData);
  const openDialog = useUIStore((state) => state.openDialog);
  const closeDialog = useUIStore((state) => state.closeDialog);

  return {
    activeDialog,
    dialogData,
    openDialog,
    closeDialog,
    isOpen: (id: string) => activeDialog === id,
  };
};
