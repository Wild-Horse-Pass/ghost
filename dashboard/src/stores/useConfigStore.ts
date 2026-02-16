import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface MempoolProfile {
  name: string;
  minFeeRate: number;
  maxTxSize: number;
  acceptT0: boolean;
  acceptT1: boolean;
  acceptT2: boolean;
  acceptT3: boolean;
}

interface TemplateProfile {
  name: string;
  includeT0: boolean;
  includeT1: boolean;
  includeT2: boolean;
  includeT3: boolean;
  priorityOrder: ('t0' | 't1' | 't2' | 't3')[];
}

interface ConfigState {
  // Node identity
  nickname: string;

  // Current settings
  ghostMode: boolean;
  archiveMode: boolean;
  publicMining: boolean;

  // Profiles
  currentMempoolProfile: string;
  currentTemplateProfile: string;
  customMempoolProfiles: MempoolProfile[];
  customTemplateProfiles: TemplateProfile[];

  // Actions
  setNickname: (nickname: string) => void;
  setGhostMode: (enabled: boolean) => void;
  setArchiveMode: (enabled: boolean) => void;
  setPublicMining: (enabled: boolean) => void;
  setCurrentMempoolProfile: (name: string) => void;
  setCurrentTemplateProfile: (name: string) => void;
  addMempoolProfile: (profile: MempoolProfile) => void;
  removeMempoolProfile: (name: string) => void;
  addTemplateProfile: (profile: TemplateProfile) => void;
  removeTemplateProfile: (name: string) => void;
}

export const useConfigStore = create<ConfigState>()(
  persist(
    (set) => ({
      nickname: '',
      ghostMode: false,
      archiveMode: false,
      publicMining: false,
      currentMempoolProfile: 'standard',
      currentTemplateProfile: 'max-fee',
      customMempoolProfiles: [],
      customTemplateProfiles: [],

      setNickname: (nickname) => set({ nickname }),
      setGhostMode: (ghostMode) => set({ ghostMode }),
      setArchiveMode: (archiveMode) => set({ archiveMode }),
      setPublicMining: (publicMining) => set({ publicMining }),
      setCurrentMempoolProfile: (currentMempoolProfile) => set({ currentMempoolProfile }),
      setCurrentTemplateProfile: (currentTemplateProfile) => set({ currentTemplateProfile }),

      addMempoolProfile: (profile) => set((state) => ({
        customMempoolProfiles: [
          ...state.customMempoolProfiles.filter(p => p.name !== profile.name),
          profile
        ]
      })),

      removeMempoolProfile: (name) => set((state) => ({
        customMempoolProfiles: state.customMempoolProfiles.filter(p => p.name !== name)
      })),

      addTemplateProfile: (profile) => set((state) => ({
        customTemplateProfiles: [
          ...state.customTemplateProfiles.filter(p => p.name !== profile.name),
          profile
        ]
      })),

      removeTemplateProfile: (name) => set((state) => ({
        customTemplateProfiles: state.customTemplateProfiles.filter(p => p.name !== name)
      })),
    }),
    {
      name: 'ghost-node-config',
      partialize: (state) => ({
        nickname: state.nickname,
        customMempoolProfiles: state.customMempoolProfiles,
        customTemplateProfiles: state.customTemplateProfiles,
      }),
    }
  )
);

export type { MempoolProfile, TemplateProfile };
