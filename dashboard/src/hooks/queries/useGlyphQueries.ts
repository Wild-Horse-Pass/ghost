import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getGlyph, checkGlyphAvailability, claimGlyph } from '@/lib/api/glyph';

export const glyphKeys = {
  all: ['glyph'] as const,
  info: (ghostId: string) => [...glyphKeys.all, 'info', ghostId] as const,
  availability: (hash: string) => [...glyphKeys.all, 'availability', hash] as const,
};

export function useGlyphInfo(ghostId: string) {
  return useQuery({
    queryKey: glyphKeys.info(ghostId),
    queryFn: () => getGlyph(ghostId),
    enabled: ghostId.length > 0,
    refetchInterval: 10_000,
  });
}

export function useClaimGlyph() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ ghostId, pixels }: { ghostId: string; pixels: number[] }) =>
      claimGlyph(ghostId, pixels),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: glyphKeys.all });
    },
  });
}
