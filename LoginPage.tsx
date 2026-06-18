import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import type { OrgRiskScore } from '@/types'

interface AssetRiskScore {
  asset_id: string
  risk_score: number
  risk_band: string
  confidence: number
  score_delta?: number
  formula_version: string
  top_drivers?: string[]
  computed_at: string
}

export function useOrgRisk() {
  return useQuery({
    queryKey: ['risk', 'organization'],
    queryFn: async () => {
      const { data } = await apiClient.get<OrgRiskScore>('/api/v1/risk/organization')
      return data
    },
  })
}

export function useAssetRisk(assetId: string | undefined) {
  return useQuery({
    queryKey: ['risk', 'asset', assetId],
    queryFn: async () => {
      const { data } = await apiClient.get<AssetRiskScore>(`/api/v1/risk/assets/${assetId}`)
      return data
    },
    enabled: !!assetId,
  })
}

export function useRecomputeAssetRisk() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (assetId: string) => {
      const { data } = await apiClient.post<AssetRiskScore>(`/api/v1/risk/assets/${assetId}/recompute`)
      return data
    },
    onSuccess: (_data, assetId) => {
      queryClient.invalidateQueries({ queryKey: ['risk', 'asset', assetId] })
      queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}

export function useExplainRisk() {
  return useMutation({
    mutationFn: async ({ assetId, role }: { assetId: string; role?: string }) => {
      const { data } = await apiClient.post<{ explanation: string; cached: boolean }>(
        '/api/v1/ai/explain/risk',
        { asset_id: assetId, requesting_role: role ?? 'security_manager' }
      )
      return data
    },
  })
}
