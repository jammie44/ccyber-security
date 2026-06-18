import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import type { Asset } from '@/types'

interface AssetListResponse {
  assets: Asset[]
  total: number
  page: number
  per_page: number
}

interface AssetSummary {
  total: number
  active: number
  critical_risk: number
  high_risk: number
  internet_facing: number
  never_scanned: number
  by_type: Record<string, number>
  by_environment: Record<string, number>
}

export function useAssets(params: { q?: string; page?: number; per_page?: number } = {}) {
  return useQuery({
    queryKey: ['assets', params],
    queryFn: async () => {
      const { data } = await apiClient.get<AssetListResponse>('/api/v1/assets', { params })
      return data
    },
  })
}

export function useAssetSummary() {
  return useQuery({
    queryKey: ['assets', 'summary'],
    queryFn: async () => {
      const { data } = await apiClient.get<AssetSummary>('/api/v1/assets/summary')
      return data
    },
  })
}

export function useAsset(assetId: string | undefined) {
  return useQuery({
    queryKey: ['assets', assetId],
    queryFn: async () => {
      const { data } = await apiClient.get<Asset>(`/api/v1/assets/${assetId}`)
      return data
    },
    enabled: !!assetId,
  })
}

export function useCreateAsset() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: Partial<Asset>) => {
      const { data } = await apiClient.post<Asset>('/api/v1/assets', payload)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}
