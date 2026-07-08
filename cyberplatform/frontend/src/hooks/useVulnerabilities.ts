import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import type { AssetVulnerability } from '@/types'

interface VulnListResponse {
  vulnerabilities: AssetVulnerability[]
  total: number
  page: number
  per_page: number
}

interface VulnSummary {
  open_critical: number
  open_high: number
  open_medium: number
  open_low: number
  kev_count: number
  exploit_available: number
  sla_breached_critical: number
  sla_breached_high: number
  delta_7d_critical: number
  total_open: number
}

export function useVulnerabilities(params: { status?: string[]; priority?: string[]; page?: number } = {}) {
  return useQuery({
    queryKey: ['vulnerabilities', params],
    queryFn: async () => {
      const { data } = await apiClient.get<VulnListResponse>('/api/v1/vulnerabilities', { params })
      return data
    },
  })
}

export function useVulnerabilitySummary() {
  return useQuery({
    queryKey: ['vulnerabilities', 'summary'],
    queryFn: async () => {
      const { data } = await apiClient.get<VulnSummary>('/api/v1/vulnerabilities/summary')
      return data
    },
  })
}

export function useUpdateVulnerability() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, payload }: { id: string; payload: Partial<AssetVulnerability> }) => {
      const { data } = await apiClient.patch<AssetVulnerability>(`/api/v1/vulnerabilities/${id}`, payload)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
    },
  })
}
