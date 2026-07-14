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

interface VulnParams {
  status?: string[]
  priority?: string[]
  asset_id?: string
  sla_status?: string
  page?: number
  per_page?: number
}

export function useVulnerabilities(params: VulnParams = {}) {
  return useQuery({
    queryKey: ['vulnerabilities', params],
    queryFn: async () => {
      // Build query string manually to handle arrays correctly
      const searchParams = new URLSearchParams()
      if (params.asset_id) searchParams.set('asset_id', params.asset_id)
      if (params.sla_status) searchParams.set('sla_status', params.sla_status)
      if (params.page) searchParams.set('page', String(params.page))
      if (params.per_page) searchParams.set('per_page', String(params.per_page))
      if (params.status) params.status.forEach(s => searchParams.append('status', s))
      if (params.priority) params.priority.forEach(p => searchParams.append('priority', p))

      const { data } = await apiClient.get<VulnListResponse>(
        `/api/v1/vulnerabilities?${searchParams.toString()}`
      )
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
      const { data } = await apiClient.patch<AssetVulnerability>(
        `/api/v1/vulnerabilities/${id}`,
        payload
      )
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
      queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}
