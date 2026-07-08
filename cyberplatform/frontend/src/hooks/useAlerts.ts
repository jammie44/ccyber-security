import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import type { Alert } from '@/types'

interface AlertListResponse {
  alerts: Alert[]
  total: number
  summary: Record<string, number>
}

export function useAlerts(params: { status?: string[]; severity?: string[]; page?: number } = {}) {
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: async () => {
      const { data } = await apiClient.get<AlertListResponse>('/api/v1/monitoring', { params })
      return data
    },
    refetchInterval: 30_000,
  })
}

export function useAcknowledgeAlert() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (alertId: string) => {
      const { data } = await apiClient.post<Alert>(`/api/v1/monitoring/${alertId}/acknowledge`, {})
      return data
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['alerts'] }),
  })
}

export function useResolveAlert() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ alertId, reason }: { alertId: string; reason: string }) => {
      const { data } = await apiClient.post<Alert>(`/api/v1/monitoring/${alertId}/resolve`, { reason })
      return data
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['alerts'] }),
  })
}
