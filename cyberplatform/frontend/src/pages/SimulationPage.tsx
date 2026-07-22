import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { StatCard } from '@/components/ui/StatCard'
import { useAssets } from '@/hooks/useAssets'

interface SimResult {
  id: string
  asset_id: string
  simulation_type: string
  target_port: number | null
  finding_title: string
  finding_detail: string
  severity: string
  was_successful: boolean
  simulated_at: string
}

interface SimSummary {
  asset_id: string
  asset_name: string
  findings: number
  alerts_raised: number
  severity_counts: Record<string, number>
}

export function SimulationPage() {
  const queryClient = useQueryClient()
  const { data: assetsData } = useAssets({ per_page: 200 })
  const [selectedAssetId, setSelectedAssetId] = useState<string>('')
  const [lastRunSummary, setLastRunSummary] = useState<SimSummary | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<string>('')
  const [filterSuccess, setFilterSuccess] = useState<string>('')

  const { data: results, isLoading } = useQuery({
    queryKey: ['simulation-results', filterSeverity, filterSuccess],
    queryFn: async () => {
      const params = new URLSearchParams({ limit: '200' })
      if (filterSeverity) params.set('severity', filterSeverity)
      if (filterSuccess !== '') params.set('was_successful', filterSuccess)
      const { data } = await apiClient.get<SimResult[]>(
        `/api/v1/simulate/results?${params.toString()}`
      )
      return data
    },
  })

  const runOne = useMutation({
    mutationFn: async (assetId: string) => {
      const { data } = await apiClient.post<SimSummary>(`/api/v1/simulate/${assetId}`)
      return data
    },
    onSuccess: (data) => {
      setLastRunSummary(data)
      queryClient.invalidateQueries({ queryKey: ['simulation-results'] })
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const runAll = useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post('/api/v1/simulate/all')
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['simulation-results'] })
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const criticalCount = results?.filter(r => r.severity === 'critical').length ?? 0
  const highCount = results?.filter(r => r.severity === 'high').length ?? 0
  const confirmedCount = results?.filter(r => r.was_successful).length ?? 0

  const TYPE_LABELS: Record<string, string> = {
    web_probe: '🌐 Web Probe',
    exposure_check: '🔌 Exposure Check',
    credential_test: '🔑 Credential Test',
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">Attack Simulation</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Passive web probing and network exposure validation
          </p>
        </div>
        <button
          onClick={() => runAll.mutate()}
          disabled={runAll.isPending}
          className="rounded-lg bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
        >
          {runAll.isPending ? 'Simulating all…' : '⚡ Run All Assets'}
        </button>
      </div>

      {/* Run single asset */}
      <div className="rounded-2xl border border-gray-200 bg-white p-4 flex items-center gap-3">
        <select
          value={selectedAssetId}
          onChange={e => setSelectedAssetId(e.target.value)}
          className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
        >
          <option value="">Select an asset to simulate…</option>
          {assetsData?.assets.map(a => (
            <option key={a.id} value={a.id}>
              {a.name} ({a.environment})
            </option>
          ))}
        </select>
        <button
          onClick={() => selectedAssetId && runOne.mutate(selectedAssetId)}
          disabled={!selectedAssetId || runOne.isPending}
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap"
        >
          {runOne.isPending ? 'Running…' : '▶ Run Simulation'}
        </button>
      </div>

      {/* Last run summary */}
      {lastRunSummary && (
        <div className="rounded-2xl border border-green-200 bg-green-50 p-4">
          <p className="text-sm font-semibold text-green-800 mb-2">
            ✓ Simulation complete for {lastRunSummary.asset_name}
          </p>
          <div className="flex gap-6 text-sm text-green-700">
            <span>Total findings: <strong>{lastRunSummary.findings}</strong></span>
            <span>Alerts raised: <strong>{lastRunSummary.alerts_raised}</strong></span>
            <span>Critical: <strong className="text-red-600">{lastRunSummary.severity_counts?.critical ?? 0}</strong></span>
            <span>High: <strong className="text-orange-600">{lastRunSummary.severity_counts?.high ?? 0}</strong></span>
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label="Total Findings" value={results?.length ?? 0} />
        <StatCard label="Critical" value={criticalCount} accent="critical" />
        <StatCard label="High" value={highCount} accent="high" />
        <StatCard label="Confirmed Exposures" value={confirmedCount} accent={confirmedCount > 0 ? 'critical' : 'default'} />
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap items-center">
        <span className="text-xs text-gray-500">Filter:</span>
        {['critical', 'high', 'medium', 'low'].map(s => (
          <button key={s} onClick={() => setFilterSeverity(filterSeverity === s ? '' : s)}
            className={`rounded-full border px-3 py-1 text-xs font-medium capitalize transition-colors ${
              filterSeverity === s
                ? 'border-blue-400 bg-blue-50 text-blue-700'
                : 'border-gray-200 text-gray-600 hover:bg-gray-50'
            }`}>
            {s}
          </button>
        ))}
        <button onClick={() => setFilterSuccess(filterSuccess === 'true' ? '' : 'true')}
          className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
            filterSuccess === 'true'
              ? 'border-red-400 bg-red-50 text-red-700'
              : 'border-gray-200 text-gray-600 hover:bg-gray-50'
          }`}>
          Confirmed only
        </button>
        {(filterSeverity || filterSuccess) && (
          <button onClick={() => { setFilterSeverity(''); setFilterSuccess('') }}
            className="text-xs text-gray-400 hover:text-gray-600 underline">
            Clear
          </button>
        )}
      </div>

      {/* Results table */}
      <div className="overflow-hidden rounded-2xl border border-gray-200 bg-white">
        <table className="w-full text-sm">
          <thead className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500">
            <tr>
              <th className="px-4 py-2">Type</th>
              <th className="px-4 py-2">Finding</th>
              <th className="px-4 py-2">Port</th>
              <th className="px-4 py-2">Severity</th>
              <th className="px-4 py-2">Confirmed</th>
              <th className="px-4 py-2">When</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {isLoading && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">Loading results…</td></tr>
            )}
            {!isLoading && (!results || results.length === 0) && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center">
                  <p className="text-gray-400 text-sm">No simulation results yet.</p>
                  <p className="text-gray-400 text-xs mt-1">
                    Select an asset above and click Run Simulation to start.
                  </p>
                </td>
              </tr>
            )}
            {results?.map(r => (
              <tr key={r.id} className={`hover:bg-gray-50 ${r.was_successful ? 'bg-red-50/30' : ''}`}>
                <td className="px-4 py-2.5 text-gray-600 whitespace-nowrap">
                  {TYPE_LABELS[r.simulation_type] ?? r.simulation_type}
                </td>
                <td className="px-4 py-2.5">
                  <p className="font-medium text-gray-900 text-xs">{r.finding_title}</p>
                  <p className="text-gray-500 text-xs mt-0.5 max-w-md truncate">{r.finding_detail}</p>
                </td>
                <td className="px-4 py-2.5 text-gray-600 tabular-nums">
                  {r.target_port ?? '—'}
                </td>
                <td className="px-4 py-2.5">
                  <SeverityBadge severity={r.severity} />
                </td>
                <td className="px-4 py-2.5">
                  {r.was_successful
                    ? <span className="text-red-600 font-medium text-xs">⚠ Yes</span>
                    : <span className="text-gray-400 text-xs">No</span>}
                </td>
                <td className="px-4 py-2.5 text-gray-400 text-xs whitespace-nowrap">
                  {new Date(r.simulated_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
