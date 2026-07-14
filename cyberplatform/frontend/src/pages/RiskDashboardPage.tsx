import React from 'react'
import { Link } from 'react-router-dom'
import { useOrgRisk, useRecomputeAssetRisk } from '@/hooks/useRisk'
import { useAssets } from '@/hooks/useAssets'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { StatCard } from '@/components/ui/StatCard'
import { RiskTrendChart } from '@/components/charts/RiskTrendChart'
import { apiClient } from '@/api/client'
import { useQueryClient } from '@tanstack/react-query'

export function RiskDashboardPage() {
  const { data: orgRisk, isLoading } = useOrgRisk()
  const { data: assetsData } = useAssets({ per_page: 200 })
  const queryClient = useQueryClient()
  const [recomputing, setRecomputing] = React.useState(false)
  const [message, setMessage] = React.useState('')

  const recomputeAll = async () => {
    if (!assetsData?.assets.length) return
    setRecomputing(true)
    setMessage('Recomputing risk scores for all assets…')
    let done = 0
    for (const asset of assetsData.assets) {
      try {
        await apiClient.post(`/api/v1/risk/assets/${asset.id}/recompute`)
        done++
        setMessage(`Recomputing… ${done}/${assetsData.assets.length}`)
      } catch {
        // continue on individual asset failure
      }
    }
    try {
      await apiClient.post('/api/v1/risk/organization/recompute')
    } catch {}
    queryClient.invalidateQueries({ queryKey: ['risk'] })
    queryClient.invalidateQueries({ queryKey: ['assets'] })
    setMessage(`✓ Recomputed risk scores for ${done} assets`)
    setRecomputing(false)
  }

  if (isLoading) return <div className="p-6 text-gray-400">Loading risk data…</div>

  const bandColor = (band?: string) => {
    if (band === 'critical') return 'text-red-600'
    if (band === 'high') return 'text-orange-600'
    if (band === 'medium') return 'text-yellow-600'
    return 'text-gray-700'
  }

  const BAND_COUNTS = ['critical', 'high', 'medium', 'low', 'minimal'].map(band => ({
    band,
    count: assetsData?.assets.filter(a => a.current_risk_band === band).length ?? 0,
  }))

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">Risk Overview</h1>
          {orgRisk && (
            <p className="text-sm text-gray-500 mt-0.5">
              {orgRisk.assets_assessed} of {orgRisk.assets_total} assets scored
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          {orgRisk && <RiskBadge band={orgRisk.risk_band} />}
          <button
            onClick={recomputeAll}
            disabled={recomputing || !assetsData?.assets.length}
            className="rounded-lg border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50">
            {recomputing ? 'Recomputing…' : '↻ Recompute All'}
          </button>
        </div>
      </div>

      {message && (
        <p className={`text-sm px-3 py-2 rounded-lg ${
          message.startsWith('✓') ? 'bg-green-50 text-green-700' : 'bg-blue-50 text-blue-700'
        }`}>
          {message}
        </p>
      )}

      {/* Top stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard
          label="Org Risk Score"
          value={orgRisk ? orgRisk.risk_score.toFixed(0) : '—'}
          accent={orgRisk && orgRisk.risk_score >= 60 ? 'critical' : 'default'}
          subtext={orgRisk?.risk_band ?? ''}
        />
        <StatCard label="Critical Risk Assets" value={orgRisk?.critical_assets ?? 0} accent="critical" />
        <StatCard label="High Risk Assets" value={orgRisk?.high_risk_assets ?? 0} accent="high" />
        <StatCard label="Assets Scored" value={orgRisk?.assets_assessed ?? 0} />
      </div>

      {/* Trend chart */}
      {orgRisk && (
        <div className="rounded-2xl border border-gray-200 bg-white p-5">
          <h2 className="text-sm font-semibold text-gray-900 mb-3">Risk Trend & Projection</h2>
          <RiskTrendChart currentScore={orgRisk.risk_score} projection30d={orgRisk.projection_30d} />
          {orgRisk.trend_direction && (
            <p className="text-xs text-gray-500 mt-3">
              Trend: <span className="font-medium capitalize">{orgRisk.trend_direction}</span>
              {orgRisk.trend_velocity != null && (
                <span> · {Math.abs(orgRisk.trend_velocity).toFixed(2)} pts/day</span>
              )}
              {orgRisk.projection_30d != null && (
                <span> · 30-day projection: <span className={bandColor(orgRisk.risk_band)}>{orgRisk.projection_30d.toFixed(0)}</span></span>
              )}
            </p>
          )}
        </div>
      )}

      {/* Risk band breakdown */}
      <div className="rounded-2xl border border-gray-200 bg-white p-5">
        <h2 className="text-sm font-semibold text-gray-900 mb-4">Assets by Risk Band</h2>
        <div className="space-y-3">
          {BAND_COUNTS.map(({ band, count }) => {
            const total = assetsData?.total ?? 0
            const pct = total > 0 ? Math.round((count / total) * 100) : 0
            const barColor =
              band === 'critical' ? 'bg-red-500' :
              band === 'high' ? 'bg-orange-500' :
              band === 'medium' ? 'bg-yellow-400' :
              band === 'low' ? 'bg-blue-400' : 'bg-gray-300'
            return (
              <div key={band}>
                <div className="flex items-center justify-between text-sm mb-1">
                  <span className="capitalize font-medium text-gray-700">{band}</span>
                  <span className="text-gray-500 tabular-nums">{count} assets ({pct}%)</span>
                </div>
                <div className="h-2 rounded-full bg-gray-100 overflow-hidden">
                  <div className={`h-full rounded-full ${barColor} transition-all`} style={{ width: `${pct}%` }} />
                </div>
              </div>
            )
          })}
        </div>
        {(!assetsData || assetsData.total === 0) && (
          <p className="text-center text-gray-400 text-sm py-4">
            No assets yet. <Link to="/assets" className="text-blue-600 hover:underline">Add assets →</Link>
          </p>
        )}
      </div>

      {/* Top 5 riskiest assets */}
      {assetsData && assetsData.assets.length > 0 && (
        <div className="rounded-2xl border border-gray-200 bg-white p-5">
          <h2 className="text-sm font-semibold text-gray-900 mb-4">Top Riskiest Assets</h2>
          <table className="w-full text-sm">
            <thead className="text-left text-xs font-medium text-gray-500 border-b border-gray-100">
              <tr>
                <th className="pb-2">Asset</th>
                <th className="pb-2">Environment</th>
                <th className="pb-2">Risk Score</th>
                <th className="pb-2">Band</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {[...assetsData.assets]
                .sort((a, b) => (b.current_risk_score ?? 0) - (a.current_risk_score ?? 0))
                .slice(0, 5)
                .map(asset => (
                  <tr key={asset.id}>
                    <td className="py-2.5">
                      <Link to={`/assets/${asset.id}`} className="text-blue-600 hover:underline font-medium">
                        {asset.name}
                      </Link>
                    </td>
                    <td className="py-2.5 text-gray-600 capitalize">{asset.environment}</td>
                    <td className="py-2.5 font-bold tabular-nums text-gray-900">
                      {asset.current_risk_score?.toFixed(0) ?? '—'}
                    </td>
                    <td className="py-2.5"><RiskBadge band={asset.current_risk_band} /></td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
