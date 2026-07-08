import React from 'react'
import { useOrgRisk } from '@/hooks/useRisk'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { StatCard } from '@/components/ui/StatCard'
import { RiskTrendChart } from '@/components/charts/RiskTrendChart'

export function RiskDashboardPage() {
  const { data: orgRisk, isLoading } = useOrgRisk()

  if (isLoading || !orgRisk) {
    return <div className="p-6 text-gray-400">Loading risk data…</div>
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900">Organization Risk</h1>
        <RiskBadge band={orgRisk.risk_band} />
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Risk Score" value={orgRisk.risk_score.toFixed(0)} accent="critical" />
        <StatCard label="Assets Assessed" value={`${orgRisk.assets_assessed} / ${orgRisk.assets_total}`} />
        <StatCard label="Critical Risk Assets" value={orgRisk.critical_assets} accent="critical" />
        <StatCard label="High Risk Assets" value={orgRisk.high_risk_assets} accent="high" />
      </div>

      <div className="rounded-2xl border border-gray-200 bg-white p-5">
        <h2 className="mb-3 text-sm font-semibold text-gray-900">Risk Trend & Projection</h2>
        <RiskTrendChart currentScore={orgRisk.risk_score} projection30d={orgRisk.projection_30d} />
      </div>

      {orgRisk.trend_direction && (
        <p className="text-sm text-gray-500">
          Trend: <span className="font-medium capitalize">{orgRisk.trend_direction}</span>
          {orgRisk.trend_velocity != null && ` (${orgRisk.trend_velocity.toFixed(2)} points/day)`}
        </p>
      )}
    </div>
  )
}
