import React from 'react'
import { Link } from 'react-router-dom'
import { useAssetSummary } from '@/hooks/useAssets'
import { useVulnerabilitySummary } from '@/hooks/useVulnerabilities'
import { useOrgRisk } from '@/hooks/useRisk'
import { useAlerts } from '@/hooks/useAlerts'
import { StatCard } from '@/components/ui/StatCard'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { SeverityDonutChart } from '@/components/charts/SeverityDonutChart'
import { RiskTrendChart } from '@/components/charts/RiskTrendChart'

export function DashboardPage() {
  const { data: assetSummary, isLoading: assetsLoading } = useAssetSummary()
  const { data: vulnSummary, isLoading: vulnLoading } = useVulnerabilitySummary()
  const { data: orgRisk, isLoading: riskLoading } = useOrgRisk()
  const { data: alertData } = useAlerts({ status: ['open'] })

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900">Security Dashboard</h1>
        {orgRisk && <RiskBadge band={orgRisk.risk_band} />}
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard
          label="Organization Risk Score"
          value={riskLoading ? '—' : orgRisk?.risk_score.toFixed(0) ?? '0'}
          accent={orgRisk && orgRisk.risk_score >= 60 ? 'critical' : 'default'}
        />
        <StatCard
          label="Total Assets"
          value={assetsLoading ? '—' : assetSummary?.total ?? 0}
          subtext={`${assetSummary?.internet_facing ?? 0} internet-facing`}
        />
        <StatCard
          label="Open Critical Vulns"
          value={vulnLoading ? '—' : vulnSummary?.open_critical ?? 0}
          accent="critical"
          subtext={`${vulnSummary?.kev_count ?? 0} in CISA KEV`}
        />
        <StatCard
          label="Open Alerts"
          value={alertData?.alerts.length ?? 0}
          accent={alertData && alertData.summary.open_critical > 0 ? 'critical' : 'default'}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-gray-200 bg-white p-5">
          <h2 className="mb-3 text-sm font-semibold text-gray-900">Risk Trend</h2>
          {orgRisk && <RiskTrendChart currentScore={orgRisk.risk_score} projection30d={orgRisk.projection_30d} />}
        </div>
        <div className="rounded-2xl border border-gray-200 bg-white p-5">
          <h2 className="mb-3 text-sm font-semibold text-gray-900">Vulnerability Severity</h2>
          {vulnSummary && (
            <SeverityDonutChart
              critical={vulnSummary.open_critical}
              high={vulnSummary.open_high}
              medium={vulnSummary.open_medium}
              low={vulnSummary.open_low}
            />
          )}
        </div>
      </div>

      <div className="flex gap-3">
        <Link to="/assets" className="text-sm font-medium text-blue-600 hover:underline">
          View all assets →
        </Link>
        <Link to="/vulnerabilities" className="text-sm font-medium text-blue-600 hover:underline">
          View vulnerabilities →
        </Link>
        <Link to="/monitoring" className="text-sm font-medium text-blue-600 hover:underline">
          View alerts →
        </Link>
      </div>
    </div>
  )
}
