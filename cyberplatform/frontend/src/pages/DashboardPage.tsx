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
import { useAuthStore } from '@/store/authStore'

export function DashboardPage() {
  const { data: assetSummary, isLoading: assetsLoading } = useAssetSummary()
  const { data: vulnSummary, isLoading: vulnLoading } = useVulnerabilitySummary()
  const { data: orgRisk, isLoading: riskLoading } = useOrgRisk()
  const { data: alertData } = useAlerts({ status: ['open'] })
  const user = useAuthStore(s => s.user)

  const openCriticalAlerts = alertData?.summary?.open_critical ?? 0

  const hasData = (assetSummary?.total ?? 0) > 0

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">Security Dashboard</h1>
          {user && <p className="text-sm text-gray-500 mt-0.5">Welcome back, {user.full_name.split(' ')[0]}</p>}
        </div>
        {orgRisk && <RiskBadge band={orgRisk.risk_band} />}
      </div>

      {/* Empty state — guide new users */}
      {!hasData && !assetsLoading && (
        <div className="rounded-2xl border-2 border-dashed border-gray-200 bg-white p-10 text-center">
          <p className="text-2xl mb-3">🛡️</p>
          <h2 className="text-base font-semibold text-gray-900 mb-1">Get started with CyberPlatform</h2>
          <p className="text-sm text-gray-500 mb-5">
            Add your first asset to start tracking security risk across your environment.
          </p>
          <div className="flex justify-center gap-3">
            <Link to="/assets"
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">
              + Add Your First Asset
            </Link>
            <Link to="/vulnerabilities"
              className="rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">
              Add a Vulnerability
            </Link>
          </div>
        </div>
      )}

      {/* Top stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard
          label="Organization Risk Score"
          value={riskLoading ? '—' : orgRisk?.risk_score.toFixed(0) ?? '0'}
          accent={orgRisk && orgRisk.risk_score >= 60 ? 'critical' : 'default'}
          subtext={orgRisk?.risk_band ?? 'Not yet computed'}
        />
        <StatCard
          label="Total Assets"
          value={assetsLoading ? '—' : assetSummary?.total ?? 0}
          subtext={`${assetSummary?.internet_facing ?? 0} internet-facing`}
        />
        <StatCard
          label="Critical Open Vulns"
          value={vulnLoading ? '—' : vulnSummary?.open_critical ?? 0}
          accent="critical"
          subtext={`${vulnSummary?.kev_count ?? 0} in CISA KEV`}
        />
        <StatCard
          label="Open Alerts"
          value={alertData?.total ?? 0}
          accent={openCriticalAlerts > 0 ? 'critical' : 'default'}
          subtext={openCriticalAlerts > 0 ? `${openCriticalAlerts} critical` : 'None critical'}
        />
      </div>

      {/* Charts row */}
      {hasData && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="rounded-2xl border border-gray-200 bg-white p-5">
            <h2 className="text-sm font-semibold text-gray-900 mb-3">Risk Score Trend</h2>
            {orgRisk ? (
              <RiskTrendChart currentScore={orgRisk.risk_score} projection30d={orgRisk.projection_30d} />
            ) : (
              <div className="h-40 flex items-center justify-center text-gray-400 text-sm">
                No risk data yet —{' '}
                <Link to="/risk" className="text-blue-600 hover:underline ml-1">compute scores →</Link>
              </div>
            )}
          </div>
          <div className="rounded-2xl border border-gray-200 bg-white p-5">
            <h2 className="text-sm font-semibold text-gray-900 mb-3">Vulnerability Severity</h2>
            {vulnSummary && vulnSummary.total_open > 0 ? (
              <SeverityDonutChart
                critical={vulnSummary.open_critical}
                high={vulnSummary.open_high}
                medium={vulnSummary.open_medium}
                low={vulnSummary.open_low}
              />
            ) : (
              <div className="h-40 flex items-center justify-center text-gray-400 text-sm">
                No open vulnerabilities —{' '}
                <Link to="/vulnerabilities" className="text-blue-600 hover:underline ml-1">add findings →</Link>
              </div>
            )}
          </div>
        </div>
      )}

      {/* SLA alerts panel */}
      {vulnSummary && (vulnSummary.sla_breached_critical > 0 || vulnSummary.sla_breached_high > 0) && (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-4 flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-red-800">⚠ SLA Breaches Detected</p>
            <p className="text-xs text-red-600 mt-0.5">
              {vulnSummary.sla_breached_critical} critical and {vulnSummary.sla_breached_high} high severity vulnerabilities are past their remediation deadline.
            </p>
          </div>
          <Link to="/vulnerabilities"
            className="shrink-0 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700">
            View Findings →
          </Link>
        </div>
      )}

      {/* Quick navigation */}
      {hasData && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {[
            { to: '/assets', label: 'Manage Assets', icon: '🖥️', desc: `${assetSummary?.total ?? 0} assets` },
            { to: '/vulnerabilities', label: 'Vulnerabilities', icon: '🛡️', desc: `${vulnSummary?.total_open ?? 0} open` },
            { to: '/risk', label: 'Risk Scores', icon: '⚠️', desc: 'Recompute & analyse' },
            { to: '/monitoring', label: 'Alerts', icon: '🔔', desc: `${alertData?.total ?? 0} total` },
          ].map(item => (
            <Link key={item.to} to={item.to}
              className="rounded-2xl border border-gray-200 bg-white p-4 hover:border-blue-300 hover:bg-blue-50 transition-colors">
              <div className="text-2xl mb-1">{item.icon}</div>
              <p className="text-sm font-medium text-gray-900">{item.label}</p>
              <p className="text-xs text-gray-500 mt-0.5">{item.desc}</p>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
