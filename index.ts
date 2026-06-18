import React from 'react'
import { useParams } from 'react-router-dom'
import { useAsset } from '@/hooks/useAssets'
import { useAssetRisk, useRecomputeAssetRisk, useExplainRisk } from '@/hooks/useRisk'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { StatCard } from '@/components/ui/StatCard'

export function AssetDetailPage() {
  const { assetId } = useParams<{ assetId: string }>()
  const { data: asset, isLoading } = useAsset(assetId)
  const { data: risk } = useAssetRisk(assetId)
  const recompute = useRecomputeAssetRisk()
  const explain = useExplainRisk()

  if (isLoading || !asset) {
    return <div className="p-6 text-gray-400">Loading asset…</div>
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">{asset.name}</h1>
          <p className="text-sm text-gray-500">
            {asset.asset_type.replace('_', ' ')} · {asset.environment} · {asset.os_name ?? 'Unknown OS'}
          </p>
        </div>
        <RiskBadge band={asset.current_risk_band} />
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Risk Score" value={asset.current_risk_score?.toFixed(0) ?? '—'} accent="critical" />
        <StatCard label="Critical Vulns" value={asset.open_vuln_critical} accent="critical" />
        <StatCard label="High Vulns" value={asset.open_vuln_high} accent="high" />
        <StatCard label="Security Health" value={asset.security_health_score.toFixed(0)} />
      </div>

      <div className="rounded-2xl border border-gray-200 bg-white p-5 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-900">Risk Assessment</h2>
          <button
            onClick={() => assetId && recompute.mutate(assetId)}
            disabled={recompute.isPending}
            className="rounded-lg border border-gray-200 px-3 py-1 text-xs font-medium text-gray-600 hover:bg-gray-50 disabled:opacity-50"
          >
            {recompute.isPending ? 'Recomputing…' : 'Recompute'}
          </button>
        </div>

        {risk?.top_drivers && risk.top_drivers.length > 0 && (
          <ul className="list-inside list-disc space-y-1 text-sm text-gray-600">
            {risk.top_drivers.map((d, i) => (
              <li key={i}>{d}</li>
            ))}
          </ul>
        )}

        <button
          onClick={() => assetId && explain.mutate({ assetId })}
          disabled={explain.isPending}
          className="inline-flex items-center gap-1 rounded-full border border-purple-200 bg-purple-50 px-3 py-1 text-xs font-medium text-purple-700 hover:bg-purple-100 disabled:opacity-50"
        >
          ✦ {explain.isPending ? 'Explaining…' : 'Explain this score'}
        </button>

        {explain.data && (
          <p className="rounded-lg bg-purple-50 p-3 text-sm text-gray-700">{explain.data.explanation}</p>
        )}
      </div>

      {asset.notes && (
        <div className="rounded-2xl border border-gray-200 bg-white p-5">
          <h2 className="mb-2 text-sm font-semibold text-gray-900">Notes</h2>
          <p className="text-sm text-gray-600">{asset.notes}</p>
        </div>
      )}
    </div>
  )
}
