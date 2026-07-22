import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { StatCard } from '@/components/ui/StatCard'
import { SeverityBadge } from '@/components/ui/SeverityBadge'

type Audience = 'executive' | 'analyst' | 'owner'

interface TrendMetric {
  current_value: number
  value_7d_ago: number | null
  delta: number | null
  direction: string
}

interface Prediction {
  asset_id: string
  asset_name: string
  predicted_severity: string
  confidence_score: number
  prediction_reason: string
  based_on_asset_count: number
}

export function IntelligencePage() {
  const queryClient = useQueryClient()
  const [audience, setAudience] = useState<Audience>('analyst')
  const [briefing, setBriefing] = useState<string | null>(null)
  const [briefingLoading, setBriefingLoading] = useState(false)
  const [analyzeResult, setAnalyzeResult] = useState<{ anomalies_found: number; alerts_raised: number; details: any[] } | null>(null)

  const { data: trends, isLoading: trendsLoading } = useQuery({
    queryKey: ['intelligence-trends'],
    queryFn: async () => {
      const { data } = await apiClient.get<Record<string, TrendMetric>>('/api/v1/intelligence/trends')
      return data
    },
  })

  const { data: predictions, isLoading: predsLoading } = useQuery({
    queryKey: ['intelligence-predictions'],
    queryFn: async () => {
      const { data } = await apiClient.get<Prediction[]>('/api/v1/intelligence/predictions')
      return data
    },
  })

  const generateBriefing = async () => {
    setBriefingLoading(true)
    setBriefing(null)
    try {
      const { data } = await apiClient.post('/api/v1/intelligence/briefing', { audience })
      setBriefing(data.briefing)
    } catch {
      setBriefing('Failed to generate briefing. Check that the backend is running.')
    } finally {
      setBriefingLoading(false)
    }
  }

  const snapshot = useMutation({
    mutationFn: async () => { await apiClient.post('/api/v1/intelligence/snapshot') },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['intelligence-trends'] }),
  })

  const analyze = useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post('/api/v1/intelligence/analyze')
      return data
    },
    onSuccess: (data) => {
      setAnalyzeResult(data)
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const recompute = useMutation({
    mutationFn: async () => { await apiClient.post('/api/v1/intelligence/predictions/recompute') },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['intelligence-predictions'] }),
  })

  const TREND_LABELS: Record<string, string> = {
    org_risk_score: 'Org Risk Score',
    open_critical_vulns: 'Critical Vulns',
    open_high_vulns: 'High Vulns',
    sla_compliance_rate: 'SLA Compliance %',
    assets_scanned: 'Assets Scanned',
    assets_with_exposures: 'Confirmed Exposures',
    total_simulation_findings: 'Simulation Findings',
  }

  const directionIcon = (dir: string) =>
    dir === 'improving' ? '✅' : dir === 'degrading' ? '⚠️' : dir === 'stable' ? '➡️' : '—'

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">AI Intelligence</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Threat briefings, risk predictions, trend analysis, and anomaly detection
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => snapshot.mutate()} disabled={snapshot.isPending}
            className="rounded-lg border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50">
            {snapshot.isPending ? 'Saving…' : '📸 Save Snapshot'}
          </button>
          <button onClick={() => analyze.mutate()} disabled={analyze.isPending}
            className="rounded-lg bg-orange-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-orange-700 disabled:opacity-50">
            {analyze.isPending ? 'Analysing…' : '🔍 Run Anomaly Check'}
          </button>
        </div>
      </div>

      {analyzeResult && (
        <div className={`rounded-2xl border p-4 ${analyzeResult.anomalies_found > 0 ? 'border-orange-200 bg-orange-50' : 'border-green-200 bg-green-50'}`}>
          <p className={`text-sm font-semibold ${analyzeResult.anomalies_found > 0 ? 'text-orange-800' : 'text-green-800'}`}>
            {analyzeResult.anomalies_found > 0
              ? `⚠ ${analyzeResult.anomalies_found} anomalie(s) found — ${analyzeResult.alerts_raised} alert(s) raised`
              : '✓ No anomalies detected — your posture is stable'}
          </p>
          {analyzeResult.details.length > 0 && (
            <ul className="mt-2 space-y-1">
              {analyzeResult.details.map((d: any, i: number) => (
                <li key={i} className="text-xs text-orange-700">• {d.rule.replace(/_/g, ' ')}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Trend metrics */}
      <div>
        <h2 className="text-sm font-semibold text-gray-900 mb-3">7-Day Trend</h2>
        {trendsLoading ? (
          <p className="text-gray-400 text-sm">Loading trends…</p>
        ) : (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {trends && Object.entries(trends).map(([key, metric]) => (
              <div key={key} className="rounded-2xl border border-gray-200 bg-white p-4">
                <p className="text-xs font-medium text-gray-500">{TREND_LABELS[key] ?? key}</p>
                <p className="text-xl font-bold tabular-nums text-gray-900 mt-1">
                  {typeof metric.current_value === 'number' ? metric.current_value.toFixed(key === 'sla_compliance_rate' ? 1 : 0) : '—'}
                </p>
                <p className="text-xs mt-1">
                  <span className="mr-1">{directionIcon(metric.direction)}</span>
                  <span className={metric.direction === 'improving' ? 'text-green-600' : metric.direction === 'degrading' ? 'text-red-600' : 'text-gray-400'}>
                    {metric.direction}
                    {metric.delta !== null && metric.delta !== 0 && ` (${metric.delta > 0 ? '+' : ''}${metric.delta.toFixed(1)})`}
                  </span>
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* AI Briefing */}
      <div className="rounded-2xl border border-gray-200 bg-white p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-900">AI Security Briefing</h2>
          <div className="flex items-center gap-2">
            <div className="flex rounded-lg border border-gray-200 overflow-hidden">
              {(['executive', 'analyst', 'owner'] as Audience[]).map(a => (
                <button key={a} onClick={() => setAudience(a)}
                  className={`px-3 py-1 text-xs font-medium capitalize transition-colors ${
                    audience === a ? 'bg-blue-600 text-white' : 'text-gray-600 hover:bg-gray-50'
                  }`}>
                  {a}
                </button>
              ))}
            </div>
            <button onClick={generateBriefing} disabled={briefingLoading}
              className="rounded-lg bg-purple-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-purple-700 disabled:opacity-50">
              {briefingLoading ? '✦ Generating…' : '✦ Generate Briefing'}
            </button>
          </div>
        </div>

        {briefingLoading && (
          <div className="space-y-2 animate-pulse">
            <div className="h-3 bg-gray-200 rounded w-full" />
            <div className="h-3 bg-gray-200 rounded w-5/6" />
            <div className="h-3 bg-gray-200 rounded w-4/6" />
          </div>
        )}

        {briefing && !briefingLoading && (
          <div className="rounded-xl bg-purple-50 border border-purple-100 p-4">
            <p className="text-xs font-medium text-purple-600 mb-2">✦ AI-Generated · {audience} audience</p>
            <p className="text-sm text-gray-700 leading-relaxed whitespace-pre-line">{briefing}</p>
            <p className="text-xs text-gray-400 mt-3">AI-assisted · Powered by Llama 3.3 via Groq · Review before sharing</p>
          </div>
        )}

        {!briefing && !briefingLoading && (
          <p className="text-sm text-gray-400 text-center py-6">
            Select an audience and click Generate Briefing to get an AI-written security summary.
          </p>
        )}
      </div>

      {/* Risk Predictions */}
      <div className="rounded-2xl border border-gray-200 bg-white p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-gray-900">Risk Predictions</h2>
            <p className="text-xs text-gray-500 mt-0.5">Unscanned assets predicted to have vulnerabilities based on similar scanned assets</p>
          </div>
          <button onClick={() => recompute.mutate()} disabled={recompute.isPending}
            className="rounded-lg border border-gray-200 px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50">
            {recompute.isPending ? 'Computing…' : '↻ Recompute'}
          </button>
        </div>

        {predsLoading && <p className="text-gray-400 text-sm">Loading predictions…</p>}

        {!predsLoading && (!predictions || predictions.length === 0) && (
          <p className="text-gray-400 text-sm text-center py-4">
            No predictions yet. Run vulnerability assessments on some assets first, then click Recompute.
          </p>
        )}

        {predictions && predictions.length > 0 && (
          <div className="space-y-3">
            {predictions.map(p => (
              <div key={p.asset_id} className="flex items-start justify-between rounded-xl border border-gray-100 p-3">
                <div>
                  <p className="text-sm font-medium text-gray-900">{p.asset_name}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{p.prediction_reason}</p>
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0 ml-3">
                  <SeverityBadge severity={p.predicted_severity} />
                  <p className="text-xs text-gray-400">
                    {Math.round(p.confidence_score * 100)}% confidence
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
