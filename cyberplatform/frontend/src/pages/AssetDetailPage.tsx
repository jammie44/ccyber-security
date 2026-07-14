import React, { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useAsset } from '@/hooks/useAssets'
import { useAssetRisk, useRecomputeAssetRisk, useExplainRisk } from '@/hooks/useRisk'
import { useVulnerabilities } from '@/hooks/useVulnerabilities'
import { useUpdateVulnerability } from '@/hooks/useVulnerabilities'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { StatCard } from '@/components/ui/StatCard'
import { apiClient } from '@/api/client'
import { useQueryClient } from '@tanstack/react-query'

const PRIORITIES = ['critical', 'high', 'medium', 'low']

function AddVulnModal({ assetId, assetName, onClose }: { assetId: string; assetName: string; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState({
    cve_id: '',
    priority: 'high',
    affected_component: '',
    affected_version: '',
    fix_version: '',
    detection_source: 'manual',
    notes: '',
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handle = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    setForm(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await apiClient.post('/api/v1/vulnerabilities', {
        asset_id: assetId,
        ...form,
        cve_id: form.cve_id || undefined,
        affected_component: form.affected_component || undefined,
        affected_version: form.affected_version || undefined,
        fix_version: form.fix_version || undefined,
        notes: form.notes || undefined,
      })
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
      queryClient.invalidateQueries({ queryKey: ['assets', assetId] })
      onClose()
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? 'Failed to add vulnerability.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-lg rounded-2xl bg-white shadow-xl overflow-y-auto max-h-[90vh]">
        <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
          <h2 className="text-base font-semibold text-gray-900">Add Vulnerability to {assetName}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl font-bold">✕</button>
        </div>
        <form onSubmit={submit} className="px-6 py-4 space-y-4">
          {error && <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-600">{error}</p>}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">CVE ID</label>
              <input name="cve_id" value={form.cve_id} onChange={handle}
                placeholder="e.g. CVE-2024-1234"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Priority *</label>
              <select name="priority" value={form.priority} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400">
                {PRIORITIES.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Affected Component</label>
              <input name="affected_component" value={form.affected_component} onChange={handle}
                placeholder="e.g. nginx"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Affected Version</label>
              <input name="affected_version" value={form.affected_version} onChange={handle}
                placeholder="e.g. 1.24.0"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Fix Version</label>
              <input name="fix_version" value={form.fix_version} onChange={handle}
                placeholder="e.g. 1.25.0"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Detection Source</label>
              <select name="detection_source" value={form.detection_source} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400">
                <option value="manual">Manual</option>
                <option value="scanner">Scanner</option>
                <option value="pen_test">Pen Test</option>
                <option value="threat_intel">Threat Intel</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Notes</label>
            <textarea name="notes" value={form.notes} onChange={handle} rows={2}
              placeholder="Any additional context..."
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
          </div>

          <div className="flex justify-end gap-3 border-t border-gray-100 pt-4">
            <button type="button" onClick={onClose}
              className="rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50">
              Cancel
            </button>
            <button type="submit" disabled={loading}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
              {loading ? 'Adding…' : 'Add Vulnerability'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export function AssetDetailPage() {
  const { assetId } = useParams<{ assetId: string }>()
  const { data: asset, isLoading } = useAsset(assetId)
  const { data: risk } = useAssetRisk(assetId)
  const recompute = useRecomputeAssetRisk()
  const explain = useExplainRisk()
  const [showAddVuln, setShowAddVuln] = useState(false)
  const updateVuln = useUpdateVulnerability()

  const { data: vulnData } = useVulnerabilities({
    // @ts-ignore
    asset_id: assetId,
    status: ['discovered', 'triaged', 'assigned', 'in_remediation', 'pending_verification'],
  })

  const closeVuln = async (id: string) => {
    if (window.confirm('Mark this vulnerability as closed / remediated?')) {
      await updateVuln.mutateAsync({ id, payload: { status: 'closed' } })
    }
  }

  if (isLoading) return <div className="p-6 text-gray-400">Loading asset…</div>
  if (!asset) return <div className="p-6 text-gray-400">Asset not found.</div>

  return (
    <div className="p-6 space-y-5">
      {showAddVuln && (
        <AddVulnModal
          assetId={asset.id}
          assetName={asset.name}
          onClose={() => setShowAddVuln(false)}
        />
      )}

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm text-gray-400 mb-1">
            <Link to="/assets" className="hover:text-blue-600">Assets</Link>
            <span>›</span>
            <span className="text-gray-600">{asset.name}</span>
          </div>
          <h1 className="text-xl font-semibold text-gray-900">{asset.name}</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {asset.asset_type.replace(/_/g, ' ')} · {asset.environment}
            {asset.os_name ? ` · ${asset.os_name}` : ''}
            {asset.cloud_provider ? ` · ${asset.cloud_provider}` : ''}
          </p>
        </div>
        <RiskBadge band={asset.current_risk_band} />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard
          label="Risk Score"
          value={asset.current_risk_score != null ? asset.current_risk_score.toFixed(0) : '—'}
          accent={asset.current_risk_score != null && asset.current_risk_score >= 60 ? 'critical' : 'default'}
        />
        <StatCard label="Critical Vulns" value={asset.open_vuln_critical} accent="critical" />
        <StatCard label="High Vulns" value={asset.open_vuln_high} accent="high" />
        <StatCard label="Security Health" value={`${asset.security_health_score.toFixed(0)}%`} />
      </div>

      {/* Risk Assessment Panel */}
      <div className="rounded-2xl border border-gray-200 bg-white p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-900">Risk Assessment</h2>
          <button
            onClick={() => assetId && recompute.mutate(assetId)}
            disabled={recompute.isPending}
            className="rounded-lg border border-gray-200 px-3 py-1 text-xs font-medium text-gray-600 hover:bg-gray-50 disabled:opacity-50">
            {recompute.isPending ? 'Recomputing…' : '↻ Recompute Score'}
          </button>
        </div>

        {risk?.top_drivers && risk.top_drivers.length > 0 ? (
          <div>
            <p className="text-xs font-medium text-gray-500 mb-2">Top Risk Drivers</p>
            <ul className="space-y-1.5">
              {risk.top_drivers.map((d: string, i: number) => (
                <li key={i} className="flex items-start gap-2 text-sm text-gray-700">
                  <span className="text-orange-500 mt-0.5">▲</span>
                  {d}
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="text-sm text-gray-400">No risk score yet. Click Recompute to generate one.</p>
        )}

        <div className="pt-2 border-t border-gray-100 space-y-3">
          <button
            onClick={() => assetId && explain.mutate({ assetId })}
            disabled={explain.isPending}
            className="inline-flex items-center gap-1.5 rounded-full border border-purple-200 bg-purple-50 px-3 py-1.5 text-xs font-medium text-purple-700 hover:bg-purple-100 disabled:opacity-50 transition-colors">
            ✦ {explain.isPending ? 'Generating explanation…' : 'Explain this risk score with AI'}
          </button>

          {explain.data && (
            <div className="rounded-xl bg-purple-50 border border-purple-100 p-4">
              <p className="text-xs font-medium text-purple-600 mb-1.5">✦ AI-Generated Explanation</p>
              <p className="text-sm text-gray-700 leading-relaxed">{explain.data.explanation}</p>
              <p className="text-xs text-gray-400 mt-2">AI-assisted · Review with your security team</p>
            </div>
          )}
        </div>
      </div>

      {/* Asset Details */}
      <div className="rounded-2xl border border-gray-200 bg-white p-5">
        <h2 className="text-sm font-semibold text-gray-900 mb-4">Asset Details</h2>
        <div className="grid grid-cols-2 gap-x-8 gap-y-3 text-sm">
          {[
            ['Environment', asset.environment],
            ['Exposure Level', asset.exposure_level],
            ['Data Classification', asset.data_classification],
            ['Criticality Score', `${asset.criticality_score}/10`],
            ['Business Impact', `${asset.business_impact_score}/10`],
            ['Internet Facing', asset.is_internet_facing ? 'Yes' : 'No'],
            ['Compliance Scope', asset.is_in_compliance_scope ? 'Yes' : 'No'],
            ['Business Unit', asset.business_unit ?? '—'],
            ['Owner', asset.owner_email ?? '—'],
            ['Last Scan', asset.last_scan_date ?? 'Never'],
          ].map(([label, value]) => (
            <div key={label} className="flex justify-between border-b border-gray-50 pb-2">
              <span className="text-gray-500">{label}</span>
              <span className="font-medium text-gray-800 capitalize">{String(value)}</span>
            </div>
          ))}
        </div>
        {asset.notes && (
          <div className="mt-4 pt-4 border-t border-gray-100">
            <p className="text-xs font-medium text-gray-500 mb-1">Notes</p>
            <p className="text-sm text-gray-700">{asset.notes}</p>
          </div>
        )}
      </div>

      {/* Vulnerabilities on this asset */}
      <div className="rounded-2xl border border-gray-200 bg-white p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-900">
            Open Vulnerabilities ({vulnData?.total ?? 0})
          </h2>
          <button
            onClick={() => setShowAddVuln(true)}
            className="rounded-lg bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-700">
            + Add Vulnerability
          </button>
        </div>

        {!vulnData || vulnData.vulnerabilities.length === 0 ? (
          <div className="text-center py-6">
            <p className="text-gray-400 text-sm">No open vulnerabilities on this asset.</p>
            <button onClick={() => setShowAddVuln(true)}
              className="mt-2 text-sm text-blue-600 hover:underline">
              Add a vulnerability →
            </button>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs font-medium text-gray-500 border-b border-gray-100">
              <tr>
                <th className="pb-2">CVE</th>
                <th className="pb-2">Priority</th>
                <th className="pb-2">Component</th>
                <th className="pb-2">SLA</th>
                <th className="pb-2">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {vulnData.vulnerabilities.map(v => (
                <tr key={v.id}>
                  <td className="py-2.5 font-medium text-gray-900">{v.cve_id ?? '—'}</td>
                  <td className="py-2.5"><SeverityBadge severity={v.priority} /></td>
                  <td className="py-2.5 text-gray-600">{v.affected_component ?? '—'}</td>
                  <td className="py-2.5">
                    <span className={
                      v.sla_status === 'breached' ? 'text-red-600 font-medium text-xs' :
                      v.sla_status === 'at_risk' ? 'text-orange-600 font-medium text-xs' :
                      'text-gray-400 text-xs'
                    }>
                      {v.sla_status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="py-2.5">
                    <button onClick={() => closeVuln(v.id)}
                      className="text-xs text-green-600 hover:underline font-medium">
                      Close
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
