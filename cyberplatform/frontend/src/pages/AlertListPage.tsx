import React, { useState } from 'react'
import { useAlerts, useAcknowledgeAlert, useResolveAlert } from '@/hooks/useAlerts'
import { apiClient } from '@/api/client'
import { useQueryClient } from '@tanstack/react-query'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { useAssets } from '@/hooks/useAssets'

function CreateAlertRuleModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState({
    name: '',
    severity: 'high',
    title_template: '',
    message_template: '',
    dedup_window_minutes: 60,
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handle = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const val = e.target.type === 'number' ? Number(e.target.value) : e.target.value
    setForm(prev => ({ ...prev, [e.target.name]: val }))
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!form.name.trim() || !form.title_template.trim()) {
      setError('Name and title template are required')
      return
    }
    setLoading(true)
    try {
      await apiClient.post('/api/v1/monitoring/rules', form)
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      onClose()
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? 'Failed to create alert rule.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-lg rounded-2xl bg-white shadow-xl">
        <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
          <h2 className="text-base font-semibold text-gray-900">Create Alert Rule</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl font-bold">✕</button>
        </div>
        <form onSubmit={submit} className="px-6 py-4 space-y-4">
          {error && <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-600">{error}</p>}

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Rule Name *</label>
            <input name="name" value={form.name} onChange={handle} required
              placeholder="e.g. Critical vulnerability detected"
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Severity</label>
              <select name="severity" value={form.severity} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400">
                {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Dedup Window (minutes)</label>
              <input name="dedup_window_minutes" type="number" min={1} max={1440}
                value={form.dedup_window_minutes} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Alert Title Template *</label>
            <input name="title_template" value={form.title_template} onChange={handle} required
              placeholder="e.g. Critical vulnerability on {asset_name}"
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Message Template</label>
            <textarea name="message_template" value={form.message_template} onChange={handle} rows={2}
              placeholder="Optional longer description of this alert..."
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
          </div>

          <div className="flex justify-end gap-3 border-t border-gray-100 pt-4">
            <button type="button" onClick={onClose}
              className="rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50">
              Cancel
            </button>
            <button type="submit" disabled={loading}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
              {loading ? 'Creating…' : 'Create Rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export function AlertListPage() {
  const [statusFilter, setStatusFilter] = useState<string[]>(['open'])
  const [showCreateRule, setShowCreateRule] = useState(false)
  const { data, isLoading } = useAlerts({ status: statusFilter })
  const acknowledge = useAcknowledgeAlert()
  const resolve = useResolveAlert()

  const severityCounts = data?.summary ?? {}

  return (
    <div className="p-6 space-y-4">
      {showCreateRule && <CreateAlertRuleModal onClose={() => setShowCreateRule(false)} />}

      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900">Alerts & Monitoring</h1>
        <button onClick={() => setShowCreateRule(true)}
          className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50">
          + Alert Rule
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {['critical','high','medium','low'].map(sev => (
          <div key={sev} className="rounded-xl border border-gray-200 bg-white px-4 py-3">
            <p className="text-xs font-medium text-gray-500 capitalize">Open {sev}</p>
            <p className={`text-2xl font-bold tabular-nums mt-1 ${
              sev === 'critical' ? 'text-red-600' :
              sev === 'high' ? 'text-orange-600' :
              sev === 'medium' ? 'text-yellow-600' : 'text-blue-600'
            }`}>
              {severityCounts[`open_${sev}`] ?? 0}
            </p>
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        {['open', 'acknowledged', 'resolved'].map(s => (
          <button key={s} onClick={() => setStatusFilter([s])}
            className={`rounded-full border px-3 py-1 text-xs font-medium capitalize transition-colors ${
              statusFilter.includes(s)
                ? 'border-blue-400 bg-blue-50 text-blue-700'
                : 'border-gray-200 text-gray-600 hover:bg-gray-50'
            }`}>
            {s}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        {isLoading && <p className="text-center text-gray-400 py-8">Loading alerts…</p>}

        {!isLoading && data?.alerts.length === 0 && (
          <div className="rounded-2xl border border-gray-200 bg-white p-10 text-center">
            <p className="text-gray-400 text-sm">
              {statusFilter.includes('open')
                ? '🎉 No open alerts — your environment looks clean.'
                : 'No alerts in this view.'}
            </p>
          </div>
        )}

        {data?.alerts.map(alert => (
          <div key={alert.id}
            className="flex items-start justify-between rounded-2xl border border-gray-200 bg-white p-4 gap-4">
            <div className="flex items-start gap-3 min-w-0">
              <SeverityBadge severity={alert.severity} />
              <div className="min-w-0">
                <p className="text-sm font-medium text-gray-900 truncate">{alert.title}</p>
                {alert.message && <p className="text-xs text-gray-500 mt-0.5">{alert.message}</p>}
                {alert.asset_name && (
                  <p className="text-xs text-gray-400 mt-0.5">Asset: {alert.asset_name}</p>
                )}
                <p className="text-xs text-gray-400 mt-0.5">
                  {alert.triggered_at ? new Date(alert.triggered_at).toLocaleString() : ''}
                  {alert.suppressed_count > 0 && ` · ${alert.suppressed_count} duplicate(s) suppressed`}
                </p>
              </div>
            </div>

            {alert.status === 'open' && (
              <div className="flex gap-2 shrink-0">
                <button
                  onClick={() => acknowledge.mutate(alert.id)}
                  disabled={acknowledge.isPending}
                  className="rounded-lg border border-gray-200 px-3 py-1 text-xs font-medium text-gray-600 hover:bg-gray-50 disabled:opacity-50 whitespace-nowrap">
                  Acknowledge
                </button>
                <button
                  onClick={() => resolve.mutate({ alertId: alert.id, reason: 'Resolved via dashboard' })}
                  disabled={resolve.isPending}
                  className="rounded-lg bg-green-600 px-3 py-1 text-xs font-medium text-white hover:bg-green-700 disabled:opacity-50">
                  Resolve
                </button>
              </div>
            )}
            {alert.status === 'acknowledged' && (
              <button
                onClick={() => resolve.mutate({ alertId: alert.id, reason: 'Resolved via dashboard' })}
                disabled={resolve.isPending}
                className="rounded-lg bg-green-600 px-3 py-1 text-xs font-medium text-white hover:bg-green-700 disabled:opacity-50 shrink-0">
                Resolve
              </button>
            )}
            {alert.status === 'resolved' && (
              <span className="text-xs text-green-600 font-medium shrink-0">✓ Resolved</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
