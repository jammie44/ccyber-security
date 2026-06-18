import React, { useState } from 'react'
import { useAlerts, useAcknowledgeAlert, useResolveAlert } from '@/hooks/useAlerts'
import { SeverityBadge } from '@/components/ui/SeverityBadge'

export function AlertListPage() {
  const [statusFilter, setStatusFilter] = useState<string[]>(['open'])
  const { data, isLoading } = useAlerts({ status: statusFilter })
  const acknowledge = useAcknowledgeAlert()
  const resolve = useResolveAlert()

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900">Alerts</h1>
        <div className="flex gap-2">
          {['open', 'acknowledged', 'resolved'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter([s])}
              className={`rounded-full border px-3 py-1 text-xs font-medium capitalize transition-colors ${
                statusFilter.includes(s)
                  ? 'border-blue-400 bg-blue-50 text-blue-700'
                  : 'border-gray-200 text-gray-600 hover:bg-gray-50'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        {isLoading && <p className="text-gray-400">Loading alerts…</p>}
        {!isLoading && data?.alerts.length === 0 && (
          <p className="rounded-2xl border border-gray-200 bg-white p-6 text-center text-gray-400">
            No alerts in this view.
          </p>
        )}
        {data?.alerts.map((alert) => (
          <div key={alert.id} className="flex items-center justify-between rounded-2xl border border-gray-200 bg-white p-4">
            <div className="flex items-start gap-3">
              <SeverityBadge severity={alert.severity} />
              <div>
                <p className="text-sm font-medium text-gray-900">{alert.title}</p>
                {alert.message && <p className="text-xs text-gray-500">{alert.message}</p>}
                {alert.asset_name && <p className="text-xs text-gray-400">Asset: {alert.asset_name}</p>}
                {alert.suppressed_count > 0 && (
                  <p className="text-xs text-gray-400">Suppressed {alert.suppressed_count} duplicate(s)</p>
                )}
              </div>
            </div>

            {alert.status === 'open' && (
              <div className="flex gap-2">
                <button
                  onClick={() => acknowledge.mutate(alert.id)}
                  disabled={acknowledge.isPending}
                  className="rounded-lg border border-gray-200 px-3 py-1 text-xs font-medium text-gray-600 hover:bg-gray-50 disabled:opacity-50"
                >
                  Acknowledge
                </button>
                <button
                  onClick={() => resolve.mutate({ alertId: alert.id, reason: 'Resolved via dashboard' })}
                  disabled={resolve.isPending}
                  className="rounded-lg bg-green-600 px-3 py-1 text-xs font-medium text-white hover:bg-green-700 disabled:opacity-50"
                >
                  Resolve
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
