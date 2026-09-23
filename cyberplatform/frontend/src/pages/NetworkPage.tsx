import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { StatCard } from '@/components/ui/StatCard'

interface UnknownDevice {
  id: string
  ip_address: string
  mac_address: string
  vendor: string | null
  hostname: string | null
  first_seen: string
  last_seen: string
  alert_id: string | null
  open_ports: Array<{ port: number; protocol: string; service: string | null }> | null
}

interface PiiFinding {
  id: string
  source_table: string
  source_record_id: string
  source_field: string
  pii_type: string
  pii_sample: string
  severity: string
  detected_at: string
}

interface AnalyzeResult {
  anomalies_found: number
  alerts_raised: number
  details: Array<{ rule: string; [key: string]: any }>
}

const PII_TYPE_LABELS: Record<string, string> = {
  email: '📧 Email Address',
  phone_number: '📞 Phone Number',
  credit_card: '💳 Credit Card Number',
  sa_id_number: '🪪 SA ID Number',
  passport_number: '🛂 Passport Number',
}

export function NetworkPage() {
  const queryClient = useQueryClient()
  const [ipRange, setIpRange] = useState('192.168.1.0/24')
  const [analyzeResult, setAnalyzeResult] = useState<AnalyzeResult | null>(null)
  const [piiScanResult, setPiiScanResult] = useState<{ findings_created: number } | null>(null)
  const [activeTab, setActiveTab] = useState<'devices' | 'pii' | 'access'>('devices')

  // Unknown devices
  const { data: unknownDevices, isLoading: devicesLoading } = useQuery({
    queryKey: ['unknown-devices'],
    queryFn: async () => {
      const { data } = await apiClient.get<UnknownDevice[]>('/api/v1/network/unknown-devices')
      return data
    },
    refetchInterval: 30_000,
  })

  // PII findings
  const { data: piiFindings, isLoading: piiLoading } = useQuery({
    queryKey: ['pii-findings'],
    queryFn: async () => {
      const { data } = await apiClient.get<PiiFinding[]>('/api/v1/network/pii-findings')
      return data
    },
  })

  const scanForUnknowns = useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post('/api/v1/network/scan-for-unknowns', {
        ip_range: ipRange,
        fast: true,
      })
      return data
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['unknown-devices'] }),
  })

  const approveDevice = useMutation({
    mutationFn: async (deviceId: string) => {
      await apiClient.post(`/api/v1/network/unknown-devices/${deviceId}/approve`)
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['unknown-devices'] }),
  })

  const analyzeAccess = useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post<AnalyzeResult>('/api/v1/network/analyze-access')
      return data
    },
    onSuccess: (data) => {
      setAnalyzeResult(data)
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const scanForPii = useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post('/api/v1/network/scan-for-pii')
      return data
    },
    onSuccess: (data) => {
      setPiiScanResult(data)
      queryClient.invalidateQueries({ queryKey: ['pii-findings'] })
    },
  })

  const resolvePii = useMutation({
    mutationFn: async (findingId: string) => {
      await apiClient.post(`/api/v1/network/pii-findings/${findingId}/resolve`)
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['pii-findings'] }),
  })

  const RULE_LABELS: Record<string, string> = {
    impossible_travel: '🌍 Impossible Travel — Same user from two different IPs within 10 minutes',
    bulk_data_harvesting: '📦 Bulk Data Access — Excessive asset requests in short window',
    privilege_probing: '🔐 Privilege Probing — Low-privilege user accessing restricted endpoint',
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">Network Monitor & Identity Protection</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Unknown device detection, data access monitoring, and PII protection
          </p>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
        <StatCard
          label="Unknown Devices"
          value={unknownDevices?.length ?? 0}
          accent={unknownDevices && unknownDevices.length > 0 ? 'critical' : 'good'}
          subtext={unknownDevices && unknownDevices.length > 0 ? 'Require attention' : 'All devices known'}
        />
        <StatCard
          label="PII Findings"
          value={piiFindings?.length ?? 0}
          accent={piiFindings && piiFindings.length > 0 ? 'high' : 'good'}
          subtext={piiFindings && piiFindings.length > 0 ? 'Unresolved findings' : 'No PII detected'}
        />
        <StatCard
          label="Last Access Analysis"
          value={analyzeResult ? analyzeResult.anomalies_found : '—'}
          accent={analyzeResult && analyzeResult.anomalies_found > 0 ? 'critical' : 'default'}
          subtext={analyzeResult ? `${analyzeResult.alerts_raised} alert(s) raised` : 'Not yet run'}
        />
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-200">
        {([
          { id: 'devices', label: '📡 Unknown Devices' },
          { id: 'pii', label: '🔒 PII Protection' },
          { id: 'access', label: '👁 Access Monitor' },
        ] as const).map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab: Unknown Devices */}
      {activeTab === 'devices' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <input
              type="text"
              value={ipRange}
              onChange={e => setIpRange(e.target.value)}
              placeholder="IP range e.g. 192.168.1.0/24"
              className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
            <button
              onClick={() => scanForUnknowns.mutate()}
              disabled={scanForUnknowns.isPending}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap">
              {scanForUnknowns.isPending ? '🔍 Scanning…' : '🔍 Scan Network'}
            </button>
          </div>

          {scanForUnknowns.data && (
            <div className={`rounded-xl border p-3 text-sm ${
              scanForUnknowns.data.error
                ? 'border-red-200 bg-red-50 text-red-700'
                : 'border-green-200 bg-green-50 text-green-800'
            }`}>
              {scanForUnknowns.data.error
                ? `Scan error: ${scanForUnknowns.data.error}`
                : `Scan complete — ${scanForUnknowns.data.unknown_devices_found} unknown device(s) found, ${scanForUnknowns.data.alerts_raised} alert(s) raised.`}
            </div>
          )}

          <div className="rounded-2xl border border-gray-200 bg-white overflow-hidden">
            <div className="border-b border-gray-100 bg-gray-50 px-4 py-2 text-xs font-medium text-gray-500">
              Unapproved Unknown Devices ({unknownDevices?.length ?? 0})
            </div>
            {devicesLoading && <p className="p-6 text-center text-gray-400 text-sm">Loading…</p>}
            {!devicesLoading && (!unknownDevices || unknownDevices.length === 0) && (
              <div className="p-8 text-center">
                <p className="text-2xl mb-2">✅</p>
                <p className="text-gray-400 text-sm">No unknown devices detected. All scanned devices are in the asset inventory.</p>
              </div>
            )}
            {unknownDevices && unknownDevices.length > 0 && (
              <div className="divide-y divide-gray-100">
                {unknownDevices.map(device => (
                  <div key={device.id} className="flex items-start justify-between p-4 gap-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-gray-900">{device.ip_address}</span>
                        {device.hostname && (
                          <span className="text-xs text-gray-500">({device.hostname})</span>
                        )}
                        <span className="inline-flex items-center rounded-full bg-red-100 border border-red-200 px-2 py-0.5 text-xs font-medium text-red-700">
                          Unknown
                        </span>
                      </div>
                      <p className="text-xs text-gray-500 mt-0.5">
                        MAC: {device.mac_address}
                        {device.vendor ? ` · ${device.vendor}` : ''}
                      </p>
                      {device.open_ports && device.open_ports.length > 0 && (
                        <p className="text-xs text-gray-400 mt-0.5">
                          Open ports: {device.open_ports.slice(0, 5).map(p => p.port).join(', ')}
                          {device.open_ports.length > 5 ? ` +${device.open_ports.length - 5} more` : ''}
                        </p>
                      )}
                      <p className="text-xs text-gray-400 mt-0.5">
                        First seen: {new Date(device.first_seen).toLocaleString()}
                        {' · '}Last seen: {new Date(device.last_seen).toLocaleString()}
                      </p>
                    </div>
                    <button
                      onClick={() => {
                        if (window.confirm(`Approve ${device.ip_address} (${device.mac_address}) as a known device?`)) {
                          approveDevice.mutate(device.id)
                        }
                      }}
                      disabled={approveDevice.isPending}
                      className="shrink-0 rounded-lg border border-gray-200 px-3 py-1 text-xs font-medium text-gray-600 hover:bg-gray-50 disabled:opacity-50">
                      ✓ Approve
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: PII Protection */}
      {activeTab === 'pii' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-500">
              Scans asset notes, vulnerability notes, and custom attributes for personal data that should not be stored there.
            </p>
            <button
              onClick={() => scanForPii.mutate()}
              disabled={scanForPii.isPending}
              className="rounded-lg bg-orange-600 px-4 py-2 text-sm font-medium text-white hover:bg-orange-700 disabled:opacity-50 whitespace-nowrap">
              {scanForPii.isPending ? '🔍 Scanning…' : '🔍 Scan for PII'}
            </button>
          </div>

          {piiScanResult && (
            <div className="rounded-xl border border-blue-200 bg-blue-50 p-3 text-sm text-blue-800">
              Scan complete — {piiScanResult.findings_created} PII finding(s) created.
            </div>
          )}

          <div className="rounded-2xl border border-gray-200 bg-white overflow-hidden">
            <div className="border-b border-gray-100 bg-gray-50 px-4 py-2 text-xs font-medium text-gray-500">
              Unresolved PII Findings ({piiFindings?.length ?? 0})
            </div>
            {piiLoading && <p className="p-6 text-center text-gray-400 text-sm">Loading…</p>}
            {!piiLoading && (!piiFindings || piiFindings.length === 0) && (
              <div className="p-8 text-center">
                <p className="text-2xl mb-2">🔒</p>
                <p className="text-gray-400 text-sm">No PII findings. Click Scan for PII to check your data.</p>
              </div>
            )}
            {piiFindings && piiFindings.length > 0 && (
              <div className="divide-y divide-gray-100">
                {piiFindings.map(f => (
                  <div key={f.id} className="flex items-center justify-between p-4 gap-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-sm font-medium text-gray-900">
                          {PII_TYPE_LABELS[f.pii_type] ?? f.pii_type}
                        </span>
                      </div>
                      <p className="text-xs text-gray-500">
                        Found in <span className="font-medium">{f.source_table}</span> · field: <span className="font-medium">{f.source_field}</span>
                      </p>
                      <p className="text-xs text-gray-400 mt-0.5">
                        Sample: <code className="bg-gray-100 px-1 rounded">{f.pii_sample}</code>
                        {' · '}{new Date(f.detected_at).toLocaleString()}
                      </p>
                    </div>
                    <button
                      onClick={() => {
                        if (window.confirm('Mark this PII finding as resolved? This means the data has been removed or reviewed.')) {
                          resolvePii.mutate(f.id)
                        }
                      }}
                      disabled={resolvePii.isPending}
                      className="shrink-0 rounded-lg bg-green-600 px-3 py-1 text-xs font-medium text-white hover:bg-green-700 disabled:opacity-50">
                      ✓ Resolve
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: Access Monitor */}
      {activeTab === 'access' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-500">
              Analyses the last 60 minutes of access logs for impossible travel, bulk data harvesting, and privilege probing.
            </p>
            <button
              onClick={() => analyzeAccess.mutate()}
              disabled={analyzeAccess.isPending}
              className="rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700 disabled:opacity-50 whitespace-nowrap">
              {analyzeAccess.isPending ? '🔍 Analysing…' : '🔍 Analyse Access Logs'}
            </button>
          </div>

          {analyzeResult && (
            <div className={`rounded-2xl border p-5 ${
              analyzeResult.anomalies_found > 0
                ? 'border-red-200 bg-red-50'
                : 'border-green-200 bg-green-50'
            }`}>
              <p className={`text-sm font-semibold mb-3 ${
                analyzeResult.anomalies_found > 0 ? 'text-red-800' : 'text-green-800'
              }`}>
                {analyzeResult.anomalies_found > 0
                  ? `⚠ ${analyzeResult.anomalies_found} anomalie(s) detected — ${analyzeResult.alerts_raised} alert(s) raised`
                  : '✅ No access anomalies detected in the last 60 minutes'}
              </p>
              {analyzeResult.details.length > 0 && (
                <div className="space-y-2">
                  {analyzeResult.details.map((d, i) => (
                    <div key={i} className="rounded-xl bg-white border border-red-100 p-3">
                      <p className="text-sm font-medium text-red-800">
                        {RULE_LABELS[d.rule] ?? d.rule.replace(/_/g, ' ')}
                      </p>
                      <div className="mt-1 text-xs text-gray-600 space-y-0.5">
                        {d.user_id && <p>User ID: {d.user_id}</p>}
                        {d.ip_a && <p>From: {d.ip_a} and {d.ip_b}</p>}
                        {d.count && <p>Request count: {d.count}</p>}
                        {d.endpoint && <p>Endpoint: {d.endpoint}</p>}
                        {d.user_role && <p>Role: {d.user_role}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {!analyzeResult && (
            <div className="rounded-2xl border border-gray-200 bg-white p-10 text-center">
              <p className="text-2xl mb-2">👁</p>
              <p className="text-gray-400 text-sm">
                Click Analyse Access Logs to check for suspicious activity in the last 60 minutes.
              </p>
              <p className="text-gray-400 text-xs mt-1">
                Access logging requires the middleware to be active — it starts automatically when the backend is running.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
