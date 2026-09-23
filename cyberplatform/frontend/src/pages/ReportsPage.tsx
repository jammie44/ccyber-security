import React, { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiClient } from '@/api/client'

interface ReportHistoryItem {
  id: string
  report_type: string
  generated_by: string | null
  generated_at: string
  file_size_bytes: number | null
  recipient_count: number | null
  status: string
}

const REPORT_TYPE_LABELS: Record<string, string> = {
  executive_pdf: '📄 Executive PDF',
  email_digest: '📧 Email Digest',
  compliance_export: '🗂 Compliance Export',
}

function formatBytes(bytes: number | null): string {
  if (!bytes) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function ReportsPage() {
  const [digestResult, setDigestResult] = useState<{ status: string; recipient_count: number; reason?: string } | null>(null)

  const { data: history, isLoading, refetch } = useQuery({
    queryKey: ['report-history'],
    queryFn: async () => {
      const { data } = await apiClient.get<ReportHistoryItem[]>('/api/v1/reports/history')
      return data
    },
  })

  const downloadPdf = useMutation({
    mutationFn: async () => {
      const response = await apiClient.get('/api/v1/reports/executive-pdf', {
        responseType: 'blob',
      })
      const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `executive-security-report.pdf`
      a.click()
      window.URL.revokeObjectURL(url)
    },
    onSuccess: () => refetch(),
  })

  const downloadCompliance = useMutation({
    mutationFn: async () => {
      const response = await apiClient.get('/api/v1/reports/compliance-export', {
        responseType: 'blob',
      })
      const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/zip' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `compliance-evidence.zip`
      a.click()
      window.URL.revokeObjectURL(url)
    },
    onSuccess: () => refetch(),
  })

  const sendDigest = useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post('/api/v1/reports/send-digest')
      return data
    },
    onSuccess: (data) => {
      setDigestResult(data)
      refetch()
    },
  })

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-gray-900">Reports & Compliance</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Generate executive reports, compliance evidence exports, and email digests
        </p>
      </div>

      {/* Report cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">

        {/* Executive PDF */}
        <div className="rounded-2xl border border-gray-200 bg-white p-5">
          <div className="text-2xl mb-3">📄</div>
          <h2 className="text-sm font-semibold text-gray-900 mb-1">Executive PDF Report</h2>
          <p className="text-xs text-gray-500 mb-4">
            6-page PDF covering risk posture, top vulnerabilities, simulation findings, and a remediation roadmap.
            Executive summary written by AI if Groq is configured.
          </p>
          <div className="space-y-1 text-xs text-gray-400 mb-4">
            <p>• Cover page with color-coded risk indicator</p>
            <p>• AI-written executive summary</p>
            <p>• Asset inventory table</p>
            <p>• Top 10 vulnerabilities by severity</p>
            <p>• Attack simulation findings</p>
            <p>• Remediation roadmap</p>
          </div>
          <button
            onClick={() => downloadPdf.mutate()}
            disabled={downloadPdf.isPending}
            className="w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
            {downloadPdf.isPending ? '⏳ Generating…' : '⬇ Download PDF'}
          </button>
          {downloadPdf.isError && (
            <p className="text-xs text-red-600 mt-2">Generation failed — check that you have Security Manager role.</p>
          )}
        </div>

        {/* Compliance Export */}
        <div className="rounded-2xl border border-gray-200 bg-white p-5">
          <div className="text-2xl mb-3">🗂</div>
          <h2 className="text-sm font-semibold text-gray-900 mb-1">Compliance Evidence Export</h2>
          <p className="text-xs text-gray-500 mb-4">
            ZIP of JSON evidence files for ISO 27001, SOC 2, and NIST CSF audits.
          </p>
          <div className="space-y-1 text-xs text-gray-400 mb-4">
            <p>• asset_inventory.json</p>
            <p>• vulnerability_register.json</p>
            <p>• risk_scores.json</p>
            <p>• simulation_findings.json</p>
            <p>• access_audit.json (30 days)</p>
            <p>• posture_snapshots.json (12 weeks)</p>
            <p>• pii_findings.json</p>
            <p>• report_metadata.json</p>
          </div>
          <button
            onClick={() => downloadCompliance.mutate()}
            disabled={downloadCompliance.isPending}
            className="w-full rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50">
            {downloadCompliance.isPending ? '⏳ Generating…' : '⬇ Download ZIP'}
          </button>
          {downloadCompliance.isError && (
            <p className="text-xs text-red-600 mt-2">Export failed — check that you have Security Manager role.</p>
          )}
        </div>

        {/* Email Digest */}
        <div className="rounded-2xl border border-gray-200 bg-white p-5">
          <div className="text-2xl mb-3">📧</div>
          <h2 className="text-sm font-semibold text-gray-900 mb-1">Weekly Email Digest</h2>
          <p className="text-xs text-gray-500 mb-4">
            Automated every Monday at 08:00 UTC to all Security Manager accounts.
            Send manually now to test your SMTP configuration.
          </p>
          <div className="space-y-1 text-xs text-gray-400 mb-4">
            <p>• Risk score change vs last week</p>
            <p>• New critical vulnerabilities</p>
            <p>• SLA breaches</p>
            <p>• Top 3 assets needing attention</p>
            <p>• Link to dashboard</p>
          </div>

          {digestResult && (
            <div className={`rounded-lg border px-3 py-2 text-xs mb-3 ${
              digestResult.status === 'success' ? 'border-green-200 bg-green-50 text-green-700' :
              digestResult.status === 'skipped' ? 'border-yellow-200 bg-yellow-50 text-yellow-700' :
              'border-red-200 bg-red-50 text-red-700'
            }`}>
              {digestResult.status === 'success' && `✓ Sent to ${digestResult.recipient_count} recipient(s)`}
              {digestResult.status === 'skipped' && `Skipped: ${digestResult.reason || 'SMTP not configured'}`}
              {digestResult.status === 'failed' && `Failed: ${digestResult.reason || 'Unknown error'}`}
            </div>
          )}

          <button
            onClick={() => sendDigest.mutate()}
            disabled={sendDigest.isPending}
            className="w-full rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700 disabled:opacity-50">
            {sendDigest.isPending ? '⏳ Sending…' : '📤 Send Digest Now'}
          </button>
          <p className="text-xs text-gray-400 mt-2 text-center">
            Requires SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM_EMAIL env vars
          </p>
        </div>
      </div>

      {/* Report history */}
      <div className="rounded-2xl border border-gray-200 bg-white overflow-hidden">
        <div className="border-b border-gray-100 bg-gray-50 px-4 py-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-900">Report History</h2>
          <button onClick={() => refetch()} className="text-xs text-blue-600 hover:underline">Refresh</button>
        </div>

        {isLoading && <p className="p-6 text-center text-gray-400 text-sm">Loading history…</p>}

        {!isLoading && (!history || history.length === 0) && (
          <p className="p-8 text-center text-gray-400 text-sm">
            No reports generated yet. Generate your first report above.
          </p>
        )}

        {history && history.length > 0 && (
          <table className="w-full text-sm">
            <thead className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500">
              <tr>
                <th className="px-4 py-2">Type</th>
                <th className="px-4 py-2">Generated</th>
                <th className="px-4 py-2">Size</th>
                <th className="px-4 py-2">Recipients</th>
                <th className="px-4 py-2">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {history.map(r => (
                <tr key={r.id} className="hover:bg-gray-50">
                  <td className="px-4 py-2.5 font-medium text-gray-900">
                    {REPORT_TYPE_LABELS[r.report_type] ?? r.report_type}
                  </td>
                  <td className="px-4 py-2.5 text-gray-600 text-xs">
                    {new Date(r.generated_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5 text-gray-600 text-xs tabular-nums">
                    {formatBytes(r.file_size_bytes)}
                  </td>
                  <td className="px-4 py-2.5 text-gray-600 text-xs tabular-nums">
                    {r.recipient_count ?? '—'}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                      r.status === 'success' ? 'bg-green-100 text-green-700' :
                      r.status === 'skipped' ? 'bg-yellow-100 text-yellow-700' :
                      'bg-red-100 text-red-700'
                    }`}>
                      {r.status}
                    </span>
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
