import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAssets, useCreateAsset } from '@/hooks/useAssets'
import { RiskBadge } from '@/components/ui/RiskBadge'

const ASSET_TYPES = [
  'physical_server', 'cloud_vm', 'workstation', 'network_device',
  'container', 'web_application', 'database', 'cloud_storage',
  'cloud_function', 'mobile_device', 'api_endpoint', 'other',
]

const ENVIRONMENTS = ['production', 'staging', 'development', 'testing']
const EXPOSURE_LEVELS = ['internet', 'partner', 'internal', 'isolated']
const DATA_CLASSIFICATIONS = ['public', 'internal', 'confidential', 'restricted', 'secret']

function CreateAssetModal({ onClose }: { onClose: () => void }) {
  const createAsset = useCreateAsset()
  const [form, setForm] = useState({
    name: '',
    asset_type: 'cloud_vm',
    environment: 'production',
    criticality_score: 5,
    business_impact_score: 5,
    data_classification: 'internal',
    exposure_level: 'internal',
    is_internet_facing: false,
    is_in_compliance_scope: false,
    os_name: '',
    cloud_provider: '',
    cloud_region: '',
    business_unit: '',
    owner_email: '',
    notes: '',
  })
  const [error, setError] = useState('')

  const handle = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const target = e.target as HTMLInputElement
    const value = target.type === 'checkbox' ? target.checked
      : target.type === 'number' ? Number(target.value)
      : target.value
    setForm(prev => ({ ...prev, [e.target.name]: value }))
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!form.name.trim()) { setError('Name is required'); return }
    try {
      await createAsset.mutateAsync(form)
      onClose()
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? err?.response?.data?.error?.message ?? 'Failed to create asset. Please try again.')
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-2xl rounded-2xl bg-white shadow-xl overflow-y-auto max-h-[90vh]">
        <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
          <h2 className="text-base font-semibold text-gray-900">Add New Asset</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl font-bold">✕</button>
        </div>
        <form onSubmit={submit} className="px-6 py-4 space-y-4">
          {error && <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-600">{error}</p>}

          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-700 mb-1">Asset Name *</label>
              <input name="name" value={form.name} onChange={handle} required
                placeholder="e.g. web-server-01"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Asset Type</label>
              <select name="asset_type" value={form.asset_type} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400">
                {ASSET_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Environment</label>
              <select name="environment" value={form.environment} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400">
                {ENVIRONMENTS.map(e => <option key={e} value={e}>{e}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Exposure Level</label>
              <select name="exposure_level" value={form.exposure_level} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400">
                {EXPOSURE_LEVELS.map(e => <option key={e} value={e}>{e}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Data Classification</label>
              <select name="data_classification" value={form.data_classification} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400">
                {DATA_CLASSIFICATIONS.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Criticality Score (1–10)</label>
              <input name="criticality_score" type="number" min={1} max={10} step={0.5}
                value={form.criticality_score} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Business Impact Score (1–10)</label>
              <input name="business_impact_score" type="number" min={1} max={10} step={0.5}
                value={form.business_impact_score} onChange={handle}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">OS / Platform</label>
              <input name="os_name" value={form.os_name} onChange={handle}
                placeholder="e.g. Ubuntu 22.04"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Cloud Provider</label>
              <input name="cloud_provider" value={form.cloud_provider} onChange={handle}
                placeholder="e.g. AWS, Azure, GCP"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Business Unit</label>
              <input name="business_unit" value={form.business_unit} onChange={handle}
                placeholder="e.g. Engineering"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Owner Email</label>
              <input name="owner_email" type="email" value={form.owner_email} onChange={handle}
                placeholder="owner@company.com"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>

            <div className="col-span-2 flex gap-6">
              <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input name="is_internet_facing" type="checkbox" checked={form.is_internet_facing} onChange={handle}
                  className="rounded border-gray-300 text-blue-600" />
                Internet-facing
              </label>
              <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input name="is_in_compliance_scope" type="checkbox" checked={form.is_in_compliance_scope} onChange={handle}
                  className="rounded border-gray-300 text-blue-600" />
                In compliance scope
              </label>
            </div>

            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-700 mb-1">Notes</label>
              <textarea name="notes" value={form.notes} onChange={handle} rows={2}
                placeholder="Any additional context about this asset..."
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>
          </div>

          <div className="flex justify-end gap-3 border-t border-gray-100 pt-4">
            <button type="button" onClick={onClose}
              className="rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50">
              Cancel
            </button>
            <button type="submit" disabled={createAsset.isPending}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
              {createAsset.isPending ? 'Creating…' : 'Create Asset'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export function AssetListPage() {
  const [q, setQ] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const { data, isLoading } = useAssets({ q: q || undefined, per_page: 50 })

  return (
    <div className="p-6 space-y-4">
      {showCreate && <CreateAssetModal onClose={() => setShowCreate(false)} />}

      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900">Asset Inventory</h1>
        <div className="flex items-center gap-3">
          <input type="text" placeholder="Search assets…" value={q}
            onChange={(e) => setQ(e.target.value)}
            className="w-56 rounded-lg border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
          <button onClick={() => setShowCreate(true)}
            className="rounded-lg bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700">
            + Add Asset
          </button>
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-gray-200 bg-white">
        <table className="w-full text-sm">
          <thead className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500">
            <tr>
              <th className="px-4 py-2">Name</th>
              <th className="px-4 py-2">Type</th>
              <th className="px-4 py-2">Environment</th>
              <th className="px-4 py-2">Risk</th>
              <th className="px-4 py-2">Critical / High</th>
              <th className="px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {isLoading && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">Loading assets…</td></tr>
            )}
            {!isLoading && data?.assets.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center">
                  <p className="text-gray-400 text-sm">No assets yet.</p>
                  <button onClick={() => setShowCreate(true)}
                    className="mt-2 text-sm text-blue-600 hover:underline">
                    Add your first asset →
                  </button>
                </td>
              </tr>
            )}
            {data?.assets.map((asset) => (
              <tr key={asset.id} className="hover:bg-gray-50">
                <td className="px-4 py-2.5">
                  <Link to={`/assets/${asset.id}`} className="font-medium text-blue-600 hover:underline">
                    {asset.name}
                  </Link>
                </td>
                <td className="px-4 py-2.5 text-gray-600 capitalize">{asset.asset_type.replace(/_/g, ' ')}</td>
                <td className="px-4 py-2.5 text-gray-600 capitalize">{asset.environment}</td>
                <td className="px-4 py-2.5"><RiskBadge band={asset.current_risk_band} /></td>
                <td className="px-4 py-2.5 text-gray-600">
                  <span className="text-red-600 font-medium">{asset.open_vuln_critical}</span>
                  {' / '}
                  <span className="text-orange-600 font-medium">{asset.open_vuln_high}</span>
                </td>
                <td className="px-4 py-2.5 text-gray-600 capitalize">{asset.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data && <p className="text-xs text-gray-400">Showing {data.assets.length} of {data.total} assets</p>}
    </div>
  )
}
