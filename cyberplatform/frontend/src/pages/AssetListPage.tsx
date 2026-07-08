import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAssets } from '@/hooks/useAssets'
import { RiskBadge } from '@/components/ui/RiskBadge'

export function AssetListPage() {
  const [q, setQ] = useState('')
  const { data, isLoading } = useAssets({ q: q || undefined, per_page: 50 })

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900">Asset Inventory</h1>
        <input
          type="text"
          placeholder="Search assets…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="w-64 rounded-lg border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
      </div>

      <div className="overflow-hidden rounded-2xl border border-gray-200 bg-white">
        <table className="w-full text-sm">
          <thead className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500">
            <tr>
              <th className="px-4 py-2">Name</th>
              <th className="px-4 py-2">Type</th>
              <th className="px-4 py-2">Environment</th>
              <th className="px-4 py-2">Risk</th>
              <th className="px-4 py-2">Open Critical/High</th>
              <th className="px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {isLoading && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-400">
                  Loading assets…
                </td>
              </tr>
            )}
            {!isLoading && data?.assets.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-400">
                  No assets found.
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
                <td className="px-4 py-2.5 text-gray-600">{asset.asset_type.replace('_', ' ')}</td>
                <td className="px-4 py-2.5 text-gray-600">{asset.environment}</td>
                <td className="px-4 py-2.5">
                  <RiskBadge band={asset.current_risk_band} />
                </td>
                <td className="px-4 py-2.5 text-gray-600">
                  {asset.open_vuln_critical} / {asset.open_vuln_high}
                </td>
                <td className="px-4 py-2.5 text-gray-600 capitalize">{asset.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {data && (
        <p className="text-xs text-gray-400">
          Showing {data.assets.length} of {data.total} assets
        </p>
      )}
    </div>
  )
}
