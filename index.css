import React from 'react'
import clsx from 'clsx'

const BAND_STYLES: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
  minimal: 'bg-gray-100 text-gray-600 border-gray-200',
}

export function RiskBadge({ band }: { band?: string }) {
  const key = (band ?? 'minimal').toLowerCase()
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium capitalize',
        BAND_STYLES[key] ?? BAND_STYLES.minimal
      )}
    >
      {key}
    </span>
  )
}
