import React from 'react'
import clsx from 'clsx'

interface Props {
  label: string
  value: string | number
  accent?: 'default' | 'critical' | 'high' | 'good'
  subtext?: string
}

const ACCENT_STYLES: Record<string, string> = {
  default: 'text-gray-900',
  critical: 'text-red-600',
  high: 'text-orange-600',
  good: 'text-green-600',
}

export function StatCard({ label, value, accent = 'default', subtext }: Props) {
  return (
    <div className="rounded-2xl border border-gray-200 bg-white p-4">
      <p className="text-xs font-medium text-gray-500">{label}</p>
      <p className={clsx('mt-1 text-2xl font-bold tabular-nums', ACCENT_STYLES[accent])}>{value}</p>
      {subtext && <p className="mt-1 text-xs text-gray-400">{subtext}</p>}
    </div>
  )
}
