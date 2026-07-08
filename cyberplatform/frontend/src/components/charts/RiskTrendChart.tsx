import React from 'react'
import { Line } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Filler,
} from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Filler)

interface Props {
  currentScore: number
  projection30d?: number
}

export function RiskTrendChart({ currentScore, projection30d }: Props) {
  // Lightweight synthetic series anchored on the current and projected score,
  // since historical time-series storage is not yet wired to this endpoint.
  const points = projection30d != null ? [currentScore, (currentScore + projection30d) / 2, projection30d] : [currentScore]
  const labels = projection30d != null ? ['Today', '+15d', '+30d (projected)'] : ['Today']

  const data = {
    labels,
    datasets: [
      {
        label: 'Risk Score',
        data: points,
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59,130,246,0.08)',
        fill: true,
        tension: 0.3,
        pointRadius: 4,
      },
    ],
  }

  return (
    <Line
      data={data}
      options={{
        scales: { y: { min: 0, max: 100, ticks: { stepSize: 20 } } },
        plugins: { legend: { display: false } },
      }}
    />
  )
}
