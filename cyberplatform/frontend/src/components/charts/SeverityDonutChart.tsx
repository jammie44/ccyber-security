import React from 'react'
import { Doughnut } from 'react-chartjs-2'
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js'

ChartJS.register(ArcElement, Tooltip, Legend)

interface Props {
  critical: number
  high: number
  medium: number
  low: number
}

export function SeverityDonutChart({ critical, high, medium, low }: Props) {
  const data = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [critical, high, medium, low],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
        borderWidth: 0,
      },
    ],
  }

  return (
    <Doughnut
      data={data}
      options={{
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } } },
        cutout: '65%',
      }}
    />
  )
}
