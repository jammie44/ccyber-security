import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RiskBadge } from '@/components/ui/RiskBadge'

describe('RiskBadge', () => {
  it('renders the critical band label', () => {
    render(<RiskBadge band="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('defaults to minimal when band is undefined', () => {
    render(<RiskBadge />)
    expect(screen.getByText('minimal')).toBeInTheDocument()
  })

  it('normalizes case', () => {
    render(<RiskBadge band="HIGH" />)
    expect(screen.getByText('high')).toBeInTheDocument()
  })
})
