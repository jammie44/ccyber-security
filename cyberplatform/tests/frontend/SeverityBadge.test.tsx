import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SeverityBadge } from '@/components/ui/SeverityBadge'

describe('SeverityBadge', () => {
  it('renders the provided severity', () => {
    render(<SeverityBadge severity="high" />)
    expect(screen.getByText('high')).toBeInTheDocument()
  })

  it('defaults to info when severity is undefined', () => {
    render(<SeverityBadge />)
    expect(screen.getByText('info')).toBeInTheDocument()
  })
})
