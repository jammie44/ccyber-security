export type RiskBand = 'critical' | 'high' | 'medium' | 'low' | 'minimal'
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type VulnPriority = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Asset {
  id: string
  tenant_id: string
  name: string
  asset_type: string
  status: string
  environment: string
  criticality_score: number
  criticality_label: string
  business_impact_score: number
  data_classification: string
  exposure_level: string
  is_internet_facing: boolean
  is_in_compliance_scope: boolean
  os_name?: string
  os_version?: string
  cloud_provider?: string
  cloud_region?: string
  business_unit?: string
  department?: string
  owner_email?: string
  security_health_score: number
  open_vuln_critical: number
  open_vuln_high: number
  open_vuln_medium: number
  open_vuln_low: number
  current_risk_score?: number
  current_risk_band?: RiskBand
  tags?: Record<string, string>
  notes?: string
  last_scan_date?: string
  agent_last_checkin?: string
  discovery_source?: string
  fqdn?: string
  created_at: string
  updated_at: string
}

export interface AssetVulnerability {
  id: string
  tenant_id: string
  asset_id: string
  cve_id?: string
  priority: VulnPriority
  status: string
  affected_component?: string
  affected_version?: string
  fix_version?: string
  risk_score?: number
  sla_status: string
  sla_deadline?: string
  first_detected_at?: string
  remediated_at?: string
  notes?: string
  created_at: string
  cvss_v3_score?: number
  epss_score?: number
  is_in_kev?: boolean
  exploit_maturity?: string
}

export interface OrgRiskScore {
  risk_score: number
  risk_band: RiskBand
  score_delta_7d?: number
  score_delta_30d?: number
  trend_direction?: string
  trend_velocity?: number
  projection_30d?: number
  assets_assessed: number
  assets_total: number
  critical_assets: number
  high_risk_assets: number
}

export interface Alert {
  id: string
  tenant_id: string
  title: string
  message?: string
  severity: AlertSeverity
  status: string
  fingerprint: string
  asset_id?: string
  asset_name?: string
  context_data?: Record<string, unknown>
  suppressed_count: number
  triggered_at?: string
  acknowledged_at?: string
  acknowledged_by?: string
  resolved_at?: string
  resolved_reason?: string
  created_at: string
}

export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  per_page: number
}
