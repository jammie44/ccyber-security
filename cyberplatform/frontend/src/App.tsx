import React from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { ProtectedRoute } from '@/components/layout/ProtectedRoute'
import { AppLayout } from '@/components/layout/AppLayout'
import { LoginPage } from '@/pages/LoginPage'
import { RegisterPage } from '@/pages/RegisterPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { AssetListPage } from '@/pages/AssetListPage'
import { AssetDetailPage } from '@/pages/AssetDetailPage'
import { VulnerabilityListPage } from '@/pages/VulnerabilityListPage'
import { RiskDashboardPage } from '@/pages/RiskDashboardPage'
import { AlertListPage } from '@/pages/AlertListPage'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/assets" element={<AssetListPage />} />
          <Route path="/assets/:assetId" element={<AssetDetailPage />} />
          <Route path="/vulnerabilities" element={<VulnerabilityListPage />} />
          <Route path="/risk" element={<RiskDashboardPage />} />
          <Route path="/monitoring" element={<AlertListPage />} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}
