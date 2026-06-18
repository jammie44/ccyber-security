import React from 'react'
import { NavLink } from 'react-router-dom'
import clsx from 'clsx'
import { useAuthStore } from '@/store/authStore'

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Dashboard', icon: '📊' },
  { to: '/assets', label: 'Assets', icon: '🖥️' },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: '🛡️' },
  { to: '/risk', label: 'Risk', icon: '⚠️' },
  { to: '/monitoring', label: 'Alerts', icon: '🔔' },
]

export function Sidebar() {
  const { user, logout } = useAuthStore()

  return (
    <aside className="flex h-screen w-60 flex-col border-r border-gray-200 bg-white">
      <div className="flex items-center gap-2 px-5 py-5 border-b border-gray-100">
        <span className="text-lg font-bold text-gray-900">CyberPlatform</span>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-blue-50 text-blue-700'
                  : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
              )
            }
          >
            <span>{item.icon}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-gray-100 px-4 py-4">
        <div className="mb-2 text-sm">
          <p className="font-medium text-gray-900">{user?.full_name}</p>
          <p className="text-xs text-gray-500">{user?.role?.replace('_', ' ')}</p>
        </div>
        <button
          onClick={logout}
          className="w-full rounded-lg border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50"
        >
          Sign out
        </button>
      </div>
    </aside>
  )
}
