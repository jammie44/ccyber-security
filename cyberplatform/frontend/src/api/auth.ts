import { useMutation } from '@tanstack/react-query'
import { apiClient } from './client'
import { useAuthStore } from '@/store/authStore'

interface LoginPayload {
  email: string
  password: string
  mfa_code?: string
}

interface RegisterPayload {
  email: string
  password: string
  full_name: string
  tenant_name: string
}

interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

async function fetchMe(token: string) {
  const { data } = await apiClient.get('/api/v1/auth/me', {
    headers: { Authorization: `Bearer ${token}` },
  })
  return data
}

export function useLogin() {
  const { setTokens, setUser } = useAuthStore()
  return useMutation({
    mutationFn: async (payload: LoginPayload) => {
      const { data } = await apiClient.post<TokenResponse>('/api/v1/auth/login', payload)
      return data
    },
    onSuccess: async (data) => {
      setTokens(data.access_token, data.refresh_token)
      const user = await fetchMe(data.access_token)
      setUser(user)
    },
  })
}

export function useRegister() {
  const { setTokens, setUser } = useAuthStore()
  return useMutation({
    mutationFn: async (payload: RegisterPayload) => {
      const { data } = await apiClient.post<TokenResponse>('/api/v1/auth/register', payload)
      return data
    },
    onSuccess: async (data) => {
      setTokens(data.access_token, data.refresh_token)
      const user = await fetchMe(data.access_token)
      setUser(user)
    },
  })
}
