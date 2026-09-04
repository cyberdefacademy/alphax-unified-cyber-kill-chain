import { useState, useEffect } from 'react'
import KillChainDashboard from './components/KillChainDashboard'
import axios from 'axios'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ThemeSwitcher, useTheme } from './components/ThemeSwitcher'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export default function App() {
  const qc = useQueryClient()
  useTheme() // applies data-theme to <html> on mount + persists
  useEffect(() => {
    // Restore scanline overlay preference
    if (typeof document !== 'undefined' && localStorage.getItem('alphax_scanlines') === 'true') {
      document.documentElement.classList.add('ax-scanlines')
    }
  }, [])
  const [engagementId, setEngagementId] = useState<string>(() => localStorage.getItem('alphax_eid') || '')
  const [token, setToken] = useState<string>(() => localStorage.getItem('alphax_token') || '')
  const [user, setUser] = useState('operator')
  const [pass, setPass] = useState('AlphaX!2026')
  const [newName, setNewName] = useState('VulnHub Kioptrix')
  const [newScope, setNewScope] = useState('192.168.56.0/24')
  const [loginErr, setLoginErr] = useState('')
  const [createErr, setCreateErr] = useState('')

  const isUUID = UUID_RE.test(engagementId.trim())

  // persist
  useEffect(()=>{ if(token) localStorage.setItem('alphax_token', token); else localStorage.removeItem('alphax_token') },[token])
  useEffect(()=>{ if(engagementId) localStorage.setItem('alphax_eid', engagementId); else localStorage.removeItem('alphax_eid') },[engagementId])

  const loginMut = useMutation({
    mutationFn: async ()=>{
      const p = new URLSearchParams()
      p.append('username', user)
      p.append('password', pass)
      const r = await axios.post('/api/v1/auth/login', p, { headers: {'Content-Type':'application/x-www-form-urlencoded'}})
      return r.data.access_token as string
    },
    onSuccess:(t)=>{ setToken(t); setLoginErr('') },
    onError:(e:any)=> setLoginErr(e?.response?.data?.detail || e.message || 'login failed')
  })

  const engsQ = useQuery({
    queryKey:['engs', token],
    enabled: !!token,
    queryFn: async()=>{
      const r = await axios.get('/api/v1/engagements', { headers:{ Authorization:`Bearer ${token}` }})
      return r.data as Array<{id:string,name:string,scope_cidr:string,status:string,current_phase:number}>
    },
    refetchInterval: 8000,
  })

  const createMut = useMutation({
    mutationFn: async()=>{
      const r = await axios.post('/api/v1/engagements', { name:newName, scope_cidr:newScope }, { headers:{ Authorization:`Bearer ${token}`, 'Content-Type':'application/json'}})
      return r.data
    },
    onSuccess:(data)=>{ setEngagementId(data.id); qc.invalidateQueries({queryKey:['engs']}); setCreateErr('') },
    onError:(e:any)=> setCreateErr(e?.response?.data?.detail || e.message)
  })

  const deleteOneMut = useMutation({
    mutationFn: async(id:string)=> axios.delete(`/api/v1/engagements/${id}`, { headers:{ Authorization:`Bearer ${token}` }}),
    onSuccess:(_d, id)=>{
      qc.invalidateQueries({queryKey:['engs']})
      if (engagementId === id) { setEngagementId(''); localStorage.removeItem('alphax_eid') }
    }
  })

  const deleteAllMut = useMutation({
    mutationFn: async()=> axios.delete('/api/v1/engagements', { headers:{ Authorization:`Bearer ${token}` }}),
    onSuccess:()=>{ qc.invalidateQueries({queryKey:['engs']}); setEngagementId(''); localStorage.removeItem('alphax_eid') }
  })

  const logout = ()=>{ setToken(''); setEngagementId('') }

  return (
    <div className="min-h-screen" style={{ color: 'var(--fg-primary)' }}>
      <header className="border-b backdrop-blur sticky top-0 z-20" style={{ borderColor: 'var(--border-base)', backgroundColor: 'color-mix(in srgb, var(--bg-panel) 70%, transparent)' }}>
        <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded flex items-center justify-center font-black" style={{ background: 'var(--accent)', color: 'var(--bg-deep)' }}>AX</div>
            <div>
              <h1 className="ax-title font-bold text-sm">ALPHAX CYBER KILL-CHAIN</h1>
              <p className="text-xs ax-fg-muted">Director&apos;s Console — 18 Phase UCKC — VulnHub Lab — HITL Gates Enforced</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="px-2 py-1 rounded" style={{ backgroundColor: 'var(--danger-soft)', color: 'var(--danger)', border: '1px solid color-mix(in srgb, var(--danger) 40%, transparent)' }}>AUTHORIZED ENGAGEMENTS ONLY</span>
            <ThemeSwitcher />
            {token ? <button onClick={logout} className="ax-btn-secondary rounded px-3 py-1">Logout</button> : null}
            <span style={{ color: token ? 'var(--success)' : 'var(--fg-muted)' }}>{token ? '● operator' : '○ not authed'}</span>
            <span className="ax-fg-muted hidden md:inline">API :8001 • UI :3002</span>
          </div>
        </div>
      </header>

      {/* Controls */}
      <div className="max-w-[1600px] mx-auto px-6 py-4 space-y-3">
        {/* Login row */}
        <div className="ax-card p-3">
          <div className="text-[11px] tracking-widest ax-fg-muted mb-2">1 — AUTHENTICATE (single-operator JWT)</div>
          <div className="flex flex-wrap gap-2 items-end">
            <label className="text-xs space-y-1">
              <span className="ax-fg-2">Username</span>
              <input value={user} onChange={e=>setUser(e.target.value)} className="ax-input w-36 rounded px-3 py-2 text-xs" />
            </label>
            <label className="text-xs space-y-1">
              <span className="ax-fg-2">Password</span>
              <input type="password" value={pass} onChange={e=>setPass(e.target.value)} className="ax-input w-36 rounded px-3 py-2 text-xs" />
            </label>
            <button onClick={()=>loginMut.mutate()} disabled={loginMut.isPending} className="ax-btn-primary rounded px-4 py-2 text-xs disabled:opacity-50">
              {loginMut.isPending ? 'Logging…' : token ? 'Re-Login' : 'Login'}
            </button>
            <span className="text-xs ax-fg-muted">{token ? `Token ${token.slice(0,22)}… ✓` : 'Default: operator / AlphaX!2026'}</span>
            {loginErr && <span className="text-xs ax-danger rounded px-2 py-1" style={{ backgroundColor: 'var(--danger-soft)', border: '1px solid color-mix(in srgb, var(--danger) 30%, transparent)' }}>{loginErr}</span>}
            {token && <span className="text-[11px] ax-success">Login OK — token auto-saved.</span>}
          </div>
          {!token && <div className="text-[11px] ax-warn mt-2">Or cURL: <code>curl -X POST http://localhost:8001/api/v1/auth/login -H "Content-Type: application/x-www-form-urlencoded" -d "username=operator&password=AlphaX!2026"</code></div>}
        </div>

        {/* Engagement row */}
        <div className="ax-card p-3">
          <div className="text-[11px] tracking-widest ax-fg-muted mb-2">2 — SELECT / CREATE ENGAGEMENT (scope = VulnHub CIDR)</div>
          {!token ? <div className="text-xs ax-fg-muted">Login first.</div> : (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2 items-end">
                <label className="text-xs space-y-1 flex-1 min-w-[280px]">
                  <span className="ax-fg-2">Engagement ID (UUID) {engagementId && !isUUID && <span className="ax-danger">— must be UUID, you pasted &quot;{engagementId.slice(0,30)}&quot;</span>}</span>
                  <input value={engagementId} onChange={e=>setEngagementId(e.target.value.trim())} placeholder="select from list or paste UUID" className={`w-full ax-input rounded px-3 py-2 text-xs font-mono ${engagementId && !isUUID ? 'border-red-700 text-red-200' : ''}`} />
                </label>
                {isUUID && <span className="text-xs ax-success mb-2">✓ UUID valid</span>}
                {!isUUID && engagementId && <span className="text-xs ax-danger mb-2">✗ Invalid UUID — stops 401 polling. Pick from list below.</span>}
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] ax-fg-2">Engagements ({engsQ.data?.length ?? 0})</span>
                {(engsQ.data?.length ?? 0) > 0 && (
                  <button onClick={() => { if (confirm(`Delete ALL ${engsQ.data?.length} engagement(s) + their targets/credentials/commands?`)) deleteAllMut.mutate() }} disabled={deleteAllMut.isPending} className="ax-btn-danger rounded px-2 py-1 text-[11px] font-semibold disabled:opacity-50">
                    {deleteAllMut.isPending ? 'Clearing…' : 'Clear All'}
                  </button>
                )}
              </div>
              <div className="flex gap-2 flex-wrap">
                {(engsQ.data ?? []).map(e=>{
                  const isSel = engagementId === e.id
                  return (
                    <div key={e.id} className="flex items-stretch border rounded overflow-hidden" style={{ backgroundColor: isSel ? 'var(--accent-soft)' : 'var(--bg-input)', borderColor: isSel ? 'var(--accent-border)' : 'var(--border-base)' }}>
                      <button onClick={()=>setEngagementId(e.id)} className="px-3 py-2 text-xs text-left flex-1">
                        <div className="font-semibold ax-fg">{e.name}</div>
                        <div className="text-[11px] ax-fg-muted">{e.id.slice(0,8)} • {e.scope_cidr} • P{e.current_phase} • {e.status}</div>
                      </button>
                      <button onClick={() => { if (confirm(`Delete engagement "${e.name}" + cascade targets/credentials/commands?`)) deleteOneMut.mutate(e.id) }} disabled={deleteOneMut.isPending} className="px-2 ax-fg-muted hover:ax-danger text-[14px] disabled:opacity-50" style={{ borderLeft: '1px solid var(--border-base)' }} title="Delete this engagement">
                        ×
                      </button>
                    </div>
                  )
                })}
                {engsQ.isLoading && <span className="text-xs ax-fg-muted">Loading engagements…</span>}
                {engsQ.data?.length===0 && <span className="text-xs ax-fg-muted">No engagements yet — create below.</span>}
              </div>

              <div className="flex flex-wrap gap-2 items-end border-t pt-3" style={{ borderColor: 'var(--border-base)' }}>
                <label className="text-xs space-y-1">
                  <span className="ax-fg-2">New name</span>
                  <input value={newName} onChange={e=>setNewName(e.target.value)} className="ax-input w-56 rounded px-3 py-2 text-xs" />
                </label>
                <label className="text-xs space-y-1">
                  <span className="ax-fg-2">Scope CIDR</span>
                  <input value={newScope} onChange={e=>setNewScope(e.target.value)} className="ax-input w-40 rounded px-3 py-2 text-xs" />
                </label>
                <button onClick={()=>createMut.mutate()} disabled={createMut.isPending || !token} className="rounded px-4 py-2 text-xs font-bold disabled:opacity-50" style={{ backgroundColor: 'var(--success)', color: 'var(--bg-deep)' }}>
                  {createMut.isPending ? 'Creating…' : 'Create & Select'}
                </button>
                {createErr && <span className="text-xs ax-danger rounded px-2 py-1" style={{ backgroundColor: 'var(--danger-soft)', border: '1px solid color-mix(in srgb, var(--danger) 30%, transparent)' }}>{createErr}</span>}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Dashboard */}
      {isUUID && token ? <KillChainDashboard engagementId={engagementId} token={token} /> : (
        <div className="max-w-[1600px] mx-auto px-6 pb-12 text-center ax-fg-muted py-8">
          <p className="text-sm">{!token ? 'Login above.' : !isUUID ? 'Fix Engagement ID — must be a UUID from the list (or create one). The 401 loops you saw came from pasting "username=operator..." into the ID field.' : 'Select an engagement.'}</p>
        </div>
      )}
    </div>
  )
}
