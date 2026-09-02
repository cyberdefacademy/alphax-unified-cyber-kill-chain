import { useState, useEffect } from 'react'
import KillChainDashboard from './components/KillChainDashboard'
import axios from 'axios'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export default function App() {
  const qc = useQueryClient()
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

  const logout = ()=>{ setToken(''); setEngagementId('') }

  return (
    <div className="min-h-screen bg-[#060a12] text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-20">
        <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-cyan-400 flex items-center justify-center font-black text-slate-900">AX</div>
            <div>
              <h1 className="font-bold tracking-widest text-sm">ALPHAX CYBER KILL-CHAIN</h1>
              <p className="text-xs text-slate-400">Director&apos;s Console — 18 Phase UCKC — VulnHub Lab — HITL Gates Enforced</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="px-2 py-1 rounded bg-red-500/20 text-red-300 border border-red-500/30">AUTHORIZED ENGAGEMENTS ONLY</span>
            {token ? <button onClick={logout} className="px-3 py-1 rounded bg-slate-800 border border-slate-700 hover:bg-slate-700">Logout</button> : null}
            <span className={token ? "text-emerald-400" : "text-slate-500"}>{token ? '● operator' : '○ not authed'}</span>
            <span className="text-slate-600 hidden md:inline">API :8001 • UI :3002</span>
          </div>
        </div>
      </header>

      {/* Controls */}
      <div className="max-w-[1600px] mx-auto px-6 py-4 space-y-3">
        {/* Login row */}
        <div className="bg-slate-900 border border-slate-800 rounded p-3">
          <div className="text-[11px] tracking-widest text-slate-400 mb-2">1 — AUTHENTICATE (single-operator JWT)</div>
          <div className="flex flex-wrap gap-2 items-end">
            <label className="text-xs space-y-1">
              <span className="text-slate-400">Username</span>
              <input value={user} onChange={e=>setUser(e.target.value)} className="w-36 bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs" />
            </label>
            <label className="text-xs space-y-1">
              <span className="text-slate-400">Password</span>
              <input type="password" value={pass} onChange={e=>setPass(e.target.value)} className="w-36 bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs" />
            </label>
            <button onClick={()=>loginMut.mutate()} disabled={loginMut.isPending} className="px-4 py-2 rounded bg-cyan-500 text-slate-900 font-bold text-xs hover:bg-cyan-400 disabled:opacity-50">
              {loginMut.isPending ? 'Logging…' : token ? 'Re-Login' : 'Login'}
            </button>
            <span className="text-xs text-slate-500">{token ? `Token ${token.slice(0,22)}… ✓` : 'Default: operator / AlphaX!2026'}</span>
            {loginErr && <span className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded px-2 py-1">{loginErr}</span>}
            {token && <span className="text-[11px] text-emerald-300">Login OK — token auto-saved.</span>}
          </div>
          {!token && <div className="text-[11px] text-amber-300 mt-2">Or cURL: <code>curl -X POST http://localhost:8001/api/v1/auth/login -H "Content-Type: application/x-www-form-urlencoded" -d "username=operator&password=AlphaX!2026"</code></div>}
        </div>

        {/* Engagement row */}
        <div className="bg-slate-900 border border-slate-800 rounded p-3">
          <div className="text-[11px] tracking-widest text-slate-400 mb-2">2 — SELECT / CREATE ENGAGEMENT (scope = VulnHub CIDR)</div>
          {!token ? <div className="text-xs text-slate-500">Login first.</div> : (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2 items-end">
                <label className="text-xs space-y-1 flex-1 min-w-[280px]">
                  <span className="text-slate-400">Engagement ID (UUID) {engagementId && !isUUID && <span className="text-red-400">— must be UUID, you pasted &quot;{engagementId.slice(0,30)}&quot;</span>}</span>
                  <input value={engagementId} onChange={e=>setEngagementId(e.target.value.trim())} placeholder="select from list or paste UUID" className={`w-full border rounded px-3 py-2 text-xs font-mono ${engagementId && !isUUID ? 'bg-red-950 border-red-700 text-red-200' : 'bg-slate-950 border-slate-700'}`} />
                </label>
                {isUUID && <span className="text-xs text-emerald-400 mb-2">✓ UUID valid</span>}
                {!isUUID && engagementId && <span className="text-xs text-red-400 mb-2">✗ Invalid UUID — stops 401 polling. Pick from list below.</span>}
              </div>

              <div className="flex gap-2 flex-wrap">
                {(engsQ.data ?? []).map(e=>(
                  <button key={e.id} onClick={()=>setEngagementId(e.id)} className={`px-3 py-2 rounded border text-xs text-left ${engagementId===e.id?'bg-cyan-500/20 border-cyan-500 text-cyan-300':'bg-slate-950 border-slate-700 hover:border-slate-600'}`}>
                    <div className="font-semibold">{e.name}</div>
                    <div className="text-[11px] text-slate-400">{e.id.slice(0,8)} • {e.scope_cidr} • P{e.current_phase} • {e.status}</div>
                  </button>
                ))}
                {engsQ.isLoading && <span className="text-xs text-slate-500">Loading engagements…</span>}
                {engsQ.data?.length===0 && <span className="text-xs text-slate-500">No engagements yet — create below.</span>}
              </div>

              <div className="flex flex-wrap gap-2 items-end border-t border-slate-800 pt-3">
                <label className="text-xs space-y-1">
                  <span className="text-slate-400">New name</span>
                  <input value={newName} onChange={e=>setNewName(e.target.value)} className="w-56 bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs" />
                </label>
                <label className="text-xs space-y-1">
                  <span className="text-slate-400">Scope CIDR</span>
                  <input value={newScope} onChange={e=>setNewScope(e.target.value)} className="w-40 bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs" />
                </label>
                <button onClick={()=>createMut.mutate()} disabled={createMut.isPending || !token} className="px-4 py-2 rounded bg-emerald-500 text-slate-900 font-bold text-xs hover:bg-emerald-400 disabled:opacity-50">
                  {createMut.isPending ? 'Creating…' : 'Create & Select'}
                </button>
                {createErr && <span className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded px-2 py-1">{createErr}</span>}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Dashboard */}
      {isUUID && token ? <KillChainDashboard engagementId={engagementId} token={token} /> : (
        <div className="max-w-[1600px] mx-auto px-6 pb-12 text-center text-slate-400 py-8">
          <p className="text-sm">{!token ? 'Login above.' : !isUUID ? 'Fix Engagement ID — must be a UUID from the list (or create one). The 401 loops you saw came from pasting "username=operator..." into the ID field.' : 'Select an engagement.'}</p>
        </div>
      )}
    </div>
  )
}
