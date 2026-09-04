import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { useState, useEffect } from 'react'

export default function PhasePanel({ engagementId, phase, token, onExecuted, initialTool, initialParams, initialRaw }: { engagementId: string; phase: number; token: string; onExecuted: ()=>void; initialTool?: string; initialParams?: Record<string,string>; initialRaw?: string }) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  const qc = useQueryClient()
  const [tool, setTool] = useState<string>('')
  const [params, setParams] = useState<Record<string,string>>({})
  const [rawOverride, setRawOverride] = useState<string>('')
  const [lastCmdId, setLastCmdId] = useState<string>('')

  const toolsQ = useQuery({
    queryKey: ['tools', phase, engagementId],
    enabled: !!token,
    queryFn: async () => (await axios.get(`/api/v1/engagements/${engagementId}/killchain/tools/${phase}`, { headers })).data,
  })

  useEffect(()=>{ if(toolsQ.data?.length && !tool) { setTool(toolsQ.data[0].name); const p:Record<string,string>={}; for(const pr of toolsQ.data[0].params) if(pr.default) p[pr.name]=pr.default; setParams(p) } }, [toolsQ.data])

  // Apply AI recommendation (initial tool + params) when arriving
  useEffect(()=>{
    if (!initialTool || !toolsQ.data) return
    const spec = toolsQ.data.find((t:any) => t.name === initialTool)
    if (!spec) return
    setTool(initialTool)
    const p: Record<string,string> = {}
    if (initialParams) {
      for (const pr of spec.params) {
        if (initialParams[pr.name] !== undefined) p[pr.name] = String(initialParams[pr.name])
        else if (pr.default) p[pr.name] = pr.default
      }
    } else {
      for (const pr of spec.params) if (pr.default) p[pr.name] = pr.default
    }
    setParams(p)
  }, [initialTool, initialParams, toolsQ.data])

  useEffect(()=>{ if (initialRaw) setRawOverride(initialRaw) }, [initialRaw])

  const onSelectTool = (name: string) => {
    setTool(name)
    const spec = toolsQ.data?.find((t:any)=>t.name===name)
    const p:Record<string,string>={}
    if(spec) for(const pr of spec.params) if(pr.default) p[pr.name]=pr.default
    setParams(p)
  }

  const createMut = useMutation({
    mutationFn: async () => {
      const body: any = { phase, tool_name: tool, params }
      if (rawOverride.trim()) body.raw_command = rawOverride.trim()
      const r = await axios.post(`/api/v1/engagements/${engagementId}/commands`, body, { headers })
      return r.data
    },
    onSuccess: (data)=>{ setLastCmdId(data.id); qc.invalidateQueries({queryKey:['cmds']}) }
  })

  const approveMut = useMutation({
    mutationFn: async () => (await axios.post(`/api/v1/engagements/${engagementId}/commands/${lastCmdId}/approve`, {}, { headers })).data,
    onSuccess: ()=> qc.invalidateQueries({queryKey:['cmds']})
  })
  const execMut = useMutation({
    mutationFn: async () => (await axios.post(`/api/v1/engagements/${engagementId}/commands/${lastCmdId}/execute`, {}, { headers })).data,
    onSuccess: ()=>{ qc.invalidateQueries({queryKey:['cmds']}); onExecuted() }
  })

  const spec = toolsQ.data?.find((t:any)=>t.name===tool)

  return (
    <div className="p-3 space-y-3">
      <div className="flex items-center gap-2">
        <select value={tool} onChange={e=>onSelectTool(e.target.value)} className="flex-1 ax-btn-secondary border ax-border-base rounded px-2 py-2 text-xs">
          {(toolsQ.data ?? []).map((t:any)=><option key={t.name} value={t.name}>{t.name} — {t.description}</option>)}
        </select>
        <span className="text-xs px-2 py-1 rounded ax-btn-secondary border ax-border-base">P{phase}</span>
      </div>

      <div className="space-y-2">
        {(spec?.params ?? []).map((p:any)=>(
          <label key={p.name} className="block text-xs space-y-1">
            <span className="ax-fg-2">{p.name} {p.required ? <span className="ax-danger">*</span> : <span className="ax-fg-muted">(opt)</span>} — <span className="ax-fg-muted">{p.description}</span></span>
            <input value={params[p.name] ?? ''} onChange={e=>setParams({...params, [p.name]: e.target.value})} placeholder={p.example || p.default || ''} className="w-full ax-input border ax-border-base rounded px-2 py-1.5 text-xs" />
          </label>
        ))}
        {spec?.params?.length===0 && <div className="text-xs ax-fg-muted">No parameters — tool runs as-is (ensure HITL approval).</div>}
        {spec && <div className="text-[11px] ax-fg-muted">Template: <code className="ax-accent">{spec.template}</code></div>}
        <label className="block text-[11px] space-y-1 pt-1 border-t ax-border-base">
          <span className="ax-fg-muted">Override raw command (optional — bypasses template assembly):</span>
          <input value={rawOverride} onChange={e => setRawOverride(e.target.value)} placeholder={spec?.template || 'nmap -sV -oX - -p- 192.168.56.0/24'} className="w-full ax-input border ax-border-base rounded px-2 py-1 text-[11px] font-mono" />
        </label>
      </div>

      <div className="flex gap-2">
        <button onClick={()=>createMut.mutate()} disabled={!tool || createMut.isPending} className="flex-1 ax-btn-secondary hover:ax-bg-elevated border ax-border-strong rounded px-3 py-2 text-xs font-semibold disabled:opacity-50">
          {createMut.isPending ? 'Creating...' : '1. Create Command (Pending Approval)'}
        </button>
      </div>

      {lastCmdId && (
        <div className="space-y-2 p-2 rounded border  ax-btn-primary //10">
          <div className="text-xs font-mono text-amber-200">Command {lastCmdId.slice(0,8)} — requires HITL gate</div>
          <div className="flex gap-2">
            <button onClick={()=>approveMut.mutate()} disabled={approveMut.isPending} className="flex-1 ax-btn-primary / hover:ax-btn-primary / text-slate-900 rounded px-3 py-2 text-xs font-bold disabled:opacity-50">
              {approveMut.isPending ? 'Approving...' : '2. Approve ✓'}
            </button>
            <button onClick={()=>execMut.mutate()} disabled={execMut.isPending} className="flex-1 ax-btn-primary / hover:ax-btn-primary / text-slate-900 rounded px-3 py-2 text-xs font-bold disabled:opacity-50">
              {execMut.isPending ? 'Executing...' : '3. Execute ▶'}
            </button>
          </div>
          <div className="text-[11px] ax-fg-2">Raw command will stream to Live Console via WebSocket.</div>
        </div>
      )}

      {(createMut.isError || approveMut.isError || execMut.isError) && (
        <div className="text-xs ax-danger ax-btn-danger //10 border  rounded p-2">
          {(createMut.error as any)?.response?.data?.detail || (approveMut.error as any)?.response?.data?.detail || (execMut.error as any)?.response?.data?.detail || 'Request failed'}
        </div>
      )}
    </div>
  )
}
