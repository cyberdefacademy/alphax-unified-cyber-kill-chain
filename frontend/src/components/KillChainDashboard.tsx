import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import { useState } from 'react'
import AttackFlow from './AttackFlow'
import PhasePanel from './PhasePanel'
import LiveConsole from './LiveConsole'
import KnowledgeGraph from './KnowledgeGraph'
import AIAssistPanel from './AIAssistPanel'
import { useEngagementWS } from '../hooks/useEngagementWS'

const PHASES_META = [
  [1,"Reconnaissance"],[2,"Weaponization"],[3,"Delivery"],[4,"Social Engineering"],[5,"Exploitation"],[6,"Persistence"],[7,"Defense Evasion"],[8,"Command & Control"],[9,"Pivoting"],[10,"Discovery"],[11,"Privilege Escalation"],[12,"Execution"],[13,"Credential Access"],[14,"Lateral Movement"],[15,"Collection"],[16,"Exfiltration"],[17,"Impact"],[18,"Objectives"],
]

export default function KillChainDashboard({ engagementId, token }: { engagementId: string; token: string }) {
  const [currentPhase, setCurrentPhase] = useState(1)
  const [aiPicked, setAiPicked] = useState<{ tool?: string; params?: Record<string,string> }>({})
  const headers = token ? { Authorization: `Bearer ${token}` } : {}

  const uuidValid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(engagementId)
  const engQ = useQuery({
    queryKey: ['eng', engagementId],
    enabled: !!engagementId && !!token && uuidValid,
    queryFn: async () => {
      const r = await axios.get(`/api/v1/engagements/${engagementId}`, { headers })
      return r.data
    },
    refetchInterval: 5000,
    retry: false,
  })

  const graphQ = useQuery({
    queryKey: ['graph', engagementId],
    enabled: !!engagementId && !!token && uuidValid,
    queryFn: async () => (await axios.get(`/api/v1/engagements/${engagementId}/graph`, { headers })).data,
    refetchInterval: 6000,
    retry: false,
  })

  const cmdsQ = useQuery({
    queryKey: ['cmds', engagementId],
    enabled: !!engagementId && !!token && uuidValid,
    queryFn: async () => (await axios.get(`/api/v1/engagements/${engagementId}/commands`, { headers })).data,
    refetchInterval: 4000,
    retry: false,
  })

  const { lines, status: wsStatus, clear } = useEngagementWS(engagementId)

  if (!engagementId || !uuidValid) {
    return <div className="max-w-[1600px] mx-auto px-6 py-12 text-center text-slate-400">
      <p className="text-sm text-red-400">Engagement ID invalid — not a UUID.</p>
      <p className="text-xs mt-2">You pasted <code className="bg-slate-900 p-1 rounded">{engagementId || '(empty)'}</code> — must be like <code>80e7b1a0-a15b-4013-8aaf-...</code></p>
      <p className="text-xs mt-2">Use the selector in the header above (or create one). This stops the 401 polling loops you saw in logs.</p>
    </div>
  }
  if (engQ.isError) {
    return <div className="max-w-[1600px] mx-auto px-6 py-12 text-center">
      <p className="text-sm text-red-400">Failed to load engagement: {(engQ.error as any)?.response?.data?.detail || (engQ.error as any)?.message}</p>
      <p className="text-xs text-slate-500 mt-2">Check token expiry — re-login above. Engagement must exist in DB (psql alphax → SELECT id FROM engagements).</p>
    </div>
  }

  const eng = engQ.data
  const activePhase = eng?.current_phase ?? currentPhase

  return (
    <div className="max-w-[1600px] mx-auto px-6 pb-12 space-y-4">
      {/* War Room header stats */}
      <div className="grid grid-cols-4 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded p-3">
          <div className="text-[11px] tracking-widest text-slate-400">ENGAGEMENT</div>
          <div className="text-sm font-semibold truncate">{eng?.name ?? '—'}</div>
          <div className="text-xs text-slate-500">{eng?.scope_cidr} • {eng?.status}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded p-3">
          <div className="text-[11px] tracking-widest text-slate-400">CURRENT PHASE</div>
          <div className="text-sm font-semibold">{activePhase} / 18 — {PHASES_META.find(p=>p[0]===activePhase)?.[1]}</div>
          <div className="text-xs text-cyan-400">WS {wsStatus}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded p-3">
          <div className="text-[11px] tracking-widest text-slate-400">KNOWLEDGE GRAPH</div>
          <div className="text-sm">{graphQ.data?.targets?.length ?? 0} hosts • {graphQ.data?.credentials?.length ?? 0} creds</div>
          <div className="text-xs text-slate-500 truncate">{graphQ.data?.targets?.map((t:any)=>t.ip).join(', ') || 'no hosts yet'}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded p-3">
          <div className="text-[11px] tracking-widest text-slate-400">COMMANDS</div>
          <div className="text-sm">{cmdsQ.data?.length ?? 0} total • {cmdsQ.data?.filter((c:any)=>c.status==='succeeded').length ?? 0} succeeded</div>
          <div className="text-xs text-amber-400">{cmdsQ.data?.filter((c:any)=>c.status==='pending_approval').length ?? 0} pending approval</div>
        </div>
      </div>

      <AttackFlow currentPhase={activePhase} onSelect={setCurrentPhase} />

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-5 space-y-3">
          <div className="bg-slate-900 border border-slate-800 rounded">
            <div className="flex overflow-x-auto border-b border-slate-800">
              {PHASES_META.map(([id,label]) => (
                <button key={id} onClick={()=>{ setCurrentPhase(id as number); setAiPicked({}) }} className={`px-3 py-2 text-[11px] whitespace-nowrap border-b-2 ${currentPhase===id ? 'border-cyan-400 text-cyan-300 bg-slate-800' : activePhase===(id as number) ? 'border-amber-400 text-amber-300' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
                  {id}. {String(label).slice(0,10)}
                </button>
              ))}
            </div>
            <PhasePanel engagementId={engagementId} phase={currentPhase} token={token} onExecuted={()=>{ cmdsQ.refetch(); engQ.refetch(); }} initialTool={aiPicked.tool} initialParams={aiPicked.params} />
          </div>
          <AIAssistPanel engagementId={engagementId} token={token} currentPhase={currentPhase} onPickedTool={(t, p) => { setAiPicked({ tool: t, params: p }); setCurrentPhase(activePhase) }} />
          <KnowledgeGraph targets={graphQ.data?.targets ?? []} credentials={graphQ.data?.credentials ?? []} commands={cmdsQ.data ?? []} />
        </div>

        <div className="col-span-7">
          <LiveConsole lines={lines} wsStatus={wsStatus} onClear={clear} engagementId={engagementId} />
          <div className="mt-3 bg-slate-900 border border-slate-800 rounded p-3">
            <div className="text-xs font-semibold tracking-widest text-slate-400 mb-2">RECENT COMMANDS</div>
            <div className="space-y-1 max-h-[260px] overflow-auto">
              {(cmdsQ.data ?? []).slice(0,20).map((c:any)=>(
                <div key={c.id} className="flex items-center justify-between text-xs bg-slate-950 border border-slate-800 rounded px-2 py-1">
                  <span className="truncate flex-1"><span className="text-slate-500">P{c.phase}</span> {c.tool_name} — <code className="text-cyan-300">{c.raw_command.slice(0,80)}</code></span>
                  <span className={`ml-2 px-2 py-0.5 rounded text-[10px] ${c.status==='succeeded'?'bg-emerald-500/20 text-emerald-300':c.status==='failed'?'bg-red-500/20 text-red-300':c.status==='pending_approval'?'bg-amber-500/20 text-amber-300':'bg-slate-800 text-slate-400'}`}>{c.status}</span>
                </div>
              ))}
              {(!cmdsQ.data || cmdsQ.data.length===0) && <div className="text-xs text-slate-500">No commands yet — select a phase and tool to begin.</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
