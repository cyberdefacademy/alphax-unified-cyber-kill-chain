import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { useState } from 'react'

export default function AIAssistPanel({ engagementId, token, onPickedTool, currentPhase }: { engagementId: string; token: string; onPickedTool: (toolName: string, params: any) => void; currentPhase: number }) {
  const qc = useQueryClient()
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  const [startPhase, setStartPhase] = useState(1)
  const [endPhase, setEndPhase] = useState(Math.min(6, currentPhase + 1))
  const [aiMessages, setAiMessages] = useState<{ role: 'ai' | 'user'; text: string }[]>([
    { role: 'ai', text: 'AlphaX AI assist ready. I will recommend tools, build chains, and pivot on failures. Ask or click a button.' }
  ])

  const statusQ = useQuery({
    queryKey: ['ai-status', engagementId],
    enabled: !!engagementId && !!token,
    queryFn: async () => (await axios.get(`/api/v1/ai/${engagementId}/status`, { headers })).data,
    refetchInterval: 10000,
  })

  const recommendMut = useMutation({
    mutationFn: async (phase: number) => (await axios.post(`/api/v1/ai/${engagementId}/recommend`, { phase }, { headers })).data,
    onSuccess: (data, phase) => {
      const msg = `Phase ${phase} → recommend ${data.tool_name} (conf ${(data.confidence * 100).toFixed(0)}%). ${data.rationale}${data.cve_hint ? ' | ' + data.cve_hint : ''}`
      setAiMessages(m => [...m, { role: 'ai', text: msg }])
      onPickedTool(data.tool_name, data.params)
      qc.invalidateQueries({ queryKey: ['tools', phase, engagementId] })
    },
  })

  const chainMut = useMutation({
    mutationFn: async () => (await axios.post(`/api/v1/ai/${engagementId}/chain`, { start_phase: startPhase, end_phase: endPhase }, { headers })).data,
    onSuccess: (data) => {
      const steps = data.steps.map((s: any) => `  P${s.phase} ${s.tool_name} — ${s.rationale}`).join('\n')
      setAiMessages(m => [...m, { role: 'ai', text: `Chain ${data.start_phase}→${data.end_phase} planned:\n${steps}` }])
    },
  })

  const execChainMut = useMutation({
    mutationFn: async () => (await axios.post(`/api/v1/ai/${engagementId}/execute-chain`, { start_phase: startPhase, end_phase: endPhase, auto_advance: true }, { headers })).data,
    onSuccess: (data) => {
      setAiMessages(m => [...m, { role: 'ai', text: `AI chain launched: ${data.queued_steps} step(s) in background. WS events: ai_chain_step / ai_chain_step_finished / ai_chain_halted.` }])
    },
  })

  const pivotMut = useMutation({
    mutationFn: async ({ phase, failed_tool, stderr, exit_code }: { phase: number; failed_tool: string; stderr: string; exit_code: number }) =>
      (await axios.post(`/api/v1/ai/${engagementId}/pivot`, { phase, failed_tool, stderr, exit_code }, { headers })).data,
    onSuccess: (data) => {
      const text = data.suggestions.map((s: any) => `  • [${s.type}] ${s.action || s.tool_name || s.reason}`).join('\n')
      setAiMessages(m => [...m, { role: 'ai', text: `Failure pivot for P${data.phase} ${data.failed_tool} (exit ${data.exit_code}):\n${text}` }])
    },
  })

  return (
    <div className="ax-card border ax-border-base rounded">
      <div className="px-3 py-2 border-b ax-border-base flex items-center justify-between">
        <div className="text-xs font-semibold tracking-widest ax-accent">AI ASSIST — CHAIN & PIVOT ENGINE</div>
        <div className="text-[10px] ax-fg-muted">recommend • chain • auto-pivot</div>
      </div>

      <div className="p-3 space-y-3">
        {/* Status summary */}
        <div className="ax-input border ax-border-base rounded p-2 text-[11px] ax-fg-2">
          {statusQ.isLoading && <span className="ax-fg-muted">Loading context…</span>}
          {statusQ.data && (
            <>
              <div className="ax-fg-2">{statusQ.data.summary}</div>
              {statusQ.data.recommendation && (
                <div className="mt-1 ax-accent">▶ Current phase rec: <code>{statusQ.data.recommendation.tool_name}</code> ({(statusQ.data.recommendation.confidence * 100).toFixed(0)}% conf) — {statusQ.data.recommendation.rationale}</div>
              )}
            </>
          )}
        </div>

        {/* Quick actions */}
        <div className="grid grid-cols-2 gap-2">
          <button onClick={() => recommendMut.mutate(currentPhase)} disabled={recommendMut.isPending} className="px-2 py-2 rounded ax-btn-primary / text-slate-900 font-bold text-[11px] hover:ax-btn-primary / disabled:opacity-50">
            {recommendMut.isPending ? '…' : `Recommend for P${currentPhase}`}
          </button>
          <button onClick={() => pivotMut.mutate({ phase: 8, failed_tool: 'sliver', stderr: 'sliver: not found', exit_code: 127 })} disabled={pivotMut.isPending} className="px-2 py-2 rounded ax-btn-primary / text-slate-900 font-bold text-[11px] hover:ax-btn-primary / disabled:opacity-50">
            {pivotMut.isPending ? '…' : 'Simulate Pivot'}
          </button>
        </div>

        {/* Chain builder */}
        <div className="ax-input border ax-border-base rounded p-2 space-y-2">
          <div className="text-[11px] ax-fg-2">Chain builder (preview only)</div>
          <div className="flex items-center gap-2 text-[11px]">
            <label className="flex items-center gap-1">
              <span className="ax-fg-2">start</span>
              <input type="number" min={1} max={18} value={startPhase} onChange={e => setStartPhase(Math.max(1, Math.min(18, +e.target.value || 1)))} className="w-14 ax-card border ax-border-base rounded px-2 py-1" />
            </label>
            <label className="flex items-center gap-1">
              <span className="ax-fg-2">end</span>
              <input type="number" min={1} max={18} value={endPhase} onChange={e => setEndPhase(Math.max(1, Math.min(18, +e.target.value || 18)))} className="w-14 ax-card border ax-border-base rounded px-2 py-1" />
            </label>
            <button onClick={() => chainMut.mutate()} disabled={chainMut.isPending} className="px-2 py-1 rounded ax-btn-secondary border ax-border-strong hover:ax-bg-elevated text-[11px]">
              {chainMut.isPending ? '…' : 'Preview'}
            </button>
            <button onClick={() => execChainMut.mutate()} disabled={execChainMut.isPending} className="px-2 py-1 rounded ax-btn-primary / text-slate-900 font-bold hover:ax-btn-primary / text-[11px]">
              {execChainMut.isPending ? '…' : '▶ Run Chain'}
            </button>
          </div>
          <div className="text-[10px] ax-warn">Run Chain = auto-approve each step + auto-advance phase (still hits host subprocess; halts on blocked_needs_input).</div>
        </div>

        {/* AI chat log */}
        <div className="bg-black border ax-border-base rounded p-2 h-40 overflow-auto text-[11px] font-mono">
          {aiMessages.map((m, i) => (
            <div key={i} className={m.role === 'ai' ? 'ax-accent' : 'ax-fg'}>
              <span className="ax-fg-muted">[{m.role === 'ai' ? 'AI' : 'YOU'}]</span> {m.text.split('\n').map((l, j) => <div key={j} className={j === 0 ? '' : 'pl-3'}>{l}</div>)}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
