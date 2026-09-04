import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import { useEffect, useRef } from 'react'

type Snapshot = {
  engagement: { id: string; name: string; scope_cidr: string; status: string; current_phase: number }
  phase_grid: Array<{ phase: number; status: string; last_status: string; last_tool: string | null; commands: number; succeeded: number; failed: number }>
  targets: Array<{ id: string; ip: string; hostname: string | null; discovered_in_phase: number; open_ports: any[]; services: string[] }>
  credentials: Array<{ id: string; user: string; hash_type: string | null; cracked: boolean; phase: number | null }>
  threats: Array<{ id: string; phase: number; tool: string; exit_code: number; severity: string; ts: string; summary: string }>
  timeline: Array<{ id: string; ts: string; phase: number; tool: string; status: string; exit_code: number | null; raw: string }>
  counters: { by_status: Record<string, number>; tools_top: [string, number][]; threat_score: number; total_commands: number; recent_5min: number }
  ts: string
}

const PHASE_NAMES = [
  '', 'Reconnaissance', 'Weaponization', 'Delivery', 'Social Engineering', 'Exploitation', 'Persistence', 'Defense Evasion', 'Command & Control',
  'Pivoting', 'Discovery', 'Privilege Escalation', 'Execution', 'Credential Access', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact', 'Objectives'
]

export default function MonitoringWindow({ engagementId, token, wsEvents }: { engagementId: string; token: string; wsEvents: any[] }) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  const snapQ = useQuery<Snapshot>({
    queryKey: ['monitoring', engagementId],
    enabled: !!engagementId && !!token,
    queryFn: async () => (await axios.get(`/api/v1/monitoring/${engagementId}/snapshot`, { headers })).data,
    refetchInterval: 4000,
  })

  const canvasRef = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const c = canvasRef.current
    if (!c) return
    const ctx = c.getContext('2d')
    if (!ctx) return
    const dpr = window.devicePixelRatio || 1
    const rect = c.getBoundingClientRect()
    c.width = rect.width * dpr
    c.height = rect.height * dpr
    ctx.scale(dpr, dpr)
    ctx.clearRect(0, 0, rect.width, rect.height)
    const s = snapQ.data
    if (!s) {
      ctx.fillStyle = '#475569'
      ctx.font = '12px monospace'
      ctx.fillText('Loading snapshot…', 10, 20)
      return
    }
    // Map: origin = operator host, circles = discovered targets, lines = phase->target edges
    const W = rect.width, H = rect.height
    const cx = 60, cy = H / 2
    // operator node
    ctx.fillStyle = '#22d3ee'
    ctx.beginPath(); ctx.arc(cx, cy, 14, 0, Math.PI * 2); ctx.fill()
    ctx.fillStyle = '#0f172a'
    ctx.font = 'bold 10px monospace'
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle'
    ctx.fillText('OP', cx, cy)
    ctx.fillStyle = '#94a3b8'
    ctx.font = '9px monospace'
    ctx.textAlign = 'left'
    ctx.fillText('operator', cx + 22, cy)
    // target nodes
    const targets = s.targets.length ? s.targets : [{ id: 'none', ip: s.engagement.scope_cidr, hostname: 'scope', discovered_in_phase: 0, open_ports: [], services: [] }]
    const n = Math.max(targets.length, 1)
    targets.forEach((t, i) => {
      const ang = (Math.PI * (i + 1)) / (n + 1)
      const r = Math.min(W * 0.42, H * 0.42)
      const tx = cx + 100 + r * Math.cos(ang)
      const ty = cy + r * Math.sin(ang)
      const openN = (t.open_ports || []).length
      const color = openN > 0 ? '#22c55e' : '#64748b'
      // edge from operator with phase tag
      ctx.strokeStyle = 'rgba(34,211,238,0.4)'
      ctx.lineWidth = 1
      ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(tx, ty); ctx.stroke()
      // node
      ctx.fillStyle = color
      ctx.beginPath(); ctx.arc(tx, ty, 12, 0, Math.PI * 2); ctx.fill()
      ctx.fillStyle = '#0f172a'
      ctx.font = 'bold 9px monospace'
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle'
      ctx.fillText(String(openN), tx, ty)
      // label
      ctx.fillStyle = '#cbd5e1'
      ctx.font = '10px monospace'
      ctx.textAlign = 'left'
      ctx.fillText(t.ip, tx + 16, ty - 2)
      ctx.fillStyle = '#64748b'
      ctx.font = '9px monospace'
      ctx.fillText(`P${t.discovered_in_phase || 0} • ${openN} open`, tx + 16, ty + 10)
    })
  }, [snapQ.data, snapQ.dataUpdatedAt])

  if (snapQ.isLoading) return <div className="ax-fg-muted text-xs p-3">Loading monitoring snapshot…</div>
  const s = snapQ.data!
  const score = s.counters.threat_score
  const scoreColor = score < 30 ? '#22c55e' : score < 70 ? '#f59e0b' : '#f43f5e'

  return (
    <div className="ax-card border ax-border-base rounded">
      <div className="px-3 py-2 border-b ax-border-base flex items-center justify-between">
        <div className="text-xs font-semibold tracking-widest ax-accent">VISUAL MONITORING — {s.engagement.name.toUpperCase()}</div>
        <div className="text-[10px] ax-fg-muted">live • refresh 4s • ws-events {wsEvents.length}</div>
      </div>

      <div className="grid grid-cols-12 gap-0">
        {/* Left: phase grid + host map */}
        <div className="col-span-8 p-3 space-y-3">
          {/* Phase grid 3x6 */}
          <div className="grid grid-cols-6 gap-1.5">
            {s.phase_grid.map((p) => {
              const active = p.phase === s.engagement.current_phase
              const done = p.phase < s.engagement.current_phase || p.last_status === 'succeeded' && p.phase === s.engagement.current_phase
              const failed = p.last_status === 'failed'
              const color = active ? ' ax-btn-primary //15' : done ? ' ax-btn-primary //10' : failed ? ' ax-btn-danger //10' : 'ax-border-base ax-input'
              return (
                <div key={p.phase} className={`border ${color} rounded p-1.5 text-[10px] relative`}>
                  <div className="flex items-center justify-between">
                    <span className="font-mono ax-fg-2">P{p.phase}</span>
                    <span className="ax-fg-2 text-[9px] truncate ml-1">{PHASE_NAMES[p.phase]?.slice(0, 7)}</span>
                  </div>
                  {active && <div className="absolute top-0.5 right-0.5 w-1.5 h-1.5 rounded-full bg-cyan-300 animate-ping"></div>}
                  <div className="mt-1 ax-fg-muted truncate">{p.last_tool ?? '—'}</div>
                  <div className="flex items-center gap-1 text-[9px] mt-0.5">
                    <span className="ax-success">✓{p.succeeded}</span>
                    <span className="ax-danger">✗{p.failed}</span>
                    <span className="ax-fg-muted ml-auto">{p.commands}cmd</span>
                  </div>
                </div>
              )
            })}
          </div>
          {/* Host map (SVG/Canvas) */}
          <div className="ax-input border ax-border-base rounded">
            <div className="px-2 py-1 border-b ax-border-base text-[11px] ax-fg-2 font-mono">HOST MAP — OPERATOR → TARGETS</div>
            <canvas ref={canvasRef} className="w-full" style={{ height: 200 }} />
          </div>
          {/* Timeline */}
          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">COMMAND TIMELINE (latest 30)</div>
            <div className="space-y-0.5 max-h-32 overflow-auto">
              {s.timeline.length === 0 && <div className="text-[11px] ax-fg-muted">no commands yet</div>}
              {s.timeline.map((t) => {
                const c = t.status === 'succeeded' ? '' : t.status === 'failed' ? '' : t.status === 'running' ? 'border-amber-500/40' : 'ax-border-base'
                const badge = t.status === 'succeeded' ? '✓' : t.status === 'failed' ? '✗' : t.status === 'running' ? '◐' : '·'
                return (
                  <div key={t.id} className={`flex items-center gap-2 text-[10px] border-l-2 pl-1.5 ${c}`}>
                    <span className="font-mono ax-fg-muted">{(t.ts || '').slice(11, 19)}</span>
                    <span className="ax-fg-2 w-6">P{t.phase}</span>
                    <span className="ax-accent w-20 truncate">{t.tool}</span>
                    <span className="ax-fg-2 flex-1 truncate font-mono">{t.raw}</span>
                    <span className={t.status === 'succeeded' ? 'ax-success' : t.status === 'failed' ? 'ax-danger' : 'ax-warn'}>{badge} {t.status}{t.exit_code !== null ? `(${t.exit_code})` : ''}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        {/* Right: gauges + threats + WS pulse */}
        <div className="col-span-4 ax-border-base p-3 space-y-3">
          {/* Threat gauge SVG */}
          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">THREAT SCORE</div>
            <svg viewBox="0 0 200 110" className="w-full">
              <defs>
                <linearGradient id="g" x1="0" x2="1">
                  <stop offset="0" stopColor="#22c55e" />
                  <stop offset="0.5" stopColor="#f59e0b" />
                  <stop offset="1" stopColor="#f43f5e" />
                </linearGradient>
              </defs>
              <path d="M20,100 A80,80 0 0 1 180,100" fill="none" stroke="#1e293b" strokeWidth="14" strokeLinecap="round" />
              <path d="M20,100 A80,80 0 0 1 180,100" fill="none" stroke="url(#g)" strokeWidth="14" strokeLinecap="round" strokeDasharray={`${(score/100)*251} 251`} />
              <text x="100" y="92" textAnchor="middle" fill={scoreColor} fontSize="28" fontWeight="700" fontFamily="monospace">{score}</text>
              <text x="100" y="108" textAnchor="middle" fill="#94a3b8" fontSize="9" fontFamily="monospace">{score<30?'LOW':score<70?'MEDIUM':'HIGH'} EXPOSURE</text>
            </svg>
          </div>

          {/* Counters */}
          <div className="grid grid-cols-2 gap-1.5 text-[11px]">
            <div className="ax-input border ax-border-base rounded p-2">
              <div className="ax-fg-muted">Targets</div>
              <div className="ax-accent text-lg font-bold font-mono">{s.targets.length}</div>
            </div>
            <div className="ax-input border ax-border-base rounded p-2">
              <div className="ax-fg-muted">Credentials</div>
              <div className="ax-success text-lg font-bold font-mono">{s.credentials.length}</div>
            </div>
            <div className="ax-input border ax-border-base rounded p-2">
              <div className="ax-fg-muted">Commands</div>
              <div className="ax-fg text-lg font-bold font-mono">{s.counters.total_commands}</div>
            </div>
            <div className="ax-input border ax-border-base rounded p-2">
              <div className="ax-fg-muted">5min</div>
              <div className="ax-warn text-lg font-bold font-mono">{s.counters.recent_5min}</div>
            </div>
          </div>

          {/* Status bar chart */}
          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">COMMAND STATUS</div>
            <div className="space-y-1">
              {Object.entries(s.counters.by_status).map(([k, v]) => {
                const max = Math.max(1, ...Object.values(s.counters.by_status))
                const pct = (v / max) * 100
                const color = k === 'succeeded' ? '#22c55e' : k === 'failed' ? '#f43f5e' : k === 'running' ? '#f59e0b' : k === 'pending_approval' ? '#fbbf24' : k === 'approved' ? '#22d3ee' : '#94a3b8'
                return (
                  <div key={k} className="text-[10px]">
                    <div className="flex justify-between"><span style={{ color }}>{k}</span><span className="ax-fg-2">{v}</span></div>
                    <div className="h-1.5 ax-btn-secondary rounded"><div style={{ width: pct + '%', background: color }} className="h-1.5 rounded"></div></div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Top tools */}
          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">TOP TOOLS</div>
            <div className="space-y-0.5 text-[11px]">
              {s.counters.tools_top.length === 0 && <div className="ax-fg-muted">none</div>}
              {s.counters.tools_top.map(([t, n]) => (
                <div key={t} className="flex justify-between"><span className="ax-accent">{t}</span><span className="ax-fg-2">{n}</span></div>
              ))}
            </div>
          </div>

          {/* Threats */}
          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">THREATS ({s.threats.length})</div>
            <div className="space-y-0.5 max-h-32 overflow-auto">
              {s.threats.length === 0 && <div className="ax-fg-muted text-[10px]">no threats</div>}
              {s.threats.slice(-10).reverse().map(th => (
                <div key={th.id} className="text-[10px] flex items-center gap-1">
                  <span className={th.severity === 'high' ? 'ax-danger' : th.severity === 'medium' ? 'ax-warn' : 'ax-fg-2'}>●</span>
                  <span className="ax-fg-2 w-8">P{th.phase}</span>
                  <span className="ax-accent truncate flex-1">{th.tool}</span>
                  <span className="ax-fg-muted">exit {th.exit_code}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
