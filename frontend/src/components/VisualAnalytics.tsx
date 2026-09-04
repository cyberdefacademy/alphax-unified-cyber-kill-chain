import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import { useMemo } from 'react'

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

// MITRE tactic per UCKC phase (mirrors backend/app/killchain_engine.py PHASE_META)
const PHASE_TACTIC: Record<number, { tactic: string; code: string }> = {
  1: { tactic: 'Reconnaissance', code: 'TA0043' },
  2: { tactic: 'Resource Dev', code: 'TA00xx' },
  3: { tactic: 'Initial Access', code: 'TA00xx' },
  4: { tactic: 'Initial Access', code: 'TA00xx' },
  5: { tactic: 'Execution', code: 'TA0002' },
  6: { tactic: 'Persistence', code: 'TA0003' },
  7: { tactic: 'Defense Evasion', code: 'TA0005' },
  8: { tactic: 'Command & Control', code: 'TA0011' },
  9: { tactic: 'Lateral Movement', code: 'TA00xx' },
  10: { tactic: 'Discovery', code: 'TA0007' },
  11: { tactic: 'Privilege Escalation', code: 'TA0004' },
  12: { tactic: 'Execution', code: 'TA0002' },
  13: { tactic: 'Credential Access', code: 'TA0006' },
  14: { tactic: 'Lateral Movement', code: 'TA0008' },
  15: { tactic: 'Collection', code: 'TA0009' },
  16: { tactic: 'Exfiltration', code: 'TA0010' },
  17: { tactic: 'Impact', code: 'TA0040' },
  18: { tactic: 'Reporting', code: 'TA00xx' },
}

const EVENT_ICON: Record<string, string> = {
  ai_pivot: '◈',
  ai_chain_step: '▶',
  ai_chain_step_finished: '■',
  ai_chain_halted: '⛔',
  command_approved: '✓',
  command_finished: '●',
  knowledge_update: '⬢',
  connected: '○',
}

function Donut({ completed, active, failed, pending }: { completed: number; active: number; failed: number; pending: number }) {
  const total = Math.max(1, completed + active + failed + pending)
  const R = 52
  const C = 2 * Math.PI * R
  const segs = [
    { v: completed, color: 'var(--success)' },
    { v: active, color: 'var(--accent)' },
    { v: failed, color: 'var(--danger)' },
    { v: pending, color: 'var(--border-strong)' },
  ]
  let offset = 0
  return (
    <svg viewBox="0 0 140 140" className="w-full max-w-[190px] mx-auto">
      <circle cx="70" cy="70" r={R} fill="none" stroke="var(--bg-elevated)" strokeWidth="16" />
      {segs.map((s, i) => {
        const frac = s.v / total
        const el = (
          <circle
            key={i}
            cx="70" cy="70" r={R} fill="none"
            stroke={s.color} strokeWidth="16"
            strokeDasharray={`${frac * C} ${C}`}
            strokeDashoffset={-offset * C}
            strokeLinecap="butt"
            transform="rotate(-90 70 70)"
            opacity={s.v === 0 ? 0 : 1}
          />
        )
        offset += frac
        return el
      })}
      <text x="70" y="66" textAnchor="middle" fill="var(--fg-primary)" fontSize="22" fontWeight="800" fontFamily="monospace">
        {Math.round((completed / 18) * 100)}%
      </text>
      <text x="70" y="84" textAnchor="middle" fill="var(--fg-muted)" fontSize="9" fontFamily="monospace">
        {completed}/18 PHASES
      </text>
    </svg>
  )
}

export default function VisualAnalytics({ engagementId, token, wsEvents }: { engagementId: string; token: string; wsEvents: any[] }) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  // Same queryKey as MonitoringWindow → shared react-query cache, no double polling
  const snapQ = useQuery<Snapshot>({
    queryKey: ['monitoring', engagementId],
    enabled: !!engagementId && !!token,
    queryFn: async () => (await axios.get(`/api/v1/monitoring/${engagementId}/snapshot`, { headers })).data,
    refetchInterval: 4000,
  })

  const s = snapQ.data

  const ring = useMemo(() => {
    if (!s) return { completed: 0, active: 0, failed: 0, pending: 18 }
    let completed = 0, active = 0, failed = 0, pending = 0
    for (const p of s.phase_grid) {
      if (p.last_status === 'failed') failed++
      else if (p.phase < s.engagement.current_phase || p.last_status === 'succeeded') completed++
      else if (p.phase === s.engagement.current_phase) active++
      else pending++
    }
    return { completed, active, failed, pending }
  }, [s])

  const tacticGroups = useMemo(() => {
    if (!s) return []
    const map = new Map<string, { tactic: string; code: string; phases: number[]; done: number; failed: number; active: boolean }>()
    for (const p of s.phase_grid) {
      const t = PHASE_TACTIC[p.phase] ?? { tactic: 'Unknown', code: '—' }
      if (!map.has(t.tactic)) map.set(t.tactic, { ...t, phases: [], done: 0, failed: 0, active: false })
      const g = map.get(t.tactic)!
      g.phases.push(p.phase)
      if (p.last_status === 'succeeded') g.done++
      if (p.last_status === 'failed') g.failed++
      if (p.phase === s.engagement.current_phase) g.active = true
    }
    return [...map.values()]
  }, [s])

  const services = useMemo(() => {
    if (!s) return []
    const counts = new Map<string, { open: number; hosts: Set<string> }>()
    for (const t of s.targets) {
      for (const p of t.open_ports || []) {
        const svc = (p.service || 'unknown').toLowerCase()
        if (!counts.has(svc)) counts.set(svc, { open: 0, hosts: new Set() })
        const e = counts.get(svc)!
        e.open++
        e.hosts.add(t.ip)
      }
    }
    return [...counts.entries()]
      .map(([svc, e]) => ({ svc, open: e.open, hosts: e.hosts.size }))
      .sort((a, b) => b.open - a.open)
      .slice(0, 8)
  }, [s])
  const maxSvc = Math.max(1, ...services.map(x => x.open))

  const spark = useMemo(() => {
    if (!s) return []
    // commands per phase 1..18 as mini bar sparkline
    return s.phase_grid.map(p => ({ phase: p.phase, n: p.commands, ok: p.succeeded, bad: p.failed }))
  }, [s])
  const maxSpark = Math.max(1, ...spark.map(x => x.n))

  const graphNodes = useMemo(() => {
    if (!s) return { hosts: [], creds: [] as any[] }
    return { hosts: s.targets.slice(0, 6), creds: s.credentials.slice(0, 6) }
  }, [s])

  const tickerItems = useMemo(() => wsEvents.slice(-20).reverse(), [wsEvents])

  if (snapQ.isLoading) return <div className="text-xs p-3 ax-fg-muted">Loading visual analytics…</div>
  if (!s) return null

  return (
    <div className="ax-card ax-border-base rounded">
      <div className="px-3 py-2 border-b ax-border-base flex items-center justify-between">
        <div className="text-xs font-semibold tracking-widest ax-accent">VISUAL ANALYTICS — KILL-CHAIN INTEL</div>
        <div className="text-[10px] ax-fg-muted">ring • mitre • services • attack graph • ticker</div>
      </div>

      <div className="grid grid-cols-12 gap-0">
        {/* Left: ring + heatmap */}
        <div className="col-span-4 p-3 space-y-3 border-r ax-border-base">
          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">KILL-CHAIN PROGRESS</div>
            <Donut {...ring} />
            <div className="grid grid-cols-4 gap-1 mt-2 text-center text-[10px]">
              <div><div className="font-bold ax-success font-mono text-sm">{ring.completed}</div><div className="ax-fg-muted">done</div></div>
              <div><div className="font-bold ax-accent font-mono text-sm">{ring.active}</div><div className="ax-fg-muted">active</div></div>
              <div><div className="font-bold ax-danger font-mono text-sm">{ring.failed}</div><div className="ax-fg-muted">failed</div></div>
              <div><div className="font-bold ax-fg-2 font-mono text-sm">{ring.pending}</div><div className="ax-fg-muted">pending</div></div>
            </div>
          </div>

          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">MITRE TACTIC COVERAGE</div>
            <div className="space-y-1 max-h-56 overflow-auto">
              {tacticGroups.map(g => {
                const pct = g.phases.length ? Math.round((g.done / g.phases.length) * 100) : 0
                const bg = g.failed > 0 ? 'var(--danger-soft)' : pct === 100 ? 'var(--success-soft)' : g.active ? 'var(--accent-soft)' : 'var(--bg-elevated)'
                return (
                  <div key={g.tactic} className="rounded px-2 py-1 border ax-border-base" style={{ background: bg }} title={`Phases ${g.phases.join(', ')}`}>
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="font-semibold ax-fg truncate">{g.tactic}</span>
                      <span className="ax-fg-muted font-mono ml-2 flex-shrink-0">{g.code} • P{g.phases.join('/')}</span>
                    </div>
                    <div className="h-1 rounded mt-1" style={{ background: 'var(--bg-elevated)' }}>
                      <div className="h-1 rounded" style={{ width: `${pct}%`, background: g.failed > 0 ? 'var(--danger)' : 'var(--success)' }} />
                    </div>
                    <div className="text-[9px] ax-fg-muted mt-0.5">{g.done}/{g.phases.length} done{g.failed > 0 ? ` • ${g.failed} failed` : ''}{g.active ? ' • ACTIVE' : ''}</div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        {/* Middle: attack graph + services */}
        <div className="col-span-5 p-3 space-y-3 border-r ax-border-base">
          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">ATTACK GRAPH — OPERATOR → HOSTS → PORTS → CREDS</div>
            <svg viewBox="0 0 400 210" className="w-full" style={{ minHeight: 190 }}>
              {/* operator */}
              <circle cx="36" cy="105" r="15" fill="var(--accent)" />
              <text x="36" y="109" textAnchor="middle" fontSize="10" fontWeight="800" fill="var(--bg-deep)" fontFamily="monospace">OP</text>
              <text x="36" y="128" textAnchor="middle" fontSize="8" fill="var(--fg-muted)" fontFamily="monospace">operator</text>
              {graphNodes.hosts.length === 0 && (
                <text x="210" y="105" textAnchor="middle" fontSize="10" fill="var(--fg-muted)" fontFamily="monospace">no hosts yet — run P1 nmap</text>
              )}
              {graphNodes.hosts.map((h: any, i: number) => {
                const y = 30 + i * Math.max(34, 170 / Math.max(1, graphNodes.hosts.length))
                const openN = (h.open_ports || []).length
                const ports = (h.open_ports || []).slice(0, 4)
                return (
                  <g key={h.id}>
                    <line x1="51" y1="105" x2="130" y2={y} stroke="var(--accent)" strokeOpacity="0.45" strokeWidth="1.2" />
                    <circle cx="130" cy={y} r="12" fill={openN > 0 ? 'var(--success)' : 'var(--border-strong)'} />
                    <text x="130" y={y + 3.5} textAnchor="middle" fontSize="9" fontWeight="700" fill="var(--bg-deep)" fontFamily="monospace">{openN}</text>
                    <text x="148" y={y - 3} fontSize="10" fill="var(--fg-primary)" fontFamily="monospace">{h.ip}</text>
                    <text x="148" y={y + 9} fontSize="8" fill="var(--fg-muted)" fontFamily="monospace">P{h.discovered_in_phase || '?'} • {openN} open</text>
                    {ports.map((p: any, j: number) => (
                      <g key={j}>
                        <line x1="200" y1={y} x2="248" y2={y - 12 + j * 9} stroke="var(--border-strong)" strokeWidth="1" />
                        <rect x="248" y={y - 17 + j * 9} width="66" height="11" rx="3" fill="var(--bg-elevated)" stroke="var(--border-base)" />
                        <text x="252" y={y - 9 + j * 9} fontSize="7.5" fill="var(--fg-secondary)" fontFamily="monospace">{p.port}/{p.protocol} {String(p.service || '').slice(0, 10)}</text>
                      </g>
                    ))}
                  </g>
                )
              })}
              {/* creds column */}
              {graphNodes.creds.map((c: any, i: number) => (
                <g key={c.id}>
                  <line x1="314" y1="105" x2="348" y2={30 + i * 30} stroke="var(--warn)" strokeOpacity="0.4" strokeWidth="1" strokeDasharray="3 2" />
                  <rect x="348" y={22 + i * 30} width="48" height="16" rx="3" fill="var(--warn-soft)" stroke="var(--warn)" />
                  <text x="372" y={34 + i * 30} textAnchor="middle" fontSize="8" fill="var(--warn)" fontFamily="monospace">{String(c.user || '?').slice(0, 8)}</text>
                </g>
              ))}
              {graphNodes.creds.length > 0 && (
                <text x="372" y="200" textAnchor="middle" fontSize="8" fill="var(--fg-muted)" fontFamily="monospace">creds ({s.credentials.length})</text>
              )}
            </svg>
          </div>

          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">SERVICE DISTRIBUTION (open ports)</div>
            {services.length === 0 && <div className="text-[11px] ax-fg-muted">no open ports discovered yet</div>}
            <div className="space-y-1">
              {services.map(x => (
                <div key={x.svc} className="text-[10px]">
                  <div className="flex justify-between">
                    <span className="ax-accent font-mono truncate">{x.svc}</span>
                    <span className="ax-fg-muted font-mono">{x.open} open • {x.hosts} host{x.hosts === 1 ? '' : 's'}</span>
                  </div>
                  <div className="h-1.5 rounded" style={{ background: 'var(--bg-elevated)' }}>
                    <div className="h-1.5 rounded" style={{ width: `${(x.open / maxSvc) * 100}%`, background: 'var(--accent)' }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: sparkline + ticker */}
        <div className="col-span-3 p-3 space-y-3">
          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">COMMANDS PER PHASE</div>
            <div className="flex items-end gap-[3px] h-20">
              {spark.map(b => (
                <div key={b.phase} className="flex-1 flex flex-col items-center gap-1" title={`P${b.phase}: ${b.n} cmds (${b.ok} ok / ${b.bad} failed)`}>
                  <div className="w-full rounded-sm" style={{ height: `${Math.max(4, (b.n / maxSpark) * 64)}px`, background: b.bad > 0 ? 'var(--danger)' : b.n > 0 ? 'var(--accent)' : 'var(--border-strong)', opacity: b.n > 0 ? 1 : 0.5 }} />
                  <span className="text-[8px] font-mono" style={{ color: b.phase === s.engagement.current_phase ? 'var(--accent)' : 'var(--fg-muted)' }}>{b.phase}</span>
                </div>
              ))}
            </div>
            <div className="text-[9px] ax-fg-muted mt-1 font-mono">tallest = {maxSpark} cmds • red = has failures • number = phase</div>
          </div>

          <div className="ax-input border ax-border-base rounded p-2">
            <div className="text-[11px] ax-fg-2 font-mono mb-1">LIVE EVENT TICKER <span className="ax-accent">({wsEvents.length})</span></div>
            <div className="h-44 overflow-hidden relative">
              <div className="ax-ticker space-y-1">
                {tickerItems.length === 0 && <div className="text-[10px] ax-fg-muted font-mono">awaiting WS events… run a command or chain</div>}
                {tickerItems.map((e: any, i: number) => (
                  <div key={`${e._ts}-${i}`} className="text-[10px] font-mono border-l-2 pl-1.5 truncate" style={{ borderColor: e.type === 'ai_pivot' ? 'var(--danger)' : e.type?.startsWith('ai_chain') ? 'var(--accent)' : 'var(--success)' }}>
                    <span className="ax-accent">{EVENT_ICON[e.type] ?? '•'}</span>{' '}
                    <span className="ax-fg">{e.type}</span>{' '}
                    <span className="ax-fg-muted">{e.phase ? `P${e.phase} ` : ''}{e.tool ?? e.tool_name ?? ''}{e.status ? ` → ${e.status}` : ''}{e.exit_code != null ? `(${e.exit_code})` : ''}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="ax-input border ax-border-base rounded p-2 text-[10px] font-mono">
            <div className="ax-fg-2 mb-1">SESSION</div>
            <div className="flex justify-between"><span className="ax-fg-muted">engagement</span><span className="ax-fg truncate ml-2">{s.engagement.name}</span></div>
            <div className="flex justify-between"><span className="ax-fg-muted">scope</span><span className="ax-accent">{s.engagement.scope_cidr}</span></div>
            <div className="flex justify-between"><span className="ax-fg-muted">status</span><span className="ax-fg">{s.engagement.status}</span></div>
            <div className="flex justify-between"><span className="ax-fg-muted">snapshot</span><span className="ax-fg-muted">{(s.ts || '').slice(11, 19)}</span></div>
          </div>
        </div>
      </div>
    </div>
  )
}
