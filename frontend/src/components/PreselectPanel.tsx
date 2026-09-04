import { useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { useState, useEffect } from 'react'

const NMAP_CATS = ['all', 'scan_type', 'service', 'os', 'script', 'combo', 'discovery', 'ports', 'timing', 'evasion', 'output', 'general', 'dns']

export default function PreselectPanel({ engagementId, token, currentPhase, onPicked, onPreset }: { engagementId: string; token: string; currentPhase: number; onPicked: (tool: string, params: Record<string, string>, raw: string) => void; onPreset: (preset: any) => void }) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  const qc = useQueryClient()
  const [tab, setTab] = useState<'nmap_opts' | 'nse' | 'kali' | 'presets' | 'search'>('presets')
  const [nmapCat, setNmapCat] = useState('all')
  const [nseCat, setNseCat] = useState('all')
  const [nseSearch, setNseSearch] = useState('')
  const [kaliCat, setKaliCat] = useState('all')
  const [globalQ, setGlobalQ] = useState('')
  const [picked, setPicked] = useState<any | null>(null)

  const nmapOptsQ = useQuery({
    queryKey: ['lib-nmap-opts', nmapCat],
    enabled: !!token && tab === 'nmap_opts',
    queryFn: async () => (await axios.get(`/api/v1/library/nmap/options?category=${nmapCat}`, { headers })).data,
  })

  const nseQ = useQuery({
    queryKey: ['lib-nse', nseCat, nseSearch],
    enabled: !!token && tab === 'nse',
    queryFn: async () => {
      const p = new URLSearchParams()
      if (nseCat && nseCat !== 'all') p.append('category', nseCat)
      if (nseSearch) p.append('search', nseSearch)
      p.append('limit', '200')
      return (await axios.get(`/api/v1/library/nmap/scripts?${p}`, { headers })).data
    },
  })

  const kaliQ = useQuery({
    queryKey: ['lib-kali', kaliCat, currentPhase],
    enabled: !!token && tab === 'kali',
    queryFn: async () => {
      const p = new URLSearchParams()
      if (kaliCat && kaliCat !== 'all') p.append('category', kaliCat)
      p.append('phase', String(currentPhase))
      return (await axios.get(`/api/v1/library/kali?${p}`, { headers })).data
    },
  })

  const presetsQ = useQuery({
    queryKey: ['lib-presets', currentPhase],
    enabled: !!token && tab === 'presets',
    queryFn: async () => (await axios.get(`/api/v1/library/presets?phase=${currentPhase}`, { headers })).data,
  })

  const searchQ = useQuery({
    queryKey: ['lib-search', globalQ],
    enabled: !!token && tab === 'search' && globalQ.length >= 2,
    queryFn: async () => (await axios.get(`/api/v1/library/search?q=${encodeURIComponent(globalQ)}`, { headers })).data,
  })

  const copy = (text: string) => {
    try { navigator.clipboard.writeText(text) } catch {}
  }

  const insertTool = (tool: any) => {
    onPicked(tool.cmd, tool.phases ? {} : {}, tool.cmd)
    setPicked(tool)
  }

  const insertPreset = (p: any) => {
    onPicked(p.tool, p.params || {}, p.template)
    onPreset(p)
    setPicked(p)
  }

  const insertFlag = (flag: string) => {
    onPicked('nmap', { scan_type: flag, ports: '', extra: '', target: '' }, '')
    setPicked({ name: `flag ${flag}`, type: 'nmap_opt' })
  }

  return (
    <div className="ax-card border ax-border-base rounded">
      <div className="px-3 py-2 border-b ax-border-base flex items-center gap-2 flex-wrap">
        <div className="text-xs font-semibold tracking-widest ax-success">PRESELECT — SCRIPT LIBRARY</div>
        <div className="ml-auto flex gap-1 text-[10px]">
          {(['presets', 'nmap_opts', 'nse', 'kali', 'search'] as const).map(t => (
            <button key={t} onClick={() => setTab(t)} className={`px-2 py-1 rounded border ${tab===t ? 'ax-btn-primary //20 border-emerald-500 ax-success' : 'ax-input ax-border-base ax-fg-2'}`}>
              {t === 'nmap_opts' ? 'Nmap Opts' : t === 'nse' ? 'NSE' : t.charAt(0).toUpperCase()+t.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="p-3 space-y-2">
        {/* Global search */}
        {tab === 'search' && (
          <input value={globalQ} onChange={e => setGlobalQ(e.target.value)} placeholder="search nmap / nse / kali / presets…" className="w-full ax-input border ax-border-base rounded px-3 py-1.5 text-xs" />
        )}

        {/* PRESETS */}
        {tab === 'presets' && (
          <div className="space-y-1 max-h-72 overflow-auto">
            <div className="text-[10px] ax-fg-muted">{presetsQ.data?.count ?? '…'} curated preset(s) for P{currentPhase}</div>
            {(presetsQ.data?.items ?? []).map((p: any) => (
              <button key={p.id} onClick={() => insertPreset(p)} className="w-full text-left ax-input hover:ax-btn-secondary border ax-border-base rounded px-2 py-1.5">
                <div className="text-[11px] font-semibold ax-success">{p.label}</div>
                <div className="text-[10px] ax-fg-muted font-mono truncate">{p.template}</div>
                <div className="text-[10px] ax-fg-muted">P{p.phase} • {p.tool} • {p.tags?.join(' • ')}</div>
              </button>
            ))}
            {!presetsQ.isLoading && (presetsQ.data?.items ?? []).length === 0 && (
              <div className="text-[11px] ax-fg-muted">No presets for P{currentPhase} — switch tabs to browse raw catalog.</div>
            )}
          </div>
        )}

        {/* NMAP OPTIONS */}
        {tab === 'nmap_opts' && (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1">
              {NMAP_CATS.map(c => (
                <button key={c} onClick={() => setNmapCat(c)} className={`px-2 py-0.5 rounded text-[10px] ${nmapCat===c?'ax-btn-primary //20 border border-emerald-500 ax-success':'ax-input border ax-border-base ax-fg-2'}`}>
                  {c}
                </button>
              ))}
            </div>
            <div className="max-h-72 overflow-auto space-y-1">
              {(nmapOptsQ.data?.items ?? []).map((o: any) => (
                <div key={o.flag} className="ax-input border ax-border-base rounded px-2 py-1.5 text-[11px] flex items-center gap-2">
                  <code onClick={() => insertFlag(o.flag)} className="ax-accent cursor-pointer font-bold w-44 flex-shrink-0 hover:underline" title="Click to insert as scan_type">{o.flag}</code>
                  <span className="ax-fg-2 truncate">{o.name} — {o.desc}</span>
                  <button onClick={() => copy(o.flag)} className="ml-auto px-1 py-0.5 text-[10px] ax-btn-secondary border ax-border-base rounded ax-fg-2">copy</button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* NSE SCRIPTS */}
        {tab === 'nse' && (
          <div className="space-y-2">
            <div className="flex gap-2 items-center flex-wrap">
              <input value={nseSearch} onChange={e => setNseSearch(e.target.value)} placeholder="search 612 NSE scripts…" className="flex-1 min-w-[180px] ax-input border ax-border-base rounded px-2 py-1 text-xs" />
              <select value={nseCat} onChange={e => setNseCat(e.target.value)} className="ax-input border ax-border-base rounded px-2 py-1 text-[11px]">
                <option value="all">all</option>
                <option value="safe">safe</option>
                <option value="vuln">vuln</option>
                <option value="auth">auth</option>
                <option value="brute">brute</option>
                <option value="discovery">discovery</option>
                <option value="broadcast">broadcast</option>
                <option value="exploit">exploit</option>
                <option value="default">default</option>
                <option value="malware">malware</option>
                <option value="intrusive">intrusive</option>
                <option value="fuzzer">fuzzer</option>
                <option value="dos">dos</option>
                <option value="external">external</option>
                <option value="version">version</option>
              </select>
            </div>
            <div className="text-[10px] ax-fg-muted">{nseQ.data?.count ?? '…'} match(es)</div>
            <div className="max-h-72 overflow-auto space-y-1">
              {(nseQ.data?.items ?? []).map((s: any) => (
                <div key={s.name} className="ax-input border ax-border-base rounded px-2 py-1.5 text-[11px]">
                  <div className="flex items-center gap-2">
                    <code onClick={() => insertTool({ cmd: 'nmap', name: s.name })} className="ax-accent font-mono font-bold cursor-pointer hover:underline" title="Click to use nmap script">{s.name}</code>
                    <span className="text-[9px] ax-fg-muted">[{s.categories?.join(' / ') || s.prefix}]</span>
                    <button onClick={() => copy(`--script=${s.name}`)} className="ml-auto text-[9px] px-1 ax-btn-secondary border ax-border-base rounded ax-fg-2">copy</button>
                  </div>
                  <div className="text-[10px] ax-fg-2 truncate">{s.desc || '(no description)'}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* KALI TOOLS */}
        {tab === 'kali' && (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1">
              <button onClick={() => setKaliCat('all')} className={`px-2 py-0.5 rounded text-[10px] ${kaliCat==='all'?'ax-btn-primary //20 border border-emerald-500 ax-success':'ax-input border ax-border-base ax-fg-2'}`}>all</button>
              {['reconnaissance','credential-access','lateral-movement','execution','privilege-escalation','defense-evasion','discovery','forensics','command-and-control'].map(c => (
                <button key={c} onClick={() => setKaliCat(c)} className={`px-2 py-0.5 rounded text-[10px] ${kaliCat===c?'ax-btn-primary //20 border border-emerald-500 ax-success':'ax-input border ax-border-base ax-fg-2'}`}>
                  {c}
                </button>
              ))}
            </div>
            <div className="text-[10px] ax-fg-muted">{kaliQ.data?.count ?? '…'} tool(s) tagged for P{currentPhase} + {kaliCat}</div>
            <div className="max-h-72 overflow-auto space-y-1">
              {(kaliQ.data?.items ?? []).map((t: any) => (
                <div key={t.slug} className="ax-input border ax-border-base rounded px-2 py-1.5 text-[11px]">
                  <div className="flex items-center gap-2">
                    <code onClick={() => insertTool(t)} className="ax-accent font-mono font-bold cursor-pointer hover:underline" title={`Click to use ${t.cmd}`}>{t.name}</code>
                    <span className="text-[9px] ax-fg-muted">cmd: {t.cmd}</span>
                    <a href={t.url} target="_blank" rel="noreferrer" className="ml-auto text-[9px] ax-fg-muted hover:ax-accent">kali.org ↗</a>
                  </div>
                  <div className="text-[10px] ax-fg-2">{t.desc}</div>
                </div>
              ))}
              {!kaliQ.isLoading && (kaliQ.data?.items ?? []).length === 0 && (
                <div className="text-[11px] ax-fg-muted">No tools match. Try another category or switch to P{currentPhase}.</div>
              )}
            </div>
          </div>
        )}

        {/* SEARCH */}
        {tab === 'search' && globalQ.length >= 2 && (
          <div className="space-y-2 max-h-72 overflow-auto">
            <div className="text-[10px] ax-fg-muted">
              {(searchQ.data?.nmap_options?.length ?? 0)} opts • {(searchQ.data?.nse_scripts?.length ?? 0)} NSE • {(searchQ.data?.kali_tools?.length ?? 0)} tools • {(searchQ.data?.presets?.length ?? 0)} presets
            </div>
            {searchQ.data?.nmap_options?.map((o: any) => (
              <div key={o.flag} className="ax-input border ax-border-base rounded px-2 py-1 text-[11px]"><code className="ax-accent">{o.flag}</code> {o.name}</div>
            ))}
            {searchQ.data?.nse_scripts?.map((s: any) => (
              <div key={s.name} className="ax-input border ax-border-base rounded px-2 py-1 text-[11px]"><code className="ax-accent">{s.name}</code> — {s.desc?.slice(0,80)}</div>
            ))}
            {searchQ.data?.kali_tools?.map((t: any) => (
              <div key={t.slug} className="ax-input border ax-border-base rounded px-2 py-1 text-[11px]"><code className="ax-accent">{t.name}</code> — {t.desc} <span className="ax-fg-muted">({t.category})</span></div>
            ))}
            {searchQ.data?.presets?.map((p: any) => (
              <button key={p.id} onClick={() => insertPreset(p)} className="block w-full text-left ax-input hover:ax-btn-secondary border ax-border-base rounded px-2 py-1 text-[11px]">
                <span className="ax-success">{p.label}</span> <span className="ax-fg-muted">P{p.phase} {p.tool}</span>
              </button>
            ))}
            {searchQ.isLoading && <div className="text-[11px] ax-fg-muted">searching…</div>}
          </div>
        )}

        {picked && (
          <div className=" border border-emerald-700/40 rounded p-2 text-[10px]">
            <div className="ax-success font-bold">inserted → {picked.name || picked.label}</div>
            {picked.template && <div className="ax-fg-2 font-mono truncate">{picked.template}</div>}
            <div className="ax-fg-muted">go to PhasePanel → click 1. Create Command → 2. Approve → 3. Execute</div>
          </div>
        )}
      </div>
    </div>
  )
}
