export default function KnowledgeGraph({ targets, credentials, commands }: { targets: any[]; credentials: any[]; commands: any[] }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded p-3 space-y-3">
      <div className="text-xs font-semibold tracking-widest text-slate-400">ATTACK KNOWLEDGE GRAPH</div>
      <div>
        <div className="text-xs text-slate-300 mb-1">Hosts ({targets.length})</div>
        {targets.length ? <div className="space-y-1">
          {targets.map((t:any)=>(
            <div key={t.id} className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs">
              <span className="font-mono text-cyan-300">{t.ip}</span>
              <span className="text-slate-400 truncate ml-2">{t.hostname || '—'} • {(t.ports ?? []).filter((p:any)=>p.state==='open').length} open</span>
              <span className="text-[10px] text-slate-500 ml-2">P{t.discovered_in_phase ?? '?'}</span>
            </div>
          ))}
        </div> : <div className="text-xs text-slate-500">No hosts discovered — run Reconnaissance nmap first.</div>}
      </div>
      <div>
        <div className="text-xs text-slate-300 mb-1">Credentials ({credentials.length})</div>
        {credentials.length ? credentials.map((c:any)=><div key={c.id} className="text-xs font-mono bg-slate-950 border border-slate-800 rounded px-2 py-1">{c.username} — {c.hash_type || 'clear'} {c.cracked ? '✓ cracked':''}</div>) : <div className="text-xs text-slate-500">No creds yet — Credential Access phase will populate.</div>}
      </div>
      <div className="text-[11px] text-slate-500">Edges: discovery → pivot → lateral movement inferred from commands. Parser auto-feeds nmap hosts into next phases.</div>
    </div>
  )
}
