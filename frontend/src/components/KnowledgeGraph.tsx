export default function KnowledgeGraph({ targets, credentials, commands }: { targets: any[]; credentials: any[]; commands: any[] }) {
  return (
    <div className="ax-card border ax-border-base rounded p-3 space-y-3">
      <div className="text-xs font-semibold tracking-widest ax-fg-2">ATTACK KNOWLEDGE GRAPH</div>
      <div>
        <div className="text-xs ax-fg-2 mb-1">Hosts ({targets.length})</div>
        {targets.length ? <div className="space-y-1">
          {targets.map((t:any)=>(
            <div key={t.id} className="flex items-center justify-between ax-input border ax-border-base rounded px-2 py-1 text-xs">
              <span className="font-mono ax-accent">{t.ip}</span>
              <span className="ax-fg-2 truncate ml-2">{t.hostname || '—'} • {(t.ports ?? []).filter((p:any)=>p.state==='open').length} open</span>
              <span className="text-[10px] ax-fg-muted ml-2">P{t.discovered_in_phase ?? '?'}</span>
            </div>
          ))}
        </div> : <div className="text-xs ax-fg-muted">No hosts discovered — run Reconnaissance nmap first.</div>}
      </div>
      <div>
        <div className="text-xs ax-fg-2 mb-1">Credentials ({credentials.length})</div>
        {credentials.length ? credentials.map((c:any)=><div key={c.id} className="text-xs font-mono ax-input border ax-border-base rounded px-2 py-1">{c.username} — {c.hash_type || 'clear'} {c.cracked ? '✓ cracked':''}</div>) : <div className="text-xs ax-fg-muted">No creds yet — Credential Access phase will populate.</div>}
      </div>
      <div className="text-[11px] ax-fg-muted">Edges: discovery → pivot → lateral movement inferred from commands. Parser auto-feeds nmap hosts into next phases.</div>
    </div>
  )
}
