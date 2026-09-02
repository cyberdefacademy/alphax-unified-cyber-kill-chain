export default function AttackFlow({ currentPhase, onSelect }: { currentPhase: number; onSelect: (p:number)=>void }) {
  const phases = [
    [1,"Recon"],[2,"Weapon"],[3,"Delivery"],[4,"Social"],[5,"Exploit"],[6,"Persist"],[7,"Evade"],[8,"C2"],[9,"Pivot"],[10,"Discover"],[11,"PrivEsc"],[12,"Execute"],[13,"Creds"],[14,"Lateral"],[15,"Collect"],[16,"Exfil"],[17,"Impact"],[18,"Objectives"]
  ] as const
  return (
    <div className="bg-slate-900 border border-slate-800 rounded p-3">
      <div className="text-[11px] tracking-widest text-slate-400 mb-2">ATTACK FLOW — UNIFIED CYBER KILL CHAIN (18 PHASES)</div>
      <div className="flex items-center gap-1 overflow-x-auto pb-2">
        {phases.map(([id,label], idx)=>(
          <div key={id} className="flex items-center gap-1">
            <button onClick={()=>onSelect(id)} className={`min-w-[74px] px-2 py-2 rounded border text-[11px] font-semibold text-center transition ${id===currentPhase ? 'bg-cyan-400 text-slate-900 border-cyan-300 shadow shadow-cyan-400/30 scale-105' : id<currentPhase ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-slate-800 text-slate-400 border-slate-700 hover:border-slate-600'}`}>
              <div className="text-[10px] opacity-70">{id}</div>
              <div>{label}</div>
            </button>
            {idx < phases.length-1 && <div className={`w-4 h-0.5 ${id < currentPhase ? 'bg-emerald-500' : 'bg-slate-700'}`} />}
          </div>
        ))}
      </div>
      <div className="text-xs text-slate-500">Click any phase to open its tool panel. Current phase highlighted in cyan; completed in emerald. Transitions logged to Live Console.</div>
    </div>
  )
}
