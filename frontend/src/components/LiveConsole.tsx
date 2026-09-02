import { useEffect, useRef } from 'react'

export default function LiveConsole({ lines, wsStatus, onClear, engagementId }: { lines: string[]; wsStatus: string; onClear: ()=>void; engagementId: string }) {
  const ref = useRef<HTMLPreElement>(null)
  useEffect(()=>{ if(ref.current) ref.current.scrollTop = ref.current.scrollHeight }, [lines])
  return (
    <div className="bg-[#0a0f1e] border border-slate-800 rounded overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-slate-900/50">
        <div className="text-xs font-semibold tracking-widest">LIVE OUTPUT CONSOLE — stdout / stderr — {engagementId.slice(0,8)} — WS {wsStatus}</div>
        <button onClick={onClear} className="text-xs px-2 py-1 rounded bg-slate-800 border border-slate-700 hover:bg-slate-700">Clear</button>
      </div>
      <pre ref={ref} className="h-[360px] overflow-auto p-3 text-[12px] leading-4 font-mono text-emerald-300 whitespace-pre-wrap break-words">
        {lines.length ? lines.join('') : <span className="text-slate-500"># awaiting command execution — approve & execute from Phase panel. Raw nmap/msfvenom/hydra output will stream here line-by-line.</span>}
      </pre>
    </div>
  )
}
