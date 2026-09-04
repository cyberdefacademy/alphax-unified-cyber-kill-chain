import { useEffect, useRef } from 'react'

export default function LiveConsole({ lines, wsStatus, onClear, engagementId }: { lines: string[]; wsStatus: string; onClear: ()=>void; engagementId: string }) {
  const ref = useRef<HTMLPreElement>(null)
  useEffect(()=>{ if(ref.current) ref.current.scrollTop = ref.current.scrollHeight }, [lines])
  return (
    <div className="bg-[#0a0f1e] border ax-border-base rounded overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b ax-border-base ax-card/50">
        <div className="text-xs font-semibold tracking-widest">LIVE OUTPUT CONSOLE — stdout / stderr — {engagementId.slice(0,8)} — WS {wsStatus}</div>
        <button onClick={onClear} className="text-xs px-2 py-1 rounded ax-btn-secondary border ax-border-base hover:ax-bg-elevated">Clear</button>
      </div>
      <pre ref={ref} className="h-[360px] overflow-auto p-3 text-[12px] leading-4 font-mono ax-success whitespace-pre-wrap break-words">
        {lines.length ? lines.join('') : <span className="ax-fg-muted"># awaiting command execution — approve & execute from Phase panel. Raw nmap/msfvenom/hydra output will stream here line-by-line.</span>}
      </pre>
    </div>
  )
}
