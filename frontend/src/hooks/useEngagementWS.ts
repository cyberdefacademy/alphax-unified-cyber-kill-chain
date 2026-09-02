import { useEffect, useRef, useState } from 'react'

export function useEngagementWS(engagementId: string) {
  const [lines, setLines] = useState<string[]>([])
  const [status, setStatus] = useState<'disconnected'|'connected'>('disconnected')
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!engagementId) return
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    // API on 8001 due to 8000 occupied by NeuroSploit; proxy also available via /ws
    const port = location.port === '3000' || location.port === '3001' || location.port === '3002' ? '8001' : '8001'
    const url = `${proto}//${location.hostname}:${port}/ws/engagements/${engagementId}`
    const ws = new WebSocket(url)
    wsRef.current = ws
    ws.onopen = () => setStatus('connected')
    ws.onclose = () => setStatus('disconnected')
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'console' && msg.line) setLines(prev => [...prev.slice(-2000), msg.line])
        else if (msg.type === 'command_finished') setLines(prev => [...prev, `\n[FINISHED ${msg.status} exit=${msg.exit_code}]\n`])
        else if (msg.type === 'knowledge_update') setLines(prev => [...prev, `\n[KNOWLEDGE] new host ${msg.target?.ip}\n`])
        else if (msg.type === 'ai_pivot') {
          const sug = (msg.suggestions || []).map((s: any) => `  - [${s.type}] ${s.action || s.tool_name || s.reason}`).join('\n')
          setLines(prev => [...prev, `\n[AI PIVOT] P${msg.phase} ${msg.failed_tool} (exit ${msg.exit_code}):\n${sug}\n`])
        }
        else if (msg.type === 'ai_chain_step') setLines(prev => [...prev, `\n[AI CHAIN] P${msg.phase} ${msg.tool} ${msg.status}${msg.command_id ? ' cmd='+msg.command_id.slice(0,8) : ''}${msg.rationale ? ' — '+msg.rationale : ''}\n`])
        else if (msg.type === 'ai_chain_step_finished') setLines(prev => [...prev, `[AI CHAIN] P${msg.phase} ${msg.tool} → ${msg.status} exit=${msg.exit_code}\n`])
        else if (msg.type === 'ai_chain_halted') setLines(prev => [...prev, `[AI CHAIN] halted @P${msg.phase} — ${msg.reason}\n`])
        else if (msg.type === 'command_approved') setLines(prev => [...prev, `[APPROVED] ${msg.command_id}\n`])
        else setLines(prev => [...prev, JSON.stringify(msg)])
      } catch { setLines(prev => [...prev, ev.data]) }
    }
    return () => ws.close()
  }, [engagementId])

  const clear = () => setLines([])
  return { lines, status, clear }
}
