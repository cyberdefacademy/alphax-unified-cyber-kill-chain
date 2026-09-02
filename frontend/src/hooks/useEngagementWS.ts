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
        else setLines(prev => [...prev, JSON.stringify(msg)])
      } catch { setLines(prev => [...prev, ev.data]) }
    }
    return () => ws.close()
  }, [engagementId])

  const clear = () => setLines([])
  return { lines, status, clear }
}
