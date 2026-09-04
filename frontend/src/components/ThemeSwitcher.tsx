import { useEffect, useState } from 'react'

export type ThemeId = 'neon' | 'tactical' | 'crimson' | 'midnight'

export const THEMES: Array<{ id: ThemeId; name: string; tagline: string; swatch: string[] }> = [
  { id: 'neon',     name: 'Neon Cyan',     tagline: 'Default — Director Console', swatch: ['#060a12', '#0f172a', '#22d3ee', '#22c55e', '#f43f5e'] },
  { id: 'tactical',  name: 'Tactical Green', tagline: 'SOC Analyst — CRT phosphor', swatch: ['#04110a', '#0a1f12', '#4ade80', '#86efac', '#f87171'] },
  { id: 'crimson',  name: 'Cyber Crimson', tagline: 'Red Team — Threat Intel',     swatch: ['#150407', '#240911', '#f43f5e', '#fb7185', '#fbbf24'] },
  { id: 'midnight', name: 'Midnight Ops',   tagline: 'NSO / Aerospace — Steel + Gold', swatch: ['#05060b', '#0b0d15', '#fbbf24', '#c084fc', '#5eead4'] },
]

const STORAGE_KEY = 'alphax_theme'

export function useTheme() {
  const [theme, setTheme] = useState<ThemeId>(() => {
    if (typeof window === 'undefined') return 'neon'
    const stored = localStorage.getItem(STORAGE_KEY) as ThemeId | null
    return stored && THEMES.find(t => t.id === stored) ? stored : 'neon'
  })

  useEffect(() => {
    const root = document.documentElement
    root.setAttribute('data-theme', theme)
    localStorage.setItem(STORAGE_KEY, theme)
  }, [theme])

  return { theme, setTheme, themes: THEMES }
}

export function ThemeSwitcher() {
  const { theme, setTheme, themes } = useTheme()
  const [open, setOpen] = useState(false)
  const current = themes.find(t => t.id === theme)!

  return (
    <div className="relative">
      <button onClick={() => setOpen(o => !o)} className="ax-btn-secondary rounded px-3 py-1.5 text-[11px] font-semibold tracking-widest flex items-center gap-2" title="Switch dashboard theme">
        <span className="ax-pulse">{current.name}</span>
        <svg width="10" height="10" viewBox="0 0 10 10" className="opacity-60"><path d="M1 3l4 4 4-4" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" /></svg>
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-30" onClick={() => setOpen(false)} />
          <div className="absolute right-0 mt-2 w-80 ax-card ax-glow z-40 p-3 space-y-1">
            <div className="text-[10px] tracking-widest ax-fg-muted mb-1 px-1">DASHBOARD THEME</div>
            {themes.map(t => (
              <button key={t.id} onClick={() => { setTheme(t.id); setOpen(false) }} className={`w-full text-left rounded p-2 flex items-center gap-2 transition ${t.id === theme ? 'ring-1' : 'hover:opacity-90'}`}
                style={{
                  backgroundColor: t.id === theme ? t.swatch[1] : 'transparent',
                  boxShadow: t.id === theme ? `0 0 0 1px ${t.swatch[2]}` : 'none',
                }}
              >
                <div className="flex gap-1">
                  {t.swatch.map((c, i) => (
                    <div key={i} className="w-3 h-6 rounded-sm" style={{ backgroundColor: c, boxShadow: i === 2 ? `0 0 6px ${c}` : 'none' }} />
                  ))}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-[12px] font-semibold ax-fg flex items-center gap-1.5">
                    {t.name}
                    {t.id === theme && <span className="ax-pill ax-fg-2" style={{ fontSize: 9, padding: '1px 5px' }}>active</span>}
                  </div>
                  <div className="text-[10px] ax-fg-muted truncate">{t.tagline}</div>
                </div>
              </button>
            ))}
            <div className="border-t pt-2 mt-1" style={{ borderColor: 'var(--border-base)' }}>
              <label className="flex items-center gap-2 text-[10px] ax-fg-2 px-1 cursor-pointer">
                <input
                  type="checkbox"
                  checked={typeof document !== 'undefined' && document.documentElement.classList.contains('ax-scanlines')}
                  onChange={(e) => {
                    document.documentElement.classList.toggle('ax-scanlines', e.target.checked)
                    localStorage.setItem('alphax_scanlines', String(e.target.checked))
                  }}
                  className="accent-current"
                  style={{ accentColor: 'var(--accent)' }}
                />
                Scanline overlay (CRT vibe)
              </label>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
