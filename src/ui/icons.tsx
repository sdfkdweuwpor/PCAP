// Small inline icon set (stroke icons, 24px grid). Decorative unless given a title.
import type { SVGProps } from 'react'

type P = SVGProps<SVGSVGElement> & { size?: number }
const base = ({ size = 16, ...p }: P) => ({
  width: size,
  height: size,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
  ...p,
})

export const IconUpload = (p: P) => (<svg {...base(p)}><path d="M12 16V4" /><path d="m6 10 6-6 6 6" /><path d="M4 20h16" /></svg>)
export const IconShield = (p: P) => (<svg {...base(p)}><path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z" /><path d="m9 12 2 2 4-4" /></svg>)
export const IconPlay = (p: P) => (<svg {...base(p)}><path d="M7 5v14l12-7z" fill="currentColor" /></svg>)
export const IconPause = (p: P) => (<svg {...base(p)}><path d="M8 5v14M16 5v14" /></svg>)
export const IconStepBack = (p: P) => (<svg {...base(p)}><path d="M6 5v14" /><path d="M18 5 9 12l9 7z" /></svg>)
export const IconStepFwd = (p: P) => (<svg {...base(p)}><path d="M18 5v14" /><path d="m6 5 9 7-9 7z" /></svg>)
export const IconEye = (p: P) => (<svg {...base(p)}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>)
export const IconEyeOff = (p: P) => (<svg {...base(p)}><path d="M3 3l18 18" /><path d="M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6C3.9 8.4 2 12 2 12s3.5 7 10 7a9.8 9.8 0 0 0 5.4-1.6" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /></svg>)
export const IconCheck = (p: P) => (<svg {...base(p)}><path d="m5 12 5 5 9-10" /></svg>)
export const IconX = (p: P) => (<svg {...base(p)}><path d="M6 6l12 12M18 6 6 18" /></svg>)
export const IconHalf = (p: P) => (<svg {...base(p)}><circle cx="12" cy="12" r="8" /><path d="M12 4v16" /><path d="M12 4a8 8 0 0 1 0 16z" fill="currentColor" /></svg>)
export const IconFlame = (p: P) => (<svg {...base(p)}><path d="M12 22c4 0 7-3 7-7 0-5-5-7-4-12-3 2-5 5-5 8-1-1-2-2-2-4-2 2-3 5-3 8 0 4 3 7 7 7z" fill="currentColor" fillOpacity=".25" /></svg>)
export const IconBulb = (p: P) => (<svg {...base(p)}><path d="M9 18h6M10 21h4" /><path d="M12 3a6 6 0 0 0-4 10.5c.7.7 1 1.5 1 2.5h6c0-1 .3-1.8 1-2.5A6 6 0 0 0 12 3z" /></svg>)
export const IconGear = (p: P) => (<svg {...base(p)}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" /></svg>)
export const IconSun = (p: P) => (<svg {...base(p)}><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></svg>)
export const IconMoon = (p: P) => (<svg {...base(p)}><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></svg>)
export const IconChevron = (p: P) => (<svg {...base(p)}><path d="m9 6 6 6-6 6" /></svg>)
export const IconArrowRight = (p: P) => (<svg {...base(p)}><path d="M5 12h14M13 6l6 6-6 6" /></svg>)
export const IconArrowLeft = (p: P) => (<svg {...base(p)}><path d="M19 12H5M11 6l-6 6 6 6" /></svg>)
export const IconFilter = (p: P) => (<svg {...base(p)}><path d="M3 5h18l-7 8v6l-4 2v-8z" /></svg>)
export const IconClose = IconX
export const IconTarget = (p: P) => (<svg {...base(p)}><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1" fill="currentColor" /></svg>)
export const IconGrip = (p: P) => (<svg {...base(p)}><circle cx="9" cy="6" r="1" fill="currentColor" /><circle cx="15" cy="6" r="1" fill="currentColor" /><circle cx="9" cy="12" r="1" fill="currentColor" /><circle cx="15" cy="12" r="1" fill="currentColor" /><circle cx="9" cy="18" r="1" fill="currentColor" /><circle cx="15" cy="18" r="1" fill="currentColor" /></svg>)
export const IconUp = (p: P) => (<svg {...base(p)}><path d="m6 15 6-6 6 6" /></svg>)
export const IconDown = (p: P) => (<svg {...base(p)}><path d="m6 9 6 6 6-6" /></svg>)
export const IconBook = (p: P) => (<svg {...base(p)}><path d="M4 4h10a4 4 0 0 1 4 4v12H8a4 4 0 0 1-4-4z" /><path d="M4 16a4 4 0 0 1 4-4h10" /></svg>)
export const IconClock = (p: P) => (<svg {...base(p)}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>)
export const IconSpark = (p: P) => (<svg {...base(p)}><path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6" /></svg>)
export const IconDownload = (p: P) => (<svg {...base(p)}><path d="M12 4v12" /><path d="m6 10 6 6 6-6" /><path d="M4 20h16" /></svg>)
export const IconRefresh = (p: P) => (<svg {...base(p)}><path d="M20 11a8 8 0 0 0-14.9-3M4 5v3h3" /><path d="M4 13a8 8 0 0 0 14.9 3M20 19v-3h-3" /></svg>)
export const IconAlert = (p: P) => (<svg {...base(p)}><path d="M12 3 2 20h20z" /><path d="M12 10v4M12 17h.01" /></svg>)
export const IconLock = (p: P) => (<svg {...base(p)}><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>)
export const IconLogo = ({ size = 28 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
    <rect width="32" height="32" rx="8" fill="var(--panel-3)" />
    <path d="M6 10h8l4 6-4 6H6l4-6z" fill="var(--accent)" />
    <path d="M16 10h10l-4 6 4 6H16l4-6z" fill="var(--good)" opacity=".85" />
  </svg>
)
