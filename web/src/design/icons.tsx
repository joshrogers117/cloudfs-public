/*
 * Minimal stroke icon set — the web twin of the Mac app's SF Symbols.
 * Monochrome, 16px grid, `currentColor` so callers tint via CSS. Kept tiny on
 * purpose (no icon-kit dependency); screen agents may add more as needed.
 */
import type { SVGProps } from 'react'

type IconProps = SVGProps<SVGSVGElement> & { size?: number }

function base({ size = 16, ...rest }: IconProps) {
  return {
    width: size,
    height: size,
    viewBox: '0 0 16 16',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.4,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
    ...rest,
  }
}

export const IconFilespaces = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M8 1.6 14 4 8 6.4 2 4 8 1.6Z" />
    <path d="M2 8 8 10.4 14 8" />
    <path d="M2 12 8 14.4 14 12" />
  </svg>
)

export const IconSettings = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="8" cy="8" r="2.2" />
    <path d="M8 1.5v1.8M8 12.7v1.8M14.5 8h-1.8M3.3 8H1.5M12.6 3.4l-1.3 1.3M4.7 11.3l-1.3 1.3M12.6 12.6l-1.3-1.3M4.7 4.7 3.4 3.4" />
  </svg>
)

export const IconGlobe = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="8" cy="8" r="6.2" />
    <path d="M1.8 8h12.4M8 1.8c1.7 1.7 2.6 3.9 2.6 6.2S9.7 12.5 8 14.2C6.3 12.5 5.4 10.3 5.4 8S6.3 3.5 8 1.8Z" />
  </svg>
)

export const IconBuilding = (p: IconProps) => (
  <svg {...base(p)}>
    <rect x="3" y="2" width="10" height="12" rx="1" />
    <path d="M5.5 5h1M9.5 5h1M5.5 8h1M9.5 8h1M7 14v-2.5h2V14" />
  </svg>
)

export const IconKey = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="5.5" cy="5.5" r="3" />
    <path d="m7.6 7.6 5 5M11 11l1.5-1.5M9.5 9.5 11 8" />
  </svg>
)

export const IconMail = (p: IconProps) => (
  <svg {...base(p)}>
    <rect x="1.8" y="3.2" width="12.4" height="9.6" rx="1.4" />
    <path d="m2.4 4 5.6 4 5.6-4" />
  </svg>
)

export const IconLock = (p: IconProps) => (
  <svg {...base(p)}>
    <rect x="3.2" y="7" width="9.6" height="6.6" rx="1.4" />
    <path d="M5.2 7V5.2a2.8 2.8 0 0 1 5.6 0V7" />
  </svg>
)

export const IconSSO = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="8" cy="5.4" r="2.6" />
    <path d="M3 13.6a5 5 0 0 1 10 0" />
  </svg>
)

export const IconInfo = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="8" cy="8" r="6.2" />
    <path d="M8 7.2v3.4M8 5.2v.1" />
  </svg>
)

export const IconCheck = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="8" cy="8" r="6.2" />
    <path d="m5.2 8.2 1.9 1.9L11 6.1" />
  </svg>
)

export const IconWarn = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M8 2.2 14.4 13H1.6L8 2.2Z" />
    <path d="M8 6.6v3M8 11.4v.1" />
  </svg>
)

export const IconError = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="8" cy="8" r="6.2" />
    <path d="m5.8 5.8 4.4 4.4M10.2 5.8l-4.4 4.4" />
  </svg>
)

export const IconSignOut = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M9.5 3.5H4a1 1 0 0 0-1 1v7a1 1 0 0 0 1 1h5.5" />
    <path d="M11 5.5 13.5 8 11 10.5M13.5 8H7" />
  </svg>
)

export const IconPlus = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M8 3v10M3 8h10" />
  </svg>
)
