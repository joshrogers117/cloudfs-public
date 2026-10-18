/*
 * Lane-local stroke icons for the Account-Settings pane. Same 16px grid +
 * currentColor convention as the shared design/icons set, kept here because the
 * design system is frozen and these glyphs (shield, passkey, QR, copy, trash)
 * are specific to this screen. Monochrome, tint via CSS.
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

export const IconShield = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M8 1.6 13 3.4v4.1c0 3.1-2 5.3-5 6.9-3-1.6-5-3.8-5-6.9V3.4L8 1.6Z" />
    <path d="m5.8 8 1.5 1.5L10.4 6" />
  </svg>
)

export const IconPasskey = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="6" cy="5.4" r="2.6" />
    <path d="M2.4 13.2a3.7 3.7 0 0 1 7.2 0" />
    <circle cx="12" cy="9" r="1.6" />
    <path d="M12 10.6V14m0-1.2 1.1.8M12 12.6l-1.1.8" />
  </svg>
)

export const IconQR = (p: IconProps) => (
  <svg {...base(p)} strokeWidth={1.1}>
    <rect x="1.8" y="1.8" width="4.4" height="4.4" rx="0.6" />
    <rect x="9.8" y="1.8" width="4.4" height="4.4" rx="0.6" />
    <rect x="1.8" y="9.8" width="4.4" height="4.4" rx="0.6" />
    <path d="M9.8 9.8h2v2M14.2 9.8v4.4M9.8 14.2h2M3.6 3.6h.9v.9h-.9zM11.6 3.6h.9v.9h-.9zM3.6 11.6h.9v.9h-.9z" />
  </svg>
)

export const IconCopy = (p: IconProps) => (
  <svg {...base(p)}>
    <rect x="5.2" y="5.2" width="8" height="8" rx="1.2" />
    <path d="M10.8 5.2V3.6a1.2 1.2 0 0 0-1.2-1.2H3.6a1.2 1.2 0 0 0-1.2 1.2v6a1.2 1.2 0 0 0 1.2 1.2h1.6" />
  </svg>
)

export const IconLaptop = (p: IconProps) => (
  <svg {...base(p)}>
    <rect x="3" y="3.2" width="10" height="7.2" rx="1" />
    <path d="M1.6 12.8h12.8M6.4 10.4h3.2" />
  </svg>
)

export const IconTrash = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M2.8 4.2h10.4M6 4.2V3a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.2M4 4.2l.6 8.2a1.2 1.2 0 0 0 1.2 1.1h4.4a1.2 1.2 0 0 0 1.2-1.1l.6-8.2" />
  </svg>
)
