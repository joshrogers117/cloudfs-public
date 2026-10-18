/*
 * Filespaces lane-local stroke icons (members / region / storage / drive / stack
 * / chevron) that aren't in the frozen design icon set. 16px grid, currentColor,
 * matching the design-system icon style. Connection selectors live in
 * connection.ts. Owned by the Filespaces screen lane.
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

/** Stacked layers — the filespace glyph (matches Mac IconSet.filespace). */
export const IconStack = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M8 1.6 14 4 8 6.4 2 4 8 1.6Z" />
    <path d="M2 8 8 10.4 14 8" />
    <path d="M2 12 8 14.4 14 12" />
  </svg>
)

/** Storage backend / drive. */
export const IconDrive = (p: IconProps) => (
  <svg {...base(p)}>
    <rect x="1.8" y="9.2" width="12.4" height="4.4" rx="1.2" />
    <path d="m3.4 9.2 1.4-5.2a1 1 0 0 1 1-0.8h4.4a1 1 0 0 1 1 0.8l1.4 5.2" />
    <path d="M11.6 11.4h.1" />
  </svg>
)

/** Region / globe (matches design IconGlobe, kept local for the meta row). */
export const IconRegion = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="8" cy="8" r="6.2" />
    <path d="M1.8 8h12.4M8 1.8c1.7 1.7 2.6 3.9 2.6 6.2S9.7 12.5 8 14.2C6.3 12.5 5.4 10.3 5.4 8S6.3 3.5 8 1.8Z" />
  </svg>
)

/** Members / people. */
export const IconMembers = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="6" cy="5.6" r="2.4" />
    <path d="M1.8 13a4.2 4.2 0 0 1 8.4 0" />
    <path d="M10.4 3.6a2.4 2.4 0 0 1 0 4.4M11 13a4.2 4.2 0 0 0-1.2-2.9" />
  </svg>
)

/** Storage size / database. */
export const IconStorage = (p: IconProps) => (
  <svg {...base(p)}>
    <ellipse cx="8" cy="3.6" rx="5" ry="2" />
    <path d="M3 3.6v8.8c0 1.1 2.2 2 5 2s5-0.9 5-2V3.6" />
    <path d="M3 8c0 1.1 2.2 2 5 2s5-0.9 5-2" />
  </svg>
)

/** Disclosure chevron. */
export const IconChevronRight = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M6 3.5 10.5 8 6 12.5" />
  </svg>
)
