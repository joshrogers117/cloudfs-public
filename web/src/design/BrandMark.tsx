// SPDX-License-Identifier: AGPL-3.0-or-later
// The purple drive from client-app/Resources/cloudfs-logo.svg.
type Props = { size?: number; chrome?: boolean; tint?: string; className?: string }
export function BrandMark({ size = 24, chrome = true, tint, className }: Props) {
  return (
    <svg width={size} height={size} viewBox={chrome ? '0 0 64 64' : '12 15 40 36'} className={className} aria-hidden="true">
      {chrome && <rect x="3" y="3" width="58" height="58" rx="14" fill="var(--cfs-accent-soft)" />}
      <g fill={tint ?? 'var(--cfs-accent)'}>
        <path d="M26 19h12a7.5 7.5 0 0 1 6.9 4.5L49 34a12 12 0 0 0-5-1H20a12 12 0 0 0-5 1l4.1-10.5A7.5 7.5 0 0 1 26 19Z" />
        <path fillRule="evenodd" d="M20 35h24a6 6 0 0 1 0 12H20a6 6 0 0 1 0-12Zm25.5 6a2 2 0 1 0-4 0 2 2 0 0 0 4 0Z" />
      </g>
    </svg>
  )
}
