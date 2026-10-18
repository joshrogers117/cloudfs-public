// SPDX-License-Identifier: AGPL-3.0-or-later
import { useId } from 'react'

export function DriveIllustration({ size = 112 }: { size?: number }) {
  const gradient = useId()
  return <svg width={size} height={size} viewBox="0 0 120 120" aria-hidden="true">
    <defs><linearGradient id={gradient} x1="0" y1="0" x2="0.5" y2="1"><stop stopColor="#e1d6ff"/><stop offset="1" stopColor="#a18fff"/></linearGradient></defs>
    <path d="M29 23Q31 17 39 17H81Q89 17 91 23L108 76H12Z" fill={`url(#${gradient})`}/>
    <rect x="12" y="70" width="96" height="24" rx="9" fill="#6e54bd"/>
    <rect x="26" y="80" width="25" height="3" rx="1.5" fill="#fff" opacity=".35"/>
    <circle cx="92.5" cy="81.5" r="2.5" fill="#f4efff"/>
  </svg>
}
