// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, type ReactNode } from 'react'

/** Native dialog supplies focus trapping, Escape dismissal, and inert background. */
export function Modal({ title, children, onClose, busy = false }: { title: string; children: ReactNode; onClose: () => void; busy?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const dialog = ref.current
    const previous = document.activeElement
    dialog?.showModal()
    return () => { dialog?.close(); if (previous instanceof HTMLElement) previous.focus() }
  }, [])
  return <dialog ref={ref} className="cfs-modal" aria-label={title} onCancel={(event) => { event.preventDefault(); if (!busy) onClose() }}>
    <header className="cfs-modal__header"><h2>{title}</h2><button type="button" className="cfs-icon-button" disabled={busy} onClick={onClose} aria-label={`Close ${title}`}>×</button></header>
    {children}
  </dialog>
}
