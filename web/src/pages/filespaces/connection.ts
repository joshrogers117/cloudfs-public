/*
 * ConnectionState → presentation selectors (pure). Mirrors the Mac app's
 * ConnectionState.dotColor / .label. Kept in its own module so the icon
 * components live separately (fast-refresh friendliness). Owned by the
 * Filespaces screen lane.
 */
import type { ConnectionState } from '../../api'
import type { StatusColor } from '../../design/components'

export function connectionDotColor(state: ConnectionState): StatusColor {
  switch (state) {
    case 'connected':
      return 'ok'
    case 'connecting':
      return 'busy'
    case 'paused':
      return 'paused'
    case 'error':
      return 'error'
    case 'disconnected':
    default:
      return 'idle'
  }
}

export function connectionLabel(state: ConnectionState): string {
  switch (state) {
    case 'connected':
      return 'Connected'
    case 'connecting':
      return 'Connecting…'
    case 'paused':
      return 'Paused'
    case 'error':
      return 'Error'
    case 'disconnected':
    default:
      return 'Offline'
  }
}
