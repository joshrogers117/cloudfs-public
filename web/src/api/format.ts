/*
 * Small display helpers shared by screens. Byte formatting matches the Mac
 * app's "14 TB" / "312 TB" style (base-1024, short units).
 */
const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

export function bytesLabel(bytes: number): string {
  if (bytes <= 0) return '0 B'
  const i = Math.min(UNITS.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)))
  const value = bytes / 1024 ** i
  const rounded = value >= 100 || Number.isInteger(value) ? Math.round(value) : Math.round(value * 10) / 10
  return `${rounded} ${UNITS[i]}`
}
