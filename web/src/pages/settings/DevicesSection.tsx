/*
 * DevicesSection — the signed-in account's device sessions: every Mac signed in
 * through the cloud-fs app's browser handoff (auth-spec §2.6 / W6). Lists name,
 * model, created and last-seen times with a confirmed per-row Revoke.
 *
 * Revoking a device signs it out server-side (the refresh token dies instantly,
 * residual access tokens within ~15 min) and CASCADES to the device's daemon
 * service token — its drive disconnects. Recently revoked sessions stay in the
 * list flagged "Revoked" until the server prunes them, so the user can see the
 * revocation took.
 *
 * Account-scoped (every user sees their own devices), not admin-gated. Owned by
 * the Settings lane; goes through the getApi() seam like every section here.
 */
import { useProductName } from '../../app/productName'
import { useEffect, useState } from 'react'
import { Banner, Button } from '../../design'
import { getApi, type DeviceSession } from '../../api'
import { SettingsGroup, SettingsRow } from './SettingsGroup'
import { IconLaptop, IconTrash } from './icons'
import './settings.css'

export function DevicesSection() {
  const productName = useProductName()
  const [devices, setDevices] = useState<DeviceSession[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [revokingId, setRevokingId] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    getApi()
      .listDevices()
      .then((list) => alive && setDevices(list))
      .catch(() => alive && setError('Couldn’t load devices.'))
    return () => {
      alive = false
    }
  }, [])

  async function revoke(device: DeviceSession) {
    if (
      !window.confirm(
        `Revoke “${device.name}”? This signs the device out and disconnects its drive.`,
      )
    ) {
      return
    }
    setError(null)
    setRevokingId(device.id)
    try {
      await getApi().revokeDevice(device.id)
      // Keep the row, flagged — mirrors the server (revoked sessions stay listed
      // for a while), and confirms to the user that the revoke took.
      setDevices((cur) =>
        (cur ?? []).map((d) =>
          d.id === device.id ? { ...d, revokedAt: new Date().toISOString() } : d,
        ),
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Couldn’t revoke the device. Try again.')
    } finally {
      setRevokingId(null)
    }
  }

  const active = (devices ?? []).filter((d) => !d.revokedAt)

  return (
    <SettingsGroup
      label="Devices"
      description={`Macs signed in to this account through the ${productName} app. Revoking a device signs it out and disconnects its drive.`}
    >
      <SettingsRow
        leading={<IconLaptop />}
        title="Connected devices"
        sublabel={
          devices == null
            ? 'Loading…'
            : active.length === 0
              ? `No devices connected. Sign in from the ${productName} Mac app and it will appear here.`
              : `${active.length} device${active.length === 1 ? '' : 's'} signed in.`
        }
      />

      {error && (
        <SettingsRow>
          <Banner kind="error" title={error} />
        </SettingsRow>
      )}

      {devices != null && devices.length > 0 && (
        <SettingsRow>
          <div className="cfs-passkeys">
            {devices.map((d) => (
              <div key={d.id} className="cfs-passkey">
                <span className="cfs-passkey__icon">
                  <IconLaptop />
                </span>
                <div className="cfs-passkey__text">
                  <span className="cfs-passkey__label">
                    {d.name}
                    {d.model ? ` (${d.model})` : ''}
                  </span>
                  <span className="cfs-passkey__meta">
                    Signed in {formatDate(d.createdAt)} · Last seen {formatRelative(d.lastSeenAt)}
                  </span>
                </div>
                {d.revokedAt ? (
                  <span className="cfs-set-chip cfs-passkey__action">Revoked</span>
                ) : (
                  <Button
                    className="cfs-passkey__action"
                    variant="destructive"
                    size="small"
                    leading={<IconTrash size={13} />}
                    onClick={() => void revoke(d)}
                    disabled={revokingId === d.id}
                  >
                    {revokingId === d.id ? 'Revoking…' : 'Revoke'}
                  </Button>
                )}
              </div>
            ))}
          </div>
        </SettingsRow>
      )}
    </SettingsGroup>
  )
}

/* ----- date helpers (lane-local, mirrors AccountSettings) ----- */

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  } catch {
    return iso
  }
}

function formatRelative(iso: string): string {
  const then = new Date(iso).getTime()
  const diff = Date.now() - then
  const mins = Math.round(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  if (days < 30) return `${days}d ago`
  return formatDate(iso)
}
