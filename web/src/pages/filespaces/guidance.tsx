/*
 * Storage guidance copy, shared by Create + Filespace settings storage editing.
 *
 * cloud-fs writes content-addressed, encrypted blocks under a per-filespace
 * prefix. A dedicated, EMPTY bucket is strongly recommended; sharing a bucket
 * risks key collisions, lifecycle-rule deletion, and data loss.
 *
 * Owned by the Filespaces screen lane.
 */
import { IconInfo } from '../../design/icons'

export function DedicatedBucketNote() {
  return (
    <div className="cfs-bucket-note" role="note">
      <span className="cfs-bucket-note__icon">
        <IconInfo />
      </span>
      <div className="cfs-bucket-note__body">
        <span className="cfs-bucket-note__title">Use a dedicated, empty bucket</span>
        <p className="cfs-bucket-note__text">
          cloud-fs stores content-addressed, encrypted blocks under a per-filespace prefix. A
          dedicated, empty bucket is strongly recommended — sharing a bucket with other data or
          another filespace risks key collisions, lifecycle-rule deletion, and data loss.
        </p>
      </div>
    </div>
  )
}
