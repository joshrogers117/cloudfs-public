// SPDX-License-Identifier: AGPL-3.0-or-later
export interface CapacityConfig { METADATA_WARNING_BYTES?: string; METADATA_ADMISSION_BYTES?: string }
const PLATFORM_BYTES = 10_000_000_000;
export class MetadataCapacityError extends Error {
  constructor() { super('metadata_capacity: filespace metadata is full; remove unused history or contact the operator'); }
}
export function isMetadataCapacityError(error: unknown): boolean {
  return /metadata_capacity:|SQLITE_FULL|database or disk is full/i.test(error instanceof Error ? error.message : String(error));
}
/** Preserve a maintenance reserve below the platform limit. Estimates bound
 * admission, not billing; SQLite's actual allocation remains authoritative. */
export class MetadataCapacity {
  constructor(private readonly sql: SqlStorage, private readonly config: CapacityConfig) {}
  private thresholds() {
    const admission = this.parse(this.config.METADATA_ADMISSION_BYTES,9_000_000_000);
    const warning = this.parse(this.config.METADATA_WARNING_BYTES,Math.min(8_000_000_000,Math.floor(admission*0.8)));
    if (warning > admission || admission > PLATFORM_BYTES - 100_000_000) throw new Error('invalid metadata capacity configuration');
    return {warningBytes:warning,admissionBytes:admission,platformBytes:PLATFORM_BYTES};
  }
  private parse(value: string | undefined, fallback: number): number {
    if (value === undefined) return fallback;
    const n=Number(value);
    if (!/^\d+$/.test(value) || !Number.isSafeInteger(n) || n<0) throw new Error('invalid metadata capacity configuration');
    return n;
  }
  admit(estimatedBytes = 65_536): void {
    if (!Number.isSafeInteger(estimatedBytes) || estimatedBytes < 0 || this.sql.databaseSize + estimatedBytes > this.thresholds().admissionBytes) throw new MetadataCapacityError();
  }
  status() {
    const thresholds=this.thresholds(),databaseBytes=this.sql.databaseSize;
    return {...thresholds,databaseBytes,state:databaseBytes>=thresholds.admissionBytes?'full':databaseBytes>=thresholds.warningBytes?'warning':'ok',
      headroomBytes:Math.max(0,thresholds.admissionBytes-databaseBytes)};
  }
  /** Explicit operator inspection only: these counts scan indexes, so never put
   * them on a per-file request or readiness health check. They are not page sizes. */
  contributors() {
    const tables=['items','blocks','stream_blocks','retained_blocks','snapshot_items','snapshot_blocks','snapshot_streams','snapshot_stream_blocks','known_objects','verified_objects','block_upload_claims','audit'];
    return tables.map(table=>({table,rows:Number(this.sql.exec(`SELECT COUNT(*) AS n FROM ${table};`).one().n)}));
  }
}
