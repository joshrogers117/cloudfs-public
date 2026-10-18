// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Block } from './types';

// The HTTP layer also bounds the encoded request. This is a defensive work bound,
// not a fixed byte-size limit on files (block lengths may vary).
export const MAX_MANIFEST_BLOCKS = 131_072;
export class InvalidManifestError extends Error {
  constructor(reason: string) { super(reason); this.name = 'InvalidManifestError'; }
}

/** Validate the whole image before changing any reference counts or namespace rows. */
export function validateBlockManifest(value: unknown): asserts value is Block[] {
  if (!Array.isArray(value) || value.length > MAX_MANIFEST_BLOCKS) throw new InvalidManifestError('invalid block count');
  let end = 0, previousChunk = -1, previousBlock = -1;
  const identities = new Map<string, string>();
  const lengths = new Map<string, number>();
  const hashes = new Map<string, string>();
  for (const b of value) {
    if (!b || typeof b !== 'object'
      || !Number.isSafeInteger(b.chunkIdx) || b.chunkIdx < 0
      || !Number.isSafeInteger(b.blockIdx) || b.blockIdx < 0
      || !Number.isSafeInteger(b.offset) || b.offset !== end
      || !Number.isSafeInteger(b.length) || b.length <= 0 || !Number.isSafeInteger(end + b.length)) {
      throw new InvalidManifestError('blocks must cover a contiguous, safely representable file');
    }
    if (b.chunkIdx < previousChunk || (b.chunkIdx === previousChunk && b.blockIdx <= previousBlock)) {
      throw new InvalidManifestError('block coordinates must be unique and ordered');
    }
    if (typeof b.blockHash !== 'string' || !b.blockHash.length || b.blockHash.length > 128
      || typeof b.objectKey !== 'string' || !b.objectKey.length || new TextEncoder().encode(b.objectKey).byteLength > 1024
      || /[\u0000-\u001f\u007f]/.test(b.objectKey)) throw new InvalidManifestError('invalid block identity');
    if ((lengths.has(b.objectKey) && lengths.get(b.objectKey) !== b.length)
      || (identities.has(b.objectKey) && identities.get(b.objectKey) !== b.blockHash)
      || (hashes.has(b.blockHash) && hashes.get(b.blockHash) !== b.objectKey)) {
      throw new InvalidManifestError('a content hash and object key must identify the same immutable object');
    }
    identities.set(b.objectKey, b.blockHash); hashes.set(b.blockHash, b.objectKey); lengths.set(b.objectKey, b.length);
    previousChunk = b.chunkIdx; previousBlock = b.blockIdx; end += b.length;
  }
}

export function sameBlockManifest(a: Block[], b: Block[]): boolean {
  return a.length === b.length && a.every((x, i) => {
    const y = b[i];
    return x.chunkIdx === y.chunkIdx && x.blockIdx === y.blockIdx && x.blockHash === y.blockHash
      && x.objectKey === y.objectKey && x.offset === y.offset && x.length === y.length;
  });
}
