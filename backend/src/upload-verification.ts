// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Block } from './metadata/types';
import { validateBlockManifest } from './metadata/block-manifest';
import { validateObjectVerificationInput } from './storage-object-verifier';

/** Completed upload identities, not a file manifest. Normalize a small batch to
 * reuse the manifest's identity/access checks without publishing file offsets. */
export function uploadVerificationManifest(value: unknown): Block[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) {
    throw new Error('verification requires 1–128 objects');
  }
  let offset = 0;
  const blocks = value.map((value, index) => {
    if (!value || typeof value !== 'object') throw new Error('invalid object');
    const block: Block = { chunkIdx: index, blockIdx: 0, offset,
      objectKey: value.objectKey, blockHash: value.blockHash, length: value.length };
    offset += block.length;
    return block;
  });
  validateBlockManifest(blocks);
  blocks.forEach(validateObjectVerificationInput);
  return blocks;
}
