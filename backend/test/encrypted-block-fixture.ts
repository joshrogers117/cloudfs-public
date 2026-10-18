// SPDX-License-Identifier: AGPL-3.0-or-later
/** Structurally valid encrypted envelope for storage-verifier tests. The backend
 * does not possess the client key and does not claim AEAD authentication here. */
export function encryptedBlockFixture(length = 4, magic: 'CFB2' | 'CFB3' = 'CFB3'): Uint8Array {
  const bytes = new Uint8Array(length + 69).fill(37);
  bytes.set(new TextEncoder().encode(magic)); bytes[4] = 0;
  new DataView(bytes.buffer).setUint32(5,length);
  return bytes;
}
