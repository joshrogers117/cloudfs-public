// SPDX-License-Identifier: AGPL-3.0-or-later
// Cloudflare SQLite limits the entire row to 2 MB. Leave room for the inode,
// stream name and row metadata; this ceiling applies to the encrypted body.
export const MAX_STREAM_BODY_BYTES = 1536 * 1024;
