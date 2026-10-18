// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mapOrgRole, spaceToFilespace } from '../src/api/wire.ts'

test('a filespace administrator is not represented as a workspace administrator', () => {
  assert.equal(mapOrgRole('space_admin'), 'Filespace Admin')
  assert.equal(mapOrgRole('admin'), 'Admin')
  assert.equal(mapOrgRole('owner'), 'Owner')
  assert.equal(mapOrgRole(undefined), 'Member')
})

test('registry entries never imply a local mount or measured usage', () => {
  const fs = spaceToFilespace({ id: 'production', name: 'Production' }, 'Standard User')
  assert.equal(fs.connection, 'disconnected')
  assert.equal(fs.usageKnown, false)
  assert.equal(fs.memberCountKnown, false)
  assert.equal(fs.mountPath, undefined)
})

test('authoritative zero usage differs from unavailable usage', () => {
  const fs = spaceToFilespace({ id: 'empty', name: 'Empty', usedBytes: 0, memberCount: 0, storageBucket: 'studio', storageEndpoint: 'https://storage.example' }, 'Filespace Admin')
  assert.equal(fs.usageKnown, true)
  assert.equal(fs.memberCountKnown, true)
  assert.equal(fs.storageBucket, 'studio')
  assert.equal(fs.storageEndpoint, 'https://storage.example')
})
