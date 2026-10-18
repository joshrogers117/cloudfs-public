import assert from 'node:assert/strict'
import { test } from 'node:test'
import { permissionsFor } from '../src/app/permissions.ts'

test('regular users, pending sessions and unknown roles have no administration controls', () => {
  for (const role of [undefined, 'Member', 'folder_admin', 'bogus']) {
    assert.ok(Object.values(permissionsFor(role)).every(value => value === false), String(role))
  }
})
test('filespace administrators retain filespace controls without workspace administration', () => {
  const p = permissionsFor('Filespace Admin')
  assert.equal(p.manageFilespaceSettings, true)
  assert.equal(p.manageGuestLinks, true)
  for (const key of ['manageWorkspace', 'manageMembers', 'createFilespaces', 'manageSchedules', 'readWorkspaceActivity', 'repointStorage', 'deleteFilespace']) assert.equal(p[key], false, key)
})
test('owners and admins can manage workspace settings; storage moves and deletion remain owner-only', () => {
  assert.ok(Object.values(permissionsFor('Owner')).every(Boolean))
  const admin = permissionsFor('Admin')
  assert.equal(admin.manageWorkspace, true)
  assert.equal(admin.manageMembers, true)
  assert.equal(admin.manageSchedules, true)
  assert.equal(admin.repointStorage, false)
  assert.equal(admin.deleteFilespace, false)
})
