// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OrgRole } from '../api/types'

// Presentation only. The gateway independently enforces live roles for every
// request, including CLI/service tokens and direct links to these routes.
export function permissionsFor(role?: OrgRole) {
  const workspaceAdmin = role === 'Owner' || role === 'Admin'
  const filespaceAdmin = workspaceAdmin || role === 'Filespace Admin'
  return {
    manageWorkspace: workspaceAdmin,
    manageMembers: workspaceAdmin,
    createFilespaces: workspaceAdmin,
    manageFilespaceSettings: filespaceAdmin,
    manageSchedules: workspaceAdmin,
    manageGuestLinks: filespaceAdmin,
    readWorkspaceActivity: workspaceAdmin,
    repointStorage: role === 'Owner',
    deleteFilespace: role === 'Owner',
  }
}
