// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSKit

extension AppModel {
    /// Counts come from memberships, which the group registry does not include.
    /// Fetch in batches of eight to keep very large directories bounded.
    func loadGroups() async {
        let generation = UUID()
        members.groupsLoadGeneration = generation
        members.groupsState = .loading
        do {
            let groups = try await gateway.listGroups().sorted {
                $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            }
            guard members.groupsLoadGeneration == generation else { return }
            members.groups = groups
            members.groupsState = .loaded(groups)
            if !groups.contains(where: { $0.id == members.selectedGroupID }) {
                members.selectedGroupID = groups.first?.id
            }
            members.groupMemberships = [:]
            guard members.canMutate else { return } // membership API requires workspace admin
            let client = gateway
            for start in stride(from: 0, to: groups.count, by: 8) {
                let batch = Array(groups[start..<min(start + 8, groups.count)])
                for group in batch { members.groupMemberships[group.id] = .loading }
                let results = await withTaskGroup(of: (String, LoadState<[String]>).self) { tasks in
                    for group in batch {
                        tasks.addTask {
                            do { return (group.id, .loaded(try await client.groupMembers(group.id))) }
                            catch { return (group.id, .failed(error.localizedDescription)) }
                        }
                    }
                    var results: [(String, LoadState<[String]>)] = []
                    for await result in tasks { results.append(result) }
                    return results
                }
                guard members.groupsLoadGeneration == generation else { return }
                for (id, state) in results { members.groupMemberships[id] = state }
            }
        } catch {
            guard members.groupsLoadGeneration == generation else { return }
            members.groupsState = .failed(error.localizedDescription)
        }
    }

    @discardableResult
    func createGroup(name: String) async -> Bool {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard members.canMutate, !trimmed.isEmpty, !members.isCreatingGroup else { return false }
        members.isCreatingGroup = true
        members.mutationError = nil
        defer { members.isCreatingGroup = false }
        do {
            let group = try await gateway.createGroup(name: trimmed)
            members.selectedGroupID = group.id
            await loadGroups()
            return true
        } catch {
            members.mutationError = error.localizedDescription
            return false
        }
    }

    func deleteGroup(_ group: MemberGroup) async {
        guard group.isEditable(by: members.currentRole),
              !members.busyGroupIDs.contains(group.id) else { return }
        members.busyGroupIDs.insert(group.id)
        members.mutationError = nil
        defer { members.busyGroupIDs.remove(group.id) }
        do {
            try await gateway.deleteGroup(group.id)
            await loadGroups()
            await loadGrants()
        } catch { members.mutationError = error.localizedDescription }
    }

    func updateGroupMembership(userID: String, group: MemberGroup, adding: Bool) async {
        guard group.isEditable(by: members.currentRole),
              !members.busyGroupIDs.contains(group.id) else { return }
        members.busyGroupIDs.insert(group.id)
        members.mutationError = nil
        defer { members.busyGroupIDs.remove(group.id) }
        do {
            if adding { try await gateway.addGroupMember(userID, to: group.id) }
            else { try await gateway.removeGroupMember(userID, from: group.id) }
            do {
                members.groupMemberships[group.id] = .loaded(try await gateway.groupMembers(group.id))
            } catch {
                // Mutation may have succeeded, but never keep a stale count.
                members.groupMemberships[group.id] = .failed(error.localizedDescription)
                members.mutationError = "The change was saved, but membership could not be refreshed. Try refreshing groups."
            }
        } catch { members.mutationError = error.localizedDescription }
    }
}
