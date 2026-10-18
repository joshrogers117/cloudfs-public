// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
@testable import CloudFSSMB

final class NodeTableTests: XCTestCase {
    private actor ListingGate {
        private var calls = 0
        private var ready: CheckedContinuation<Void, Never>?
        private var blocked: CheckedContinuation<Void, Never>?
        func pauseFirst() async {
            calls += 1
            guard calls == 1 else { return }
            ready?.resume(); ready = nil
            await withCheckedContinuation { blocked = $0 }
        }
        func started() async {
            if calls > 0 { return }
            await withCheckedContinuation { ready = $0 }
        }
        func release() { blocked?.resume(); blocked = nil }
    }

    func testOlderLookupCannotReplaceNewerStoredMetadata() async throws {
        let engine = MemoryEngine()
        let id = engine.seed("edit.bin", data: Data([1]))
        let gate = ListingGate()
        engine.lookupSnapshotHook = { await gate.pauseFirst() }
        let table = NodeTable(engine: engine, ttl: .seconds(60))
        let lookup = Task { try await table.meta(id) }
        await gate.started()
        _ = try await engine.writeRange(id, offset: 1, data: Data([2, 3]), baseVersion: nil)
        let newer = try await engine.lookup(id)
        await table.storeMeta(newer)
        await gate.release()
        let completed = try await lookup.value
        XCTAssertEqual(completed.size, 3)
        XCTAssertEqual(completed.contentVersion, newer.contentVersion)
        let cached = try await table.meta(id)
        XCTAssertEqual(cached.contentVersion, newer.contentVersion)
    }

    func testRootFileIDDoesNotAliasFirstChildAndMappingsSurviveRename() async throws {
        let engine = MemoryEngine()
        let child = engine.seed("first.txt", data: Data([1]))
        let table = NodeTable(engine: engine)

        XCTAssertEqual(NodeTable.rootFileId, 2)
        let rootID = await table.fileId(for: .root)
        let childID = await table.fileId(for: child)
        XCTAssertEqual(rootID, 2)
        XCTAssertGreaterThan(childID, 2)
        XCTAssertNotEqual(rootID, childID)
        let rootMapping = await table.id(forFileId: rootID)
        let childMapping = await table.id(forFileId: childID)
        XCTAssertEqual(rootMapping, .root)
        XCTAssertEqual(childMapping, child)

        await table.invalidateMeta(child)
        _ = try await engine.rename(child, newParent: .root, newName: "renamed.txt")
        let renamedChildID = await table.fileId(for: child)
        let rootMappingAfterRename = await table.id(forFileId: rootID)
        let childMappingAfterRename = await table.id(forFileId: childID)
        XCTAssertEqual(renamedChildID, childID)
        XCTAssertEqual(rootMappingAfterRename, .root)
        XCTAssertEqual(childMappingAfterRename, child)
    }

    func testCanonicalFileIDsAreStableAcrossLookupOrderAndRemount() async throws {
        let engine = MemoryEngine()
        let first = InodeID("stable/first")
        let second = InodeID("stable/second")
        let third = InodeID("stable/third")
        let original = NodeTable(engine: engine, remotePresentationIDs: false)
        let firstID = await original.fileId(for: first)
        let secondID = await original.fileId(for: second)
        let thirdID = await original.fileId(for: third)

        // A fresh table models a daemon remount, where no prior allocation map survives.
        let reversed = NodeTable(engine: engine, remotePresentationIDs: false)
        let reversedThirdID = await reversed.fileId(for: third)
        let reversedSecondID = await reversed.fileId(for: second)
        let reversedFirstID = await reversed.fileId(for: first)
        let rootID = await original.fileId(for: .root)

        XCTAssertEqual(NodeTable.rootFileId, 2)
        XCTAssertEqual(rootID, 2)
        XCTAssertEqual(firstID, reversedFirstID)
        XCTAssertEqual(secondID, reversedSecondID)
        XCTAssertEqual(thirdID, reversedThirdID)
        XCTAssertEqual(Set([firstID, secondID, thirdID]).count, 3)
        XCTAssertFalse([firstID, secondID, thirdID].contains(0))
        XCTAssertFalse([firstID, secondID, thirdID].contains(1))
        XCTAssertFalse([firstID, secondID, thirdID].contains(NodeTable.rootFileId))
        for (fileID, inode) in [(firstID, first), (secondID, second), (thirdID, third)] {
            let originalMapping = await original.id(forFileId: fileID)
            let reversedMapping = await reversed.id(forFileId: fileID)
            XCTAssertEqual(originalMapping, inode)
            XCTAssertEqual(reversedMapping, inode)
        }
    }

    func testNestedDirectoryParentPresentationIDsMatchDirectoryTree() async throws {
        let engine = MemoryEngine()
        let parent = engine.seedDir("parent")
        let child = engine.seedDir("child", parent: parent)
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let parentMeta = try await engine.lookup(parent)
        let childMeta = try await engine.lookup(child)

        let parentID = await table.presentationFileId(for: parentMeta)
        let childID = await table.presentationFileId(for: childMeta)
        let childParentID = try await table.presentationParentFileID(for: childMeta)
        let parentParentID = try await table.presentationParentFileID(for: parentMeta)

        XCTAssertNotEqual(childID, parentID)
        XCTAssertEqual(childParentID, parentID)
        XCTAssertEqual(parentParentID, NodeTable.rootFileId)
    }

    func testRemotePresentationIDChangesOnObservedMoveButLocalCommitKeepsIt() async throws {
        let engine = MemoryEngine()
        let source = engine.seed("source.bin", data: Data("old".utf8))
        let replacement = engine.seed("replacement.bin", data: Data("new".utf8))
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let originalSource = try await engine.lookup(source)
        let originalReplacement = try await engine.lookup(replacement)
        _ = await table.presentationFileId(for: originalSource)
        let replacementID = await table.presentationFileId(for: originalReplacement)

        let moved = try await engine.rename(replacement, newParent: .root, newName: "source.bin",
                                            replacing: originalSource)
        await table.invalidateListing(.root)
        let movedID = await table.presentationFileId(for: moved)
        XCTAssertNotEqual(movedID, replacementID,
                          "a remotely observed location change gets a new SMB presentation ID")
        let movedMapping = await table.id(forFileId: movedID)
        let heldMapping = await table.id(forFileId: replacementID)
        XCTAssertEqual(movedMapping, replacement,
                       "presentation IDs still resolve to the immutable backend inode")
        XCTAssertEqual(heldMapping, replacement,
                       "the previous presentation ID remains associated with the held inode")

        let localToken = await table.beginLocalRename(replacement)
        let locallyMoved = try await engine.rename(replacement, newParent: .root, newName: "local.bin")
        let waitingObservation = Task { await table.presentationFileId(for: originalReplacement) }
        await table.commitLocalRename(locallyMoved, token: localToken)
        let committedObservation = await waitingObservation.value
        XCTAssertEqual(committedObservation, movedID,
                       "a pre-rename listing resumed after commit uses the committed location and preserves its ID")
    }

    func testRemoteNameReuseDoesNotReuseTheMovedInodesPresentationID() async throws {
        let engine = MemoryEngine()
        let original = engine.seed("slot.bin", data: Data("old".utf8))
        let other = engine.seed("other.bin", data: Data("move".utf8))
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let originalID = await table.presentationFileId(for: try await engine.lookup(original))
        let otherMeta = try await engine.lookup(other)
        let otherID = await table.presentationFileId(for: otherMeta)
        let moved = try await engine.rename(other, newParent: .root, newName: "slot.bin",
                                            replacing: try await engine.lookup(original))
        let movedID = await table.presentationFileId(for: moved)
        XCTAssertNotEqual(movedID, originalID)
        XCTAssertNotEqual(movedID, otherID)

        let reused = engine.seed("other.bin", data: Data("new owner".utf8))
        let reusedID = await table.presentationFileId(for: try await engine.lookup(reused))
        let movedMapping = await table.id(forFileId: movedID)
        XCTAssertNotEqual(reusedID, otherID)
        XCTAssertNotEqual(reusedID, movedID)
        XCTAssertEqual(movedMapping, other)
    }

    func testRemoteDirectoryMoveRekeysObservedDescendants() async throws {
        let engine = MemoryEngine()
        let folder = engine.seedDir("before")
        let nested = engine.seedDir("nested", parent: folder)
        let leaf = engine.seed("leaf.bin", parent: nested, data: Data([1]))
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let folderBefore = await table.presentationFileId(for: try await engine.lookup(folder))
        let nestedBefore = await table.presentationFileId(for: try await engine.lookup(nested))
        let leafBefore = await table.presentationFileId(for: try await engine.lookup(leaf))

        let movedFolder = try await engine.rename(folder, newParent: .root, newName: "after")
        await table.storeMeta(movedFolder)
        let folderAfter = await table.presentationFileId(for: movedFolder)
        let nestedAfter = await table.presentationFileId(for: try await engine.lookup(nested))
        let leafAfter = await table.presentationFileId(for: try await engine.lookup(leaf))

        XCTAssertNotEqual(folderAfter, folderBefore)
        XCTAssertNotEqual(nestedAfter, nestedBefore,
                          "a child ID includes its parent directory's observed location epoch")
        XCTAssertNotEqual(leafAfter, leafBefore,
                          "a nested directory's changed epoch propagates to deeper entries")
    }

    func testLatePreRenameListingCannotRestoreOldPresentationLocation() async throws {
        let engine = MemoryEngine()
        let original = engine.seed("source.bin", data: Data("old".utf8))
        let replacement = engine.seed("replacement.bin", data: Data("new".utf8))
        let gate = ListingGate()
        engine.enumerationSnapshotHook = { await gate.pauseFirst() }
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let originalReplacement = try await engine.lookup(replacement)
        await table.storeMeta(originalReplacement)
        let oldID = await table.presentationFileId(for: originalReplacement)
        let oldListing = Task { try await table.children(of: .root) }
        await gate.started()

        let moved = try await engine.rename(replacement, newParent: .root, newName: "source.bin",
                                            replacing: try await engine.lookup(original))
        await table.storeMeta(moved)
        let movedID = await table.presentationFileId(for: moved)
        await gate.release()

        let completed = try await oldListing.value
        XCTAssertEqual(completed.map(\.id), [replacement],
                       "the stale enumeration is retried against the observed new location")
        let observedID = await table.presentationFileId(for: completed[0])
        XCTAssertNotEqual(movedID, oldID)
        XCTAssertEqual(observedID, movedID,
                       "a late old pathname cannot rotate the ID back after the move was observed")
    }

    func testStaleMetadataCannotRollBackObservedPresentationLocation() async throws {
        let engine = MemoryEngine()
        let id = engine.seed("before.bin", data: Data([1]))
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let before = try await engine.lookup(id)
        await table.storeMeta(before)
        let beforeID = await table.presentationFileId(for: before)

        let moved = try await engine.rename(id, newParent: .root, newName: "after.bin")
        await table.storeMeta(moved)
        let movedID = await table.presentationFileId(for: moved)
        XCTAssertNotEqual(movedID, beforeID)

        let acceptedStaleMeta = await table.storeMeta(before)
        let cached = await table.staleMeta(id)
        let staleSnapshotID = await table.presentationFileId(for: before)
        XCTAssertFalse(acceptedStaleMeta)
        XCTAssertEqual(cached?.name, "after.bin")
        XCTAssertEqual(staleSnapshotID, movedID,
                       "a stale metadata response cannot roll the presentation location backward")
    }

    func testInvalidatedCacheRetainsObservedVersionAgainstLateStaleMetadata() async throws {
        let engine = MemoryEngine()
        let id = engine.seed("before.bin", data: Data([1]))
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let before = try await engine.lookup(id)
        await table.storeMeta(before)
        let beforeID = await table.presentationFileId(for: before)

        let moved = try await engine.rename(id, newParent: .root, newName: "after.bin")
        await table.storeMeta(moved)
        let movedID = await table.presentationFileId(for: moved)
        XCTAssertNotEqual(movedID, beforeID)

        await table.invalidateMeta(id)
        let acceptedStaleMeta = await table.storeMeta(before)
        let staleSnapshotID = await table.presentationFileId(for: before)
        let cachedMeta = await table.staleMeta(id)
        XCTAssertFalse(acceptedStaleMeta)
        XCTAssertEqual(staleSnapshotID, movedID)
        XCTAssertNil(cachedMeta,
                       "the invalidated TTL cache remains empty even though the version guard persists")
    }

    func testLocalDirectoryRenamePreservesDescendantPresentationIDs() async throws {
        let engine = MemoryEngine()
        let folder = engine.seedDir("before")
        let child = engine.seed("child.bin", parent: folder, data: Data([1]))
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let folderBefore = await table.presentationFileId(for: try await engine.lookup(folder))
        let childBefore = await table.presentationFileId(for: try await engine.lookup(child))

        let token = await table.beginLocalRename(folder)
        let moved = try await engine.rename(folder, newParent: .root, newName: "after")
        await table.commitLocalRename(moved, token: token)
        let folderAfter = await table.presentationFileId(for: moved)
        let childAfter = await table.presentationFileId(for: try await engine.lookup(child))

        XCTAssertEqual(folderAfter, folderBefore)
        XCTAssertEqual(childAfter, childBefore,
                       "an SMB-initiated directory move leaves cached descendant identities intact")
    }

    func testPresentationDirectoryRetriesAfterWaitingForReplacementRename() async throws {
        let engine = MemoryEngine()
        let source = engine.seed("source.bin", data: Data("new bytes".utf8))
        let replaced = engine.seed("target.bin", data: Data("old bytes".utf8))
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let sourceBefore = try await engine.lookup(source)
        _ = await table.presentationFileId(for: sourceBefore)
        _ = try await table.children(of: .root) // Leave a pre-rename listing cached.

        let token = await table.beginLocalRename(source)
        let pendingListing = Task { try await table.presentationChildren(of: .root) }
        for _ in 0..<100 {
            if await table.localRenameWaiterCount(source) > 0 { break }
            await Task.yield()
        }
        let waiterCount = await table.localRenameWaiterCount(source)
        XCTAssertEqual(waiterCount, 1, "the pre-rename listing must be waiting on the local commit")

        let moved = try await engine.rename(source, newParent: .root, newName: "target.bin",
                                            replacing: try await engine.lookup(replaced))
        await table.commitLocalRename(moved, token: token, forgetting: [replaced],
                                      invalidatingDirectories: [.root])
        let entries = try await pendingListing.value

        XCTAssertEqual(entries.map { $0.metadata.name }, ["target.bin"])
        XCTAssertEqual(entries.map { $0.metadata.id }, [source],
                       "the replaced inode must not survive as a duplicate old listing entry")
        XCTAssertEqual(entries.first?.metadata.metadataVersion, moved.metadataVersion,
                       "the waiter receives metadata committed with the rename")
        let sourceID = await table.presentationFileId(for: sourceBefore)
        XCTAssertEqual(entries.first?.fileID, sourceID,
                       "a local rename updates location metadata while preserving its presentation ID")
    }

    func testReplacedRetainedInodeCanRefreshMetadataAfterForget() async throws {
        let engine = MemoryEngine()
        let source = engine.seed("source.bin", data: Data("new".utf8))
        let replaced = engine.seed("target.bin", data: Data("old".utf8))
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let original = try await engine.lookup(replaced)
        try await engine.beginOpen(replaced, handle: "held-old", access: [.read, .write],
                                   sharing: [.read, .write, .delete])
        _ = await table.presentationFileId(for: original)

        let token = await table.beginLocalRename(source)
        let moved = try await engine.rename(source, newParent: .root, newName: "target.bin",
                                            replacing: original)
        await table.commitLocalRename(moved, token: token, forgetting: [replaced],
                                      invalidatingDirectories: [.root])

        _ = try await engine.writeRange(replaced, offset: 3, data: Data("!".utf8), baseVersion: nil)
        let refreshed = try await engine.lookup(replaced)
        XCTAssertEqual(refreshed.size, 4)
        let accepted = await table.storeMeta(refreshed)
        XCTAssertTrue(accepted,
                      "forgetting a replaced namespace entry must not block updates to a retained open handle")

        await engine.endOpen(replaced, handle: "held-old")
    }

    func testConcurrentLocalRenamesOnOneInodeAreSerialized() async throws {
        let engine = MemoryEngine()
        let id = engine.seed("before.bin", data: Data([1]))
        let table = NodeTable(engine: engine, ttl: .seconds(60), remotePresentationIDs: true)
        let first = await table.beginLocalRename(id)
        let secondTask = Task { await table.beginLocalRename(id) }
        for _ in 0..<100 {
            if await table.queuedLocalRenameCount(id) == 1 { break }
            await Task.yield()
        }
        let queued = await table.queuedLocalRenameCount(id)
        XCTAssertEqual(queued, 1)

        await table.cancelLocalRename(id, token: first)
        let second = await secondTask.value
        XCTAssertNotEqual(second, first)
        let moved = try await engine.lookup(id)
        await table.commitLocalRename(moved, token: second)
    }

    func testOlderLookupCannotResurrectForgottenInode() async throws {
        let engine = MemoryEngine()
        let id = engine.seed("removed.bin", data: Data())
        let gate = ListingGate()
        engine.lookupSnapshotHook = { await gate.pauseFirst() }
        let table = NodeTable(engine: engine, ttl: .seconds(60))
        let lookup = Task { try await table.meta(id) }
        await gate.started()
        try await engine.delete(id, baseVersion: "1", recursive: false)
        await table.forget(id, parent: .root)
        await gate.release()
        do { _ = try await lookup.value; XCTFail("An older lookup must not resurrect a deleted inode") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notFound) }
        let cached = await table.staleMeta(id)
        XCTAssertNil(cached)
    }

    func testInvalidationDuringEnumerationCannotRestoreStaleSnapshot() async throws {
        let engine = MemoryEngine()
        let parent = engine.seedDir("project")
        let gate = ListingGate()
        engine.enumerationSnapshotHook = { await gate.pauseFirst() }
        let table = NodeTable(engine: engine, ttl: .seconds(60))
        let enumeration = Task { try await table.children(of: parent) }
        await gate.started()
        let created = engine.seed("peer.done.json", parent: parent, data: Data())
        await table.invalidateListing(parent)
        await gate.release()
        let children = try await enumeration.value
        XCTAssertEqual(children.map(\.id), [created])
        let cached = try await table.children(of: parent)
        XCTAssertEqual(cached.map(\.id), [created])
    }

    func testOlderConcurrentListingCannotReplaceNewerCompletedSnapshot() async throws {
        let engine = MemoryEngine()
        let parent = engine.seedDir("project")
        let gate = ListingGate()
        engine.enumerationSnapshotHook = { await gate.pauseFirst() }
        let table = NodeTable(engine: engine, ttl: .seconds(60))
        let older = Task { try await table.children(of: parent) }
        await gate.started()
        let created = engine.seed("peer.done.json", parent: parent, data: Data())
        let newer = try await table.children(of: parent)
        XCTAssertEqual(newer.map(\.id), [created])
        await gate.release()
        let completed = try await older.value
        XCTAssertEqual(completed.map(\.id), [created])
        let cached = try await table.children(of: parent)
        XCTAssertEqual(cached.map(\.id), [created])
    }

    func testListingKeepsNewerMetadataLearnedWhileEnumerationWaited() async throws {
        let engine = MemoryEngine()
        let parent = engine.seedDir("project")
        let id = engine.seed("edit.bin", parent: parent, data: Data([1]))
        let gate = ListingGate()
        engine.enumerationSnapshotHook = { await gate.pauseFirst() }
        let table = NodeTable(engine: engine, ttl: .seconds(60))
        let listing = Task { try await table.children(of: parent) }
        await gate.started()
        _ = try await engine.writeRange(id, offset: 1, data: Data([2, 3]), baseVersion: nil)
        let newer = try await engine.lookup(id)
        await table.storeMeta(newer)
        await gate.release()
        let completed = try await listing.value
        XCTAssertEqual(completed.first?.size, 3)
        XCTAssertEqual(completed.first?.contentVersion, newer.contentVersion)
        let cached = try await table.children(of: parent)
        XCTAssertEqual(cached.first?.size, 3)
    }

    func testListingDoesNotRestoreInodeForgottenWhileEnumerationWaited() async throws {
        let engine = MemoryEngine()
        let parent = engine.seedDir("project")
        let id = engine.seed("removed.bin", parent: parent, data: Data())
        let gate = ListingGate()
        engine.enumerationSnapshotHook = { await gate.pauseFirst() }
        let table = NodeTable(engine: engine, ttl: .seconds(60))
        let listing = Task { try await table.children(of: parent) }
        await gate.started()
        try await engine.delete(id, baseVersion: "1", recursive: false)
        await table.forget(id, parent: parent)
        await gate.release()
        let completed = try await listing.value
        XCTAssertTrue(completed.isEmpty)
    }

    func testNewParentMetadataInvalidatesOlderPositiveListing() async throws {
        let engine = MemoryEngine()
        let parent = engine.seedDir("project")
        let old = engine.seed("atomic.bin", parent: parent, data: Data("old".utf8))
        let staged = engine.seed("stage", parent: parent, data: Data("new".utf8))
        let table = NodeTable(engine: engine, ttl: .seconds(60))
        _ = try await table.meta(parent)
        _ = try await table.children(of: parent)

        _ = try await engine.rename(staged, newParent: parent, newName: "atomic.bin", replacing: engine.lookup(old))
        _ = try await engine.setBasicInfo(parent, info: BasicFileInfo(modifiedAt: Date()))
        await table.invalidateMeta(parent)
        _ = try await table.meta(parent)

        let resolved = try await table.child(of: parent, named: "atomic.bin")
        XCTAssertEqual(resolved?.id, staged, "A newer parent must not coexist with its older child-name mapping")
    }

    func testExplicitNewDirectoryMetadataInvalidatesListing() async throws {
        let engine = MemoryEngine()
        let parent = engine.seedDir("project")
        let old = engine.seed("old.txt", parent: parent, data: Data())
        let table = NodeTable(engine: engine, ttl: .seconds(60))
        _ = try await table.meta(parent)
        _ = try await table.children(of: parent)
        _ = try await engine.rename(old, newParent: parent, newName: "new.txt")
        let changed = try await engine.setBasicInfo(parent, info: BasicFileInfo(modifiedAt: Date()))
        await table.storeMeta(changed)
        let children = try await table.children(of: parent)
        XCTAssertEqual(children.map(\.name), ["new.txt"])
    }
}
