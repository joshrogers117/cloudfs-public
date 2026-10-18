// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — the read-path data handlers: CREATE (open existing + MxAc/AAPL
// create-context replies), CLOSE, READ, QUERY_DIRECTORY (FileIdBothDirectory-
// Information), QUERY_INFO (FILE + FILESYSTEM classes). Writes/dispositions land
// in P2. Each handler bridges the async engine on the connection thread.
//
// AAPL note: we answer the ServerQuery so the client marks us an OS X server, but
// we do NOT advertise SUPPORTS_READ_DIR_ATTR yet — that flag changes how the
// client reads directory entries and is turned on in P4 together with the
// enrichment. Here we advertise UNIX_BASED + CASE_SENSITIVE only.

import Foundation
import CloudFSCore

extension SMBServer {

    // MARK: CREATE ([MS-SMB2] §2.2.13 / §2.2.14)

    func handleCreate(_ hdr: SMB2Header, body: Data, state: SMBConnectionState,
                      profileConnection: Int32? = nil)
        -> (NTStatus, Data, DispatchExtra) {
        state.lastOpen = nil  // a failed CREATE cannot inherit an earlier compound handle
        guard state.treeConnected else { return (.accessDenied, errorBody(), DispatchExtra()) }
        guard let req = parseCreate(body) else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        if req.contexts.contains(where: { $0.name == CreateContextName.aapl }) { state.appleClient = true }

        // The client's AAPL ServerQuery (first root CREATE) opts it into AAPL
        // readdir-attr enrichment — remember it for QUERY_DIRECTORY packing.
        if req.contexts.contains(where: { $0.name == CreateContextName.aapl }),
           ProcessInfo.processInfo.environment["CLOUDFS_SMB_NO_AAPL"] == nil,
           ProcessInfo.processInfo.environment["CLOUDFS_SMB_NO_READDIRATTR"] == nil {
            state.aaplReadDirAttr = true
        }

        let table = self.table
        let streamPath = SMBStreams.parse(req.name)
        let result: (NTStatus, Data) = SMBServer.bridgeSync {
            func measured<T>(_ phase: String, _ operation: () async throws -> T) async rethrows -> T {
                let started = DispatchTime.now().uptimeNanoseconds
                SMBLog.profile(connection: profileConnection, messageId: hdr.messageId, command: .create,
                               phase: "create-\(phase)-start")
                do {
                    let value = try await operation()
                    SMBLog.profile(connection: profileConnection, messageId: hdr.messageId, command: .create,
                                   phase: "create-\(phase)-finish",
                                   elapsedNanoseconds: DispatchTime.now().uptimeNanoseconds &- started)
                    return value
                } catch {
                    SMBLog.profile(connection: profileConnection, messageId: hdr.messageId, command: .create,
                                   phase: "create-\(phase)-error",
                                   elapsedNanoseconds: DispatchTime.now().uptimeNanoseconds &- started)
                    throw error
                }
            }
            let engine = await table.engineRef()
            let leaseHandle = UUID().uuidString
            let openHandle = leaseHandle
            let fileId = await MainActorFree.newId(state)
            var leasedNode: InodeID?
            var retainedNode: InodeID?
            var remoteRetained = false
            var registered = false
            func runCreate() async -> (NTStatus, Data) {
              do {
                let comps = SMBPath.components(streamPath.base)
                guard let disp = CreateDisposition(rawValue: req.disposition) else { return (.invalidParameter, errorBody()) }
                let access = SMBAccess.expanded(req.desiredAccess)
                guard req.shareAccess & ~UInt32(0x7) == 0 else { return (.invalidParameter, errorBody()) }
                let openAccess = SMBAccess.openFileAccess(access)
                let sharing = OpenFileSharing(rawValue: UInt8(req.shareAccess))
                if req.options & CreateOptions.deleteOnClose != 0, access & SMBAccess.delete == 0 {
                    return (.accessDenied, errorBody())
                }
                if disp == .overwrite || disp == .overwriteIf || disp == .supersede,
                   access & SMBAccess.writeData == 0 { return (.accessDenied, errorBody()) }
                let changesContent = access & (SMBAccess.writeData | SMBAccess.appendData) != 0
                    || req.options & CreateOptions.deleteOnClose != 0
                    || disp == .overwrite || disp == .overwriteIf || disp == .supersede
                let wantDir = req.options & CreateOptions.directoryFile != 0
                // FILE_WRITE_DATA/APPEND/EA/ATTR, DELETE, WRITE_DAC/OWNER,
                // GENERIC_WRITE/ALL. An OPEN must fail before local write-back ACKs.
                let wantsWrite = req.desiredAccess & 0x500D_0116 != 0
                    || req.options & CreateOptions.deleteOnClose != 0
                    || disp == .overwrite || disp == .overwriteIf || disp == .supersede
                if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil {
                    SMBLog.line("create name='\(req.name)' base=\(streamPath.base) stream=\(streamPath.stream ?? "-") disp=\(req.disposition) opts=0x\(String(req.options, radix: 16)) ctxs=\(req.contexts.map(\.name))")
                }

                // Only the exact readonly CREATE/QDIR/CLOSE compound is eligible.
                // The gateway transaction rechecks ACL/share admission, obtains
                // a complete bounded child view, and closes its temporary remote
                // handle before returning. The local share reservation remains
                // held until the related SMB CLOSE below.
                if state.directorySnapshotCandidate, streamPath.stream == nil,
                   disp == .open, req.options == CreateOptions.directoryFile,
                   req.contexts.isEmpty, openAccess.rawValue <= OpenFileAccess.read.rawValue,
                   !wantsWrite, !comps.isEmpty,
                   let target = try await measured("resolve", { try await table.resolve(components: comps) }),
                   target.isDir,
                   let reservation = await table.reserveDirectorySnapshotOpen(target, handle: openHandle,
                       access: openAccess, sharing: sharing) {
                    retainedNode = target.id
                    if let snapshot = try await measured("directory-snapshot", {
                        try await engine.directorySnapshot(target.id, handle: openHandle,
                                                           access: openAccess, sharing: sharing)
                    }), let presentedSnapshot = await table.adoptDirectorySnapshot(snapshot, reservation: reservation) {
                        let openMeta = presentedSnapshot.directory
                        let diskFileID = presentedSnapshot.directoryFileID
                        let open = SMBOpen(fileId: fileId, node: openMeta.id, isDir: true,
                                           contentVersion: openMeta.contentVersion, size: openMeta.size,
                                           presentationFileID: diskFileID)
                        open.remoteOpenRetained = false
                        open.transientDirectorySnapshot = presentedSnapshot
                        open.leaseHandle = leaseHandle
                        open.grantedAccess = access
                        open.shareAccess = sharing
                        await MainActorFree.register(state, open)
                        registered = true
                        let body = self.createResponse(meta: openMeta, fileId: fileId,
                                                       diskFileID: diskFileID, action: 1,
                                                       contexts: req.contexts)
                        return (.success, body)
                    }
                    // Too-large/unsupported snapshots and stale local epochs
                    // retain ordinary CREATE semantics through the existing path.
                    await table.endLocalOpen(target.id, handle: openHandle)
                    retainedNode = nil
                }

                // Named-stream (xattr) open: the base file must exist; the open
                // targets the stream, created lazily on first WRITE.
                if let streamName = streamPath.stream {
                    guard let base = try await measured("resolve", { try await table.resolve(components: comps) }), !base.isDir else {
                        return (.objectNameNotFound, errorBody())
                    }
                    let engine = await table.engineRef()
                    if changesContent, SMBAttrs.isReadOnly(try await engine.lookup(base.id)) {
                        return (.accessDenied, errorBody())
                    }
                    guard await measured("local-open", { await table.beginLocalOpen(base.id, handle: openHandle, access: openAccess, sharing: sharing) }) else {
                        return (.sharingViolation, errorBody())
                    }
                    // Set before the async acquire so common CREATE cleanup also
                    // releases a legacy lease if its stream-list fallback fails.
                    retainedNode = base.id
                    let existingSize: Int?
                    if disp == .open && !wantsWrite {
                        // This read-only probe cannot create or overwrite stream
                        // state. Resolve existence atomically with remote open.
                        // Mark cleanup ownership before awaiting: legacy gateway
                        // fallback may acquire the open before listStreams fails.
                        remoteRetained = true
                        existingSize = try await measured("remote-stream-open") {
                            try await engine.beginStreamOpen(base.id, handle: openHandle, access: openAccess,
                                                             sharing: sharing, name: streamName,
                                                             required: true)
                        }
                    } else {
                        // Writable dispositions keep the stream check after the
                        // write lease so collision/overwrite decisions use fresh
                        // metadata protected against concurrent stream creation.
                        do { try await measured("remote-begin-open") { try await engine.beginOpen(base.id, handle: openHandle, access: openAccess, sharing: sharing) } }
                        catch { retainedNode = nil; await table.endLocalOpen(base.id, handle: openHandle); throw error }
                        remoteRetained = true
                        if wantsWrite {
                            try await measured("authorize") { try await engine.authorizeWrite(base.id, refresh: true) }
                            try await measured("lease") { try await engine.beginWrite(base.id, handle: leaseHandle) }
                            leasedNode = base.id
                        }
                        existingSize = (try await measured("stream-list") { try await engine.listStreams(base.id) })
                            .first { $0.name == streamName }?.size
                    }
                    if existingSize != nil, disp == .create { return (.objectNameCollision, errorBody()) }
                    if existingSize == nil, disp == .open || disp == .overwrite {
                        return (.objectNameNotFound, errorBody())  // reading a missing xattr
                    }
                    if let existingSize, disp == .overwrite || disp == .overwriteIf || disp == .supersede {
                        let probe = SMBOpen(fileId: fileId, node: base.id, isDir: false, contentVersion: base.contentVersion, size: existingSize)
                        probe.leaseHandle = leaseHandle; probe.streamName = streamName
                        try await self.checkRangeAccess(probe, offset: 0, length: UInt64(max(existingSize, 1)), write: true)
                        try await engine.truncateStream(base.id, name: streamName, size: 0)
                    }
                    let streamSize = (disp == .overwrite || disp == .overwriteIf || disp == .supersede) ? 0 : (existingSize ?? 0)
                    let presented = await measured("presentation") { await table.presentationMetadata(for: base) }
                    let currentBase = presented.metadata
                    let diskFileID = presented.fileID
                    let open = SMBOpen(fileId: fileId, node: currentBase.id, isDir: false,
                                       contentVersion: currentBase.contentVersion, size: streamSize,
                                       presentationFileID: diskFileID)
                    open.streamName = streamName
                    open.grantedAccess = access
                    open.shareAccess = sharing
                    open.leaseHandle = leaseHandle; open.writeLease = leasedNode != nil
                    if req.options & CreateOptions.deleteOnClose != 0 { open.deleteOnClose = true }
                    await MainActorFree.register(state, open)
                    registered = true
                    let meta = ItemMetadata(id: currentBase.id, parent: currentBase.parent, name: currentBase.name,
                                            isDir: false, size: streamSize,
                                            contentVersion: currentBase.contentVersion, metadataVersion: currentBase.metadataVersion,
                                            createdAt: currentBase.createdAt, modifiedAt: currentBase.modifiedAt, accessedAt: currentBase.accessedAt,
                                            changedAt: currentBase.changedAt, fileAttributes: currentBase.fileAttributes)
                    return (.success, self.createResponse(meta: meta, fileId: fileId,
                                                          diskFileID: diskFileID,
                                                          action: existingSize == nil ? 2 : 1, contexts: req.contexts))
                }

                let existing = try await measured("resolve") { try await table.resolve(components: comps) }
                let engine = await table.engineRef()

                // Resolve to (metadata, CreateAction) applying the disposition.
                let resolved: (meta: ItemMetadata, action: UInt32)
                if var meta = existing {
                    // Writable file opens refresh metadata again after acquiring
                    // the distributed lease below. Defer this readonly check to
                    // that leased refresh instead of serializing two GET /items
                    // calls before CREATE can complete.
                    let refreshUnderLease = wantsWrite && !meta.isDir
                    if changesContent && !refreshUnderLease {
                        meta = try await engine.lookup(meta.id)
                        await table.storeMeta(meta)
                        if SMBAttrs.isReadOnly(meta) { return (.accessDenied, errorBody()) }
                    }
                    guard await measured("local-open", { await table.beginLocalOpen(meta.id, handle: openHandle, access: openAccess, sharing: sharing) }) else {
                        return (.sharingViolation, errorBody())
                    }
                    do { try await measured("remote-begin-open") { try await engine.beginOpen(meta.id, handle: openHandle, access: openAccess, sharing: sharing) } }
                    catch { await table.endLocalOpen(meta.id, handle: openHandle); throw error }
                    remoteRetained = true
                    retainedNode = meta.id
                    if wantsWrite {
                        if meta.isDir {
                            try await measured("authorize") { try await engine.authorizeWrite(meta.id, refresh: true) }
                        } else {
                            // Set cleanup ownership before awaiting: the adapter may
                            // retain a local lease even when the metadata response
                            // is absent or malformed and fallback lookup then fails.
                            leasedNode = meta.id
                            let snapshot = try await measured("lease+metadata") {
                                try await engine.beginWriteSnapshot(meta.id, handle: leaseHandle)
                            }
                            if let snapshot {
                                meta = snapshot
                            } else {
                                // Legacy gateways and local lease hits cannot return
                                // transactionally fresh metadata. Keep the established
                                // authorization and under-lease lookup in that case.
                                try await measured("authorize") { try await engine.authorizeWrite(meta.id, refresh: true) }
                                meta = try await engine.lookup(meta.id)
                            }
                            await table.storeMeta(meta)
                            if changesContent && SMBAttrs.isReadOnly(meta) {
                                return (.accessDenied, errorBody())
                            }
                        }
                    }
                    // Directory/non-directory intent sanity.
                    if req.options & CreateOptions.directoryFile != 0, !meta.isDir {
                        return (.notADirectory, errorBody())
                    }
                    if req.options & CreateOptions.nonDirectoryFile != 0, meta.isDir {
                        return (.fileIsADirectory, errorBody())
                    }
                    if !meta.isDir, disp == .overwrite || disp == .overwriteIf || disp == .supersede {
                        let probe = SMBOpen(fileId: fileId, node: meta.id, isDir: false, contentVersion: meta.contentVersion, size: meta.size)
                        probe.leaseHandle = leaseHandle
                        try await self.checkRangeAccess(probe, offset: 0, length: UInt64(max(meta.size, 1)), write: true)
                    }
                    switch disp {
                    case .create:
                        return (.objectNameCollision, errorBody())
                    case .open, .openIf:
                        resolved = (meta, 1)                       // FILE_OPENED
                    case .overwrite, .overwriteIf:
                        if meta.isDir { return (.fileIsADirectory, errorBody()) }
                        try await engine.truncate(meta.id, newSize: 0, baseVersion: meta.metadataVersion)
                        await table.projectWrite(meta.id, newSize: 0)
                        resolved = (try await table.meta(meta.id), 3) // FILE_OVERWRITTEN
                    case .supersede:
                        if !meta.isDir {
                            try await engine.truncate(meta.id, newSize: 0, baseVersion: meta.metadataVersion)
                            await table.projectWrite(meta.id, newSize: 0)
                        }
                        resolved = (try await table.meta(meta.id), 0) // FILE_SUPERSEDED
                    }
                } else {
                    switch disp {
                    case .open, .overwrite:
                        return (.objectNameNotFound, errorBody())
                    case .create, .openIf, .overwriteIf, .supersede:
                        guard comps.count >= 1 else { return (.objectNameInvalid, errorBody()) }
                        let parentComps = Array(comps.dropLast())
                        let leaf = comps[comps.count - 1]
                        guard let created = try await table.createItem(parentComponents: parentComps,
                                                                       name: leaf, isDir: wantDir) else {
                            return (.objectPathNotFound, errorBody())
                        }
                        guard await measured("local-open", { await table.beginLocalOpen(created.id, handle: openHandle, access: openAccess, sharing: sharing) }) else {
                            return (.sharingViolation, errorBody())
                        }
                        do { try await measured("remote-begin-open") { try await engine.beginOpen(created.id, handle: openHandle, access: openAccess, sharing: sharing) } }
                        catch { await table.endLocalOpen(created.id, handle: openHandle); throw error }
                        remoteRetained = true
                        retainedNode = created.id
                        if let p = created.parent { state.notify?.postLocalChange(p) }
                        resolved = (created, 2)                    // FILE_CREATED
                    }
                }

                if wantsWrite, !resolved.meta.isDir, leasedNode == nil {
                    try await measured("lease") { try await engine.beginWrite(resolved.meta.id, handle: leaseHandle) }
                    leasedNode = resolved.meta.id
                }
                let presented = await measured("presentation") { await table.presentationMetadata(for: resolved.meta) }
                let openMeta = presented.metadata
                let diskFileID = presented.fileID
                let open = SMBOpen(fileId: fileId, node: openMeta.id, isDir: openMeta.isDir,
                                   contentVersion: openMeta.contentVersion, size: openMeta.size,
                                   presentationFileID: diskFileID)
                open.leaseHandle = leaseHandle; open.writeLease = leasedNode != nil
                open.grantedAccess = access
                open.shareAccess = sharing
                if req.options & CreateOptions.deleteOnClose != 0 { open.deleteOnClose = true }
                await MainActorFree.register(state, open)
                registered = true

                let body = self.createResponse(meta: openMeta, fileId: fileId,
                                               diskFileID: diskFileID,
                                               action: resolved.action, contexts: req.contexts)
                return (.success, body)
            } catch let e as EngineError {
                return (ntStatus(for: e), errorBody())
            } catch {
                return (.unsuccessful, errorBody())
              }
            }
            let outcome = await runCreate()
            if !registered {
                if let node = leasedNode { await engine.endWrite(node, handle: leaseHandle) }
                if let node = retainedNode {
                    if remoteRetained { await engine.endOpen(node, handle: openHandle) }
                    await table.endLocalOpen(node, handle: openHandle)
                }
            }
            return outcome
        }
        return (result.0, result.1, DispatchExtra())
    }

    /// CREATE response body ([MS-SMB2] §2.2.14) + optional MxAc/AAPL contexts.
    /// `action` is the CreateAction (0 superseded, 1 opened, 2 created, 3 overwritten).
    private func createResponse(meta: ItemMetadata, fileId: SMBFileId, diskFileID: UInt64,
                                action: UInt32, contexts: [ParsedContext]) -> Data {
        let ts = SMBAttrs.times(created: meta.createdAt, modified: meta.modifiedAt, accessed: meta.accessedAt, changed: meta.changedAt,
                                contentVersion: meta.contentVersion)
        var w = ByteWriter()
        w.u16(89)                                   // StructureSize
        w.u8(0)                                     // OplockLevel = NONE
        w.u8(0)                                     // Flags
        w.u32(action)                               // CreateAction
        w.u64(ts.creation); w.u64(ts.access); w.u64(ts.write); w.u64(ts.change)
        w.u64(SMBAttrs.allocationSize(meta.size))   // AllocationSize
        w.u64(UInt64(meta.size))                    // EndOfFile
        w.u32(SMBAttrs.fileAttributes(isDir: meta.isDir, stored: meta.fileAttributes))
        w.u32(0)                                    // Reserved2
        w.u64(fileId.persistent); w.u64(fileId.volatile)

        let ctx = buildCreateContexts(requested: contexts, diskFileID: diskFileID,
                                      volumeID: qfidVolumeID())
        // CreateContextsOffset is from the SMB2 header start; contexts follow the
        // 88-byte fixed body (after the 4-byte offset/length pair here).
        if ctx.isEmpty {
            w.u32(0); w.u32(0)                      // offset, length
        } else {
            let off = SMB2Header.size + 88
            w.u32(UInt32(off)); w.u32(UInt32(ctx.count))
            w.bytes(ctx)
        }
        return w.data
    }

    /// Build MxAc + AAPL create-context responses for whichever the client asked.
    private func buildCreateContexts(requested: [ParsedContext], diskFileID: UInt64,
                                     volumeID: UInt64) -> Data {
        var pieces: [Data] = []
        for c in requested {
            if c.name == CreateContextName.maxAccess {
                var d = ByteWriter()
                d.u32(0)                            // QueryStatus = STATUS_SUCCESS
                d.u32(0x001F_01FF)                  // MaximalAccess = FILE_ALL_ACCESS
                pieces.append(makeContext(name: CreateContextName.maxAccess, data: d.data))
            } else if c.name == CreateContextName.queryOnDiskId {
                var d = ByteWriter()
                d.u64(diskFileID)                   // DiskFileId: stable NodeTable inode id
                d.u64(volumeID)                      // VolumeId: stable for this mounted share
                d.zeros(16)                          // Reserved
                pieces.append(makeContext(name: CreateContextName.queryOnDiskId, data: d.data))
            } else if c.name == CreateContextName.aapl,
                      ProcessInfo.processInfo.environment["CLOUDFS_SMB_NO_AAPL"] == nil {
                pieces.append(makeContext(name: CreateContextName.aapl, data: aaplServerQueryReply()))
            }
        }
        // Chain them with NextEntry offsets (8-aligned); last Next = 0.
        var out = Data()
        for (i, piece) in pieces.enumerated() {
            var p = piece
            let isLast = i == pieces.count - 1
            let padded = (p.count + 7) & ~7
            if !isLast, padded > p.count { p.append(Data(count: padded - p.count)) }
            if !isLast { patchU32(&p, at: 0, UInt32(p.count)) }   // Next
            out.append(p)
        }
        return out
    }

    /// Use the first server-guid word as this SMB server instance's volume id.
    /// The SMB server and its NodeTable are created together for one mounted share.
    private func qfidVolumeID() -> UInt64 {
        var reader = ByteReader(serverGuid)
        guard let value = try? reader.u64(), value != 0 else { return 1 }
        return value
    }

    /// AAPL ServerQuery reply (Apple smb_2.h): mark us an OS X server and, unless
    /// disabled, advertise SUPPORTS_READ_DIR_ATTR so QUERY_DIRECTORY entries carry
    /// the enrichment overlay (rsrc-fork size + FinderInfo + POSIX mode) — Finder
    /// then skips a per-file stream probe when listing.
    private func aaplServerQueryReply() -> Data {
        var serverCaps = AAPL.capUnixBased
        if ProcessInfo.processInfo.environment["CLOUDFS_SMB_NO_READDIRATTR"] == nil {
            serverCaps |= AAPL.capSupportsReadDirAttr
        }
        var w = ByteWriter()
        w.u32(AAPL.commandServerQuery)              // CommandCode
        w.u32(0)                                    // Reserved
        w.u64(AAPL.bitmapServerCaps | AAPL.bitmapVolumeCaps)  // ReplyBitmap
        w.u64(serverCaps)                           // ServerCaps
        w.u64(AAPL.volCaseSensitive)                // VolumeCaps
        return w.data
    }

    /// One create context ([MS-SMB2] §2.2.13.2): Next(4)=0, NameOffset(2),
    /// NameLength(2), Reserved(2), DataOffset(2), DataLength(4), name, pad, data.
    private func makeContext(name: String, data: Data) -> Data {
        let nameBytes = Data(name.utf8)             // context names are ASCII
        var w = ByteWriter()
        w.u32(0)                                    // Next (patched by caller if chained)
        let nameOffset = 16                         // fixed header size
        w.u16(UInt16(nameOffset))                   // NameOffset
        w.u16(UInt16(nameBytes.count))              // NameLength
        w.u16(0)                                    // Reserved
        let namePadded = (nameBytes.count + 7) & ~7
        let dataOffset = nameOffset + namePadded
        w.u16(UInt16(dataOffset))                   // DataOffset
        w.u32(UInt32(data.count))                   // DataLength
        w.bytes(nameBytes)
        if namePadded > nameBytes.count { w.zeros(namePadded - nameBytes.count) }
        w.bytes(data)
        return w.data
    }

    // MARK: CLOSE ([MS-SMB2] §2.2.15 / §2.2.16)

    func handleClose(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        var r = ByteReader(body)
        guard (try? r.u16()) == 24 else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        let flags = (try? r.u16()) ?? 0
        _ = try? r.u32()                            // Reserved
        let fileId = readFileId(&r)
        guard !state.isOpenOnDifferentTree(fileId) else {
            return (.fileClosed, errorBody(), DispatchExtra())
        }
        let open = state.close(fileId)
        if let open {
            lockTable.releaseAll(owner: open.fileId)
            state.notify?.closeHandle(open.fileId)
        }

        // Delete-on-close failures must reach Finder: do not forget a live file
        // locally or claim deletion succeeded after the gateway refused it.
        var closeStatus = NTStatus.success
        if let open, open.deleteOnClose {
            let table = self.table
            let node = open.node
            let streamName = open.streamName
            closeStatus = SMBServer.bridgeSync {
                guard await table.allowsDelete(node, excluding: open.leaseHandle) else { return .sharingViolation }
                let engine = await table.engineRef()
                do {
                    if let streamName {
                        try await engine.deleteStream(node, name: streamName)
                    } else {
                        let meta = try await table.meta(node)
                        try await engine.delete(node, baseVersion: meta.metadataVersion, recursive: false,
                                                openHandle: open.leaseHandle)
                        await table.forget(node, parent: meta.parent)
                        if let p = meta.parent { state.notify?.postLocalChange(p) }
                    }
                    return .success
                } catch let error as EngineError { return ntStatus(for: error) }
                catch { return .unsuccessful }
            }
        }

        if let open {
            let table = self.table
            _ = SMBServer.bridgeSync {
                let engine = await table.engineRef()
                if open.remoteOpenRetained {
                    await engine.releaseAllRanges(open.node, handle: open.leaseHandle)
                }
                if open.writeLease { await engine.endWrite(open.node, handle: open.leaseHandle) }
                if open.remoteOpenRetained { await engine.endOpen(open.node, handle: open.leaseHandle) }
                await table.endLocalOpen(open.node, handle: open.leaseHandle)
                return true
            }
        }
        guard closeStatus == .success else { return (closeStatus, errorBody(), DispatchExtra()) }
        if flags & 0x0001 != 0, let open, let name = open.streamName, !open.deleteOnClose {
            let table = self.table
            let result: (NTStatus, Int) = SMBServer.bridgeSync {
                do { return (.success, try await table.engineRef().listStreams(open.node).first { $0.name == name }?.size ?? 0) }
                catch let error as EngineError { return (ntStatus(for: error), 0) }
                catch { return (.unsuccessful, 0) }
            }
            guard result.0 == .success else { return (result.0, errorBody(), DispatchExtra()) }
            open.size = result.1
        }
        var w = ByteWriter()
        w.u16(60)                                   // StructureSize
        w.u16(flags)                                // Flags (echo POSTQUERY_ATTRIB)
        w.u32(0)                                    // Reserved
        if flags & 0x0001 != 0, let open {
            let table = self.table
            let meta: ItemMetadata? = SMBServer.bridgeSync { try? await table.meta(open.node) }
            let times = SMBAttrs.times(created: meta?.createdAt, modified: meta?.modifiedAt,
                accessed: meta?.accessedAt, changed: meta?.changedAt, contentVersion: open.contentVersion)
            w.u64(times.creation); w.u64(times.access); w.u64(times.write); w.u64(times.change)
            w.u64(SMBAttrs.allocationSize(open.size))
            w.u64(UInt64(open.size))
            w.u32(SMBAttrs.fileAttributes(isDir: open.isDir, stored: meta?.fileAttributes))
        } else {
            w.zeros(8 * 6 + 4)                       // 4 times + alloc + eof (8 each) + attrs (4)
        }
        return (.success, w.data, DispatchExtra())
    }

    // MARK: READ ([MS-SMB2] §2.2.19 / §2.2.20)

    func handleRead(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        var r = ByteReader(body)
        guard (try? r.u16()) == 49 else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        _ = try? r.u8()                             // Padding
        _ = try? r.u8()                             // Flags
        let length = Int((try? r.u32()) ?? 0)
        guard let rawOffset = try? r.u64(), rawOffset <= UInt64(Int.max), length <= 1 << 20,
              rawOffset <= UInt64(Int.max - length) else {
            return (.invalidParameter, errorBody(), DispatchExtra())
        }
        let offset = Int(rawOffset)
        let fileId = readFileId(&r)
        guard let open = state.open(fileId), !open.isDir else {
            return (.fileClosed, errorBody(), DispatchExtra())
        }
        guard open.hasAccess(SMBAccess.readData) else { return (.accessDenied, errorBody(), DispatchExtra()) }
        if state.appleClient, let failure = open.readIntegrity.status {
            return (failure, errorBody(), DispatchExtra())
        }

        let table = self.table
        let node = open.node
        let version = open.contentVersion
        let streamName = open.streamName
        // (status, fixed-16-byte read response, payload). The payload rides
        // DispatchExtra.readPayload so it's scatter-written, not copied.
        let result: (NTStatus, Data, Data) = SMBServer.bridgeSync {
            var readStage = "admission"
            do {
                let engine = await table.engineRef()
                try await self.checkRangeAccess(open, offset: UInt64(offset), length: UInt64(length), write: false)
                // Named-stream read fetches only the requested encrypted chunks.
                if let streamName {
                    readStage = "stream-data"
                    // OPEN_IF creates a zero-length stream lazily. macOS reads
                    // AFP_AfpInfo before its first write; that read must be EOF,
                    // not a failed request for a blob which does not exist yet.
                    let payload: Data
                    do { payload = try await engine.readStreamRange(node, name: streamName, offset: offset, length: length) }
                    catch let error as EngineError where error.kind == .notFound {
                        return (.endOfFile, errorBody(), Data())
                    }
                    // Another handle may have grown or truncated this stream.
                    // Its current manifest, not this handle's old EOF, bounds READ.
                    if payload.isEmpty { return (.endOfFile, errorBody(), Data()) }
                    // A cold cloud read can outlive its admission permit. Check
                    // again before exposing bytes if another handle locked it.
                    readStage = "completion-admission"
                    try await self.checkRangeAccess(open, offset: UInt64(offset), length: UInt64(length), write: false)
                    return (.success, self.readResponseFixed(dataLen: payload.count), payload)
                }
                if offset >= open.size {
                    return (.endOfFile, errorBody(), Data())
                }
                let want = min(length, max(0, open.size - offset))
                readStage = "file-data"
                let data = try await engine.readBytes(node, version: version, offset: offset, length: want)
                readStage = "completion-admission"
                if !data.isEmpty { try await self.checkRangeAccess(open, offset: UInt64(offset), length: UInt64(length), write: false) }
                return (.success, self.readResponseFixed(dataLen: data.count), data)
            } catch let error as EngineError {
                if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil {
                    // No payload, bearer, presigned URL, or raw gateway envelope.
                    let detail = error.message.replacingOccurrences(of: "https?://\\S+", with: "<url>", options: .regularExpression).prefix(240)
                    let knownReasons = ["read-permit-expired", "lease-lost", "held-by-other", "fence-stale", "forbidden", "shared-lock"]
                    let reason: String
                    if case .string(let value) = error.data?["reason"], knownReasons.contains(value) { reason = value }
                    else { reason = "unspecified" }
                    FileHandle.standardError.write(Data("cloudfsd[smb]: read failure mid=\(hdr.messageId) stage=\(readStage) kind=\(error.kind.rawValue) reason=\(reason) message=\(detail)\n".utf8))
                }
                return (error.kind == .locked ? .fileLockConflict : ntStatus(for: error), errorBody(), Data())
            } catch {
                if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil {
                    let failure = error as NSError
                    FileHandle.standardError.write(Data("cloudfsd[smb]: read failure mid=\(hdr.messageId) stage=\(readStage) domain=\(failure.domain) code=\(failure.code)\n".utf8))
                }
                return (.unsuccessful, errorBody(), Data())
            }
        }
        return (result.0, result.1, DispatchExtra(readPayload: result.2.isEmpty ? nil : result.2))
    }

    /// READ response fixed part ([MS-SMB2] §2.2.20), WITHOUT the payload.
    /// DataOffset is from the header start = 80; the payload follows immediately.
    private func readResponseFixed(dataLen: Int) -> Data {
        var w = ByteWriter()
        w.u16(17)                                   // StructureSize
        w.u8(UInt8(SMB2Header.size + 16))           // DataOffset = 80
        w.u8(0)                                     // Reserved
        w.u32(UInt32(dataLen))                      // DataLength
        w.u32(0)                                    // DataRemaining
        w.u32(0)                                    // Reserved2
        return w.data
    }

    // MARK: WRITE ([MS-SMB2] §2.2.21 / §2.2.22)

    func handleWrite(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        var r = ByteReader(body)
        guard (try? r.u16()) == 49 else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        let dataOffset = Int((try? r.u16()) ?? 0)
        let length = Int((try? r.u32()) ?? 0)
        guard let rawOffset = try? r.u64(), rawOffset <= UInt64(Int.max), length <= SMBLimits.maximumWriteBytes,
              rawOffset <= UInt64(Int.max - length) else {
            return (.invalidParameter, errorBody(), DispatchExtra())
        }
        let offset = Int(rawOffset)
        let fileId = readFileId(&r)
        guard let open = state.open(fileId), !open.isDir else {
            return (.fileClosed, errorBody(), DispatchExtra())
        }
        guard open.hasAccess(SMBAccess.writeData | SMBAccess.appendData) else { return (.accessDenied, errorBody(), DispatchExtra()) }
        if !open.hasAccess(SMBAccess.writeData), offset != open.size { return (.accessDenied, errorBody(), DispatchExtra()) }
        // The write payload lives at DataOffset (from the SMB2 header start).
        let rel = dataOffset - SMB2Header.size
        guard rel >= 0, rel + length <= body.count else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        let payload = body.subdata(in: rel..<(rel + length))

        let table = self.table
        let node = open.node
        let streamName = open.streamName
        let result: (NTStatus, Data) = SMBServer.bridgeSync {
            do {
                let engine = await table.engineRef()
                try await self.checkRangeAccess(open, offset: UInt64(offset), length: UInt64(length), write: true)
                guard !SMBAttrs.isReadOnly(try await table.meta(node)) else { return (.accessDenied, errorBody()) }
                // AFP_AfpInfo is a tiny fixed-format FinderInfo envelope. Other
                // streams use bounded range I/O, including large resource forks.
                if let streamName {
                    if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil {
                        SMBLog.line("stream write name=\(streamName) offset=\(offset) length=\(payload.count)")
                    }
                    if streamName == "AFP_AfpInfo" {
                        var blob: Data
                        do { blob = try await engine.readStream(node, name: streamName) }
                        catch let error as EngineError where error.kind == .notFound { blob = Data() }
                        let end = offset + payload.count
                        guard end <= 64 << 10 else { return (.invalidParameter, errorBody()) }
                        if blob.count < end { blob.append(Data(repeating: 0, count: end - blob.count)) }
                        blob.replaceSubrange(offset..<end, with: payload)
                        if SMBStreams.isEmptyAfpInfo(streamName, blob) { try await engine.deleteStream(node, name: streamName) }
                        else { try await engine.writeStream(node, name: streamName, data: blob) }
                        open.size = blob.count
                    } else {
                        open.size = try await engine.writeStreamRange(node, name: streamName, offset: offset, data: payload)
                    }
                    return (.success, self.writeResponse(count: length))
                }
                let meta = try await table.meta(node)
                let newSize = try await engine.writeRange(
                    node, offset: offset, data: payload, baseVersion: meta.metadataVersion)
                await table.projectWrite(node, newSize: newSize)
                open.size = newSize
                return (.success, self.writeResponse(count: length))
            } catch let e as EngineError {
                return (e.kind == .locked ? .fileLockConflict : ntStatus(for: e), errorBody())
            } catch {
                return (.unsuccessful, errorBody())
            }
        }
        return (result.0, result.1, DispatchExtra())
    }

    /// WRITE response ([MS-SMB2] §2.2.22): StructureSize=17, Reserved(2),
    /// Count(4), Remaining(4), WriteChannelInfoOffset(2), WriteChannelInfoLength(2).
    func writeResponse(count: Int) -> Data {
        var w = ByteWriter()
        w.u16(17); w.u16(0); w.u32(UInt32(count)); w.u32(0); w.u16(0); w.u16(0)
        return w.data
    }

    // MARK: FLUSH ([MS-SMB2] §2.2.17 / §2.2.18)

    func handleFlush(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        // The engine's write-back journal is fsync-durable on ack, so a flush is
        // already satisfied. StructureSize=4, Reserved(2).
        var w = ByteWriter(); w.u16(4); w.u16(0)
        return (.success, w.data, DispatchExtra())
    }

    // MARK: SET_INFO ([MS-SMB2] §2.2.39 / §2.2.40)

    func handleSetInfo(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        var r = ByteReader(body)
        guard (try? r.u16()) == 33 else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        let infoType = (try? r.u8()) ?? 0
        let infoClass = (try? r.u8()) ?? 0
        let bufLen = Int((try? r.u32()) ?? 0)
        let bufOffset = Int((try? r.u16()) ?? 0)
        _ = try? r.u16()                            // Reserved
        _ = try? r.u32()                            // AdditionalInformation
        let fileId = readFileId(&r)
        guard let open = state.open(fileId) else { return (.fileClosed, errorBody(), DispatchExtra()) }
        let rel = bufOffset - SMB2Header.size
        guard rel >= 0, rel + bufLen <= body.count else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        let buf = body.subdata(in: rel..<(rel + bufLen))

        guard InfoType(rawValue: infoType) == .file else {
            return (.notSupported, errorBody(), DispatchExtra())
        }
        let table = self.table
        let result: NTStatus = SMBServer.bridgeSync {
            do {
                switch infoClass {
                case 4:                                          // FileBasicInformation
                    guard open.hasAccess(SMBAccess.writeAttributes) else { return .accessDenied }
                    guard !open.isDir || open.streamName == nil else { return .invalidParameter }
                    var info = try SMBAttrs.parseBasicInfo(buf, isDir: open.isDir)
                    // Apple's smbfs emits all-zero BASIC_INFO when clearing its
                    // last DOS flag (nouchg/nohidden on an archived file). Scope
                    // this observed interoperability rule to AAPL, a related
                    // attribute-only CREATE/SET_INFO compound and no timestamps.
                    // Ordinary SMB zero fields retain their no-change meaning.
                    if state.aaplReadDirAttr, fileId.isRelated, hdr.flags.contains(.relatedOps),
                       hdr.nextCommand != 0, (open.grantedAccess & ~UInt32(0x80)) == (SMBAccess.writeAttributes | 0x0010_0000),
                       buf.allSatisfy({ $0 == 0 }) {
                        info.fileAttributes = 0
                    }
                    let engine = await table.engineRef()
                    guard !engine.isReadOnly else { return .accessDenied }
                    if info.createdAt == nil, info.modifiedAt == nil, info.accessedAt == nil,
                       info.changedAt == nil, info.fileAttributes == nil {
                        // A zero BASIC_INFO packet means "leave unchanged".
                        // Complete it locally after handle/mount validation; the
                        // AAPL clear-flags quirk above remains an actual mutation.
                        return .success
                    }
                    let updated = try await engine.setBasicInfo(open.node, info: info)
                    await table.storeMeta(updated)
                    if let parent = updated.parent { await table.invalidateListing(parent); state.notify?.postLocalChange(parent) }
                    return .success
                case 20:                                         // FileEndOfFileInformation
                    guard open.hasAccess(SMBAccess.writeData) else { return .accessDenied }
                    guard !SMBAttrs.isReadOnly(try await table.meta(open.node)) else { return .accessDenied }
                    guard buf.count == 8 else { return .invalidParameter }
                    var br = ByteReader(buf)
                    guard let rawSize = try? br.u64(), rawSize <= UInt64(Int.max) else { return .invalidParameter }
                    let newSize = Int(rawSize)
                    try await self.checkRangeAccess(open, offset: UInt64(min(newSize, open.size)), length: UInt64(abs(newSize - open.size)), write: true)
                    if let name = open.streamName {
                        try await table.engineRef().truncateStream(open.node, name: name, size: newSize)
                        open.size = newSize
                        return .success
                    }
                    let meta = try await table.meta(open.node)
                    try await table.engineRef().truncate(open.node, newSize: newSize,
                                                         baseVersion: meta.metadataVersion)
                    await table.projectWrite(open.node, newSize: newSize)
                    open.size = newSize
                    state.syncSiblingSizes(from: open)   // truncate may LOWER other handles' EOF
                    return .success
                case 19:                                         // FileAllocationInformation
                    guard open.hasAccess(SMBAccess.writeData) else { return .accessDenied }
                    guard !SMBAttrs.isReadOnly(try await table.meta(open.node)) else { return .accessDenied }
                    var br = ByteReader(buf)
                    guard buf.count == 8, let allocation = try? br.u64(), allocation <= UInt64(Int.max) else { return .invalidParameter }
                    // Object storage has no physical preallocation guarantee.
                    // Shrinking allocation below EOF must still truncate data.
                    guard Int(allocation) < open.size else { return .notSupported }
                    try await self.checkRangeAccess(open, offset: allocation, length: UInt64(open.size) - allocation, write: true)
                    if let name = open.streamName {
                        try await table.engineRef().truncateStream(open.node, name: name, size: Int(allocation))
                    } else {
                        let meta = try await table.meta(open.node)
                        try await table.engineRef().truncate(open.node, newSize: Int(allocation), baseVersion: meta.metadataVersion)
                        await table.projectWrite(open.node, newSize: Int(allocation))
                    }
                    open.size = Int(allocation); state.syncSiblingSizes(from: open)
                    return .success
                case 13:                                         // FileDispositionInformation
                    guard open.hasAccess(SMBAccess.delete) else { return .accessDenied }
                    guard buf.count == 1 else { return .invalidParameter }
                    let deleting = buf[buf.startIndex] != 0
                    if deleting, SMBAttrs.isReadOnly(try await table.meta(open.node)) { return .cannotDelete }
                    if deleting, !(await table.allowsDelete(open.node, excluding: open.leaseHandle)) { return .sharingViolation }
                    if deleting, open.isDir {
                        let children = try await table.children(of: open.node)
                        if !children.isEmpty { return .directoryNotEmpty }
                    }
                    if deleting { try await table.engineRef().authorizeWrite(open.node, refresh: true) }
                    open.deleteOnClose = deleting
                    return .success
                case 10:                                         // FileRenameInformation
                    guard open.hasAccess(SMBAccess.delete) else { return .accessDenied }
                    return try await self.doRename(open: open, buf: buf, table: table, notifyLocal: state.notify)
                default:
                    return .notSupported
                }
            } catch let e as EngineError {
                return e.kind == .locked ? .fileLockConflict : ntStatus(for: e)
            } catch {
                return .unsuccessful
            }
        }
        // Failed SET_INFO requests use SMB2 ERROR (StructureSize9), not the
        // two-byte success structure. Clients parse these layouts differently.
        return (result, result == .success ? setInfoResponse() : errorBody(), DispatchExtra())
    }

    private func setInfoResponse() -> Data { var w = ByteWriter(); w.u16(2); return w.data }

    /// FileRenameInformation ([MS-FSCC] §2.4.34): ReplaceIfExists(1), Reserved(7),
    /// RootDirectory(8), FileNameLength(4), FileName (UTF-16, share-relative).
    private func doRename(open: SMBOpen, buf: Data, table: NodeTable, notifyLocal: NotifySession?) async throws -> NTStatus {
        var r = ByteReader(buf)
        guard let replaceByte = try? r.u8(), replaceByte <= 1,
              (try? r.take(7)) != nil, let rootDirectory = try? r.u64(),
              let rawNameLength = try? r.u32() else { return .invalidParameter }
        guard rootDirectory == 0 else { return .notSupported }
        let replace = replaceByte != 0, nameLen = Int(rawNameLength)
        guard nameLen > 0, nameLen.isMultiple(of: 2),
              let nameBytes = try? r.take(nameLen) else { return .invalidParameter }
        let target = SMBString.decodeUTF16le(nameBytes)
        let comps = SMBPath.components(target)
        guard !comps.isEmpty else { return .invalidParameter }
        let newName = comps[comps.count - 1]
        let parentComps = Array(comps.dropLast())

        // Resolve the destination parent (nil newParent = same dir, pure rename).
        let curMeta = try await table.meta(open.node)
        guard let destParent = try await table.resolve(components: parentComps), destParent.isDir else { return .objectPathNotFound }
        let clash = try await table.resolve(components: comps)
        let replacement = clash?.id == open.node ? nil : clash
        guard await table.allowsDelete(open.node, excluding: open.leaseHandle) else { return .sharingViolation }
        if let replacement {
            guard await table.allowsDelete(replacement.id, excluding: open.leaseHandle) else { return .sharingViolation }
            if !replace { return .objectNameCollision }
            if replacement.isDir != curMeta.isDir { return .accessDenied }
            if !replacement.isDir && ((replacement.fileAttributes ?? 0) & 1) != 0 { return .accessDenied }
            if replacement.isDir {
                let children = try await table.children(of: replacement.id)
                if !children.isEmpty { return .directoryNotEmpty }
            }
        }
        // Never DELETE then PATCH: a failure between those requests loses the
        // prior destination. The engine drains both writers and replaces remotely
        // in one CAS transaction; cache entries change only after success.
        let renameToken = await table.beginLocalRename(open.node)
        let moved: ItemMetadata
        do {
            moved = try await table.engineRef().rename(open.node,
                newParent: destParent.id == curMeta.parent ? nil : destParent.id, newName: newName,
                replacing: replacement, openHandle: open.leaseHandle)
        } catch {
            await table.cancelLocalRename(open.node, token: renameToken)
            throw error
        }
        let invalidatedParents = [curMeta.parent, moved.parent, replacement?.parent].compactMap { $0 }
        await table.commitLocalRename(moved, token: renameToken,
                                      forgetting: replacement.map { [$0.id] } ?? [],
                                      invalidatingDirectories: invalidatedParents)
        for p in Set(invalidatedParents) { notifyLocal?.postLocalChange(p) }
        return .success
    }

    // MARK: QUERY_DIRECTORY ([MS-SMB2] §2.2.33 / §2.2.34)

    func handleQueryDirectory(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        var r = ByteReader(body)
        guard (try? r.u16()) == 33 else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        let infoClass = (try? r.u8()) ?? 0
        let flags = (try? r.u8()) ?? 0
        _ = try? r.u32()                            // FileIndex
        let fileId = readFileId(&r)
        let nameOffset = Int((try? r.u16()) ?? 0)
        let nameLen = Int((try? r.u16()) ?? 0)
        let outMax = Int((try? r.u32()) ?? 0)
        let pattern: String = {
            guard nameLen > 0 else { return "*" }
            let rel = nameOffset - SMB2Header.size
            guard rel >= 0, rel + nameLen <= body.count else { return "*" }
            return SMBString.decodeUTF16le(body.subdata(in: rel..<(rel + nameLen)))
        }()

        guard let open = state.open(fileId), open.isDir else {
            if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil {
                SMBLog.line("querydir REJECT badhandle fid=\(fileId.persistent) isDir=\(state.open(fileId)?.isDir ?? false)")
            }
            return (.invalidParameter, errorBody(), DispatchExtra())
        }
        if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil {
            SMBLog.line("querydir node=\(open.node.rawValue) class=0x\(String(infoClass, radix: 16)) flags=0x\(String(flags, radix: 16)) pattern='\(pattern)' outMax=\(outMax)")
        }
        // The mac client uses FileIdBothDirectoryInformation (0x25) exclusively.
        guard infoClass == FileInfoClass.idBothDirectoryInformation.rawValue else {
            return (.notImplemented, errorBody(), DispatchExtra())
        }
        let restart = (flags & 0x01) != 0           // SMB2_RESTART_SCANS

        let singleEntry = (flags & 0x02) != 0        // SMB2_RETURN_SINGLE_ENTRY
        let table = self.table
        let node = open.node
        let result: (NTStatus, Data) = SMBServer.bridgeSync {
            do {
                if open.dirEntries == nil || restart {
                    let includesDot = SMBWildcard.match(name: ".", pattern: pattern)
                    let includesDotDot = SMBWildcard.match(name: "..", pattern: pattern)
                    let kids: [(metadata: ItemMetadata, fileID: UInt64)]
                    let directoryFileID: UInt64
                    let parentFileID: UInt64?
                    var directoryMeta: ItemMetadata?
                    if let snapshot = open.transientDirectorySnapshot {
                        // This view was atomically validated and frozen at CREATE.
                        // Do not re-enumerate after the gateway's transient handle
                        // has closed, even if a local mutation invalidated cache.
                        kids = snapshot.items.map { (metadata: $0.metadata, fileID: $0.fileID) }
                        directoryMeta = snapshot.directory
                        directoryFileID = snapshot.directoryFileID
                        parentFileID = snapshot.parentFileID
                    } else {
                        kids = try await table.presentationChildren(of: node)
                        if includesDot || includesDotDot {
                            directoryMeta = try await table.meta(node)
                        }
                        if open.presentationFileID != 0 {
                            directoryFileID = open.presentationFileID
                        } else if let directoryMeta {
                            directoryFileID = await table.presentationFileId(for: directoryMeta)
                        } else {
                            directoryFileID = 0
                        }
                        parentFileID = nil
                    }
                    // Synthesize "." and ".." at the head, then the children,
                    // then FILTER by the client's search pattern. The mac client
                    // uses single-name patterns (e.g. "clip.bin", "._") to stat
                    // individual files, so returning unmatched entries breaks it.
                    var entries: [DirEntry] = []
                    if includesDot {
                        entries.append(DirEntry(name: ".", isDir: true, size: 0,
                                                 version: "dot", fileId: directoryFileID))
                    }
                    if includesDotDot {
                        let dotDotFileID: UInt64
                        if let parentFileID { dotDotFileID = parentFileID }
                        else if let directoryMeta {
                            dotDotFileID = try await table.presentationParentFileID(for: directoryMeta)
                        } else {
                            return (.unsuccessful, errorBody())
                        }
                        entries.append(DirEntry(name: "..", isDir: true, size: 0,
                                                 version: "dotdot", fileId: dotDotFileID))
                    }
                    for entry in kids {
                        let k = entry.metadata
                        entries.append(DirEntry(name: k.name, isDir: k.isDir, size: k.size,
                                                version: k.contentVersion, fileId: entry.fileID,
                                                createdAt: k.createdAt, modifiedAt: k.modifiedAt, accessedAt: k.accessedAt, changedAt: k.changedAt, fileAttributes: k.fileAttributes,
                                                rsrcForkSize: k.rsrcForkSize, finderInfo: k.finderInfo))
                    }
                    open.cachedEntries = entries.filter { SMBWildcard.match(name: $0.name, pattern: pattern) }
                    open.dirEntries = []            // marker: enumerated
                    open.dirIndex = 0
                }
                let all = open.cachedEntries
                if open.dirIndex >= all.count {
                    return (.noMoreFiles, errorBody())
                }
                let (buf, consumed) = self.packIdBothDirInfo(all, from: open.dirIndex, maxBytes: outMax,
                                                             maxEntries: singleEntry ? 1 : Int.max,
                                                             aapl: state.aaplReadDirAttr)
                if consumed == 0 {
                    return (.bufferTooSmall, errorBody())
                }
                open.dirIndex += consumed
                if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil {
                    let hex = buf.prefix(112).map { String(format: "%02x", $0) }.joined()
                    SMBLog.line("querydir consumed=\(consumed) firstEntryHex=\(hex)")
                }
                return (.success, self.queryDirResponse(buf))
            } catch {
                return (.unsuccessful, errorBody())
            }
        }
        return (result.0, result.1, DispatchExtra())
    }

    private func queryDirResponse(_ buffer: Data) -> Data {
        var w = ByteWriter()
        w.u16(9)                                    // StructureSize
        w.u16(UInt16(SMB2Header.size + 8))          // OutputBufferOffset = 72
        w.u32(UInt32(buffer.count))                 // OutputBufferLength
        w.bytes(buffer)
        return w.data
    }

    /// Pack FileIdBothDirectoryInformation entries starting at `from`, stopping
    /// before `maxBytes`. Returns (buffer, entriesConsumed). Entries are 8-aligned;
    /// the last has NextEntryOffset = 0.
    private func packIdBothDirInfo(_ entries: [DirEntry], from: Int, maxBytes: Int,
                                   maxEntries: Int = Int.max, aapl: Bool = false)
        -> (Data, Int) {
        var out = Data()
        var count = 0
        var i = from
        while i < entries.count, count < maxEntries {
            let e = entries[i]
            let nameBytes = SMBString.utf16le(e.name)
            let fixed = 104                          // fixed part of the struct
            let entryLen = fixed + nameBytes.count
            let padded = (entryLen + 7) & ~7
            if out.count + entryLen > maxBytes, count > 0 { break }   // at least one entry
            if out.count + entryLen > maxBytes, count == 0 { break }  // won't fit at all

            let isLast = (i == entries.count - 1) || (out.count + padded + 1 > maxBytes)
            let ts = SMBAttrs.times(created: e.createdAt, modified: e.modifiedAt, accessed: e.accessedAt, changed: e.changedAt, contentVersion: e.version)
            var w = ByteWriter()
            w.u32(isLast ? 0 : UInt32(padded))       // NextEntryOffset
            w.u32(0)                                 // FileIndex
            w.u64(ts.creation); w.u64(ts.access); w.u64(ts.write); w.u64(ts.change)
            w.u64(UInt64(e.size))                    // EndOfFile
            w.u64(SMBAttrs.allocationSize(e.size))   // AllocationSize
            w.u32(SMBAttrs.fileAttributes(isDir: e.isDir, stored: e.fileAttributes))
            w.u32(UInt32(nameBytes.count))           // FileNameLength
            // AAPL SUPPORTS_READ_DIR_ATTR overlay (Apple smb_2.h): EaSize→max
            // access, ShortName[24]→u64 rsrc-fork size + 16-byte FinderInfo,
            // Reserved2→POSIX mode. Zeroed (standard meaning) when AAPL is off.
            if aapl {
                w.u32(0x001F_01FF)                   // EaSize = max access
            } else {
                w.u32(0)                             // EaSize
            }
            w.u8(0)                                  // ShortNameLength (0 = no 8.3 name)
            w.u8(0)                                  // Reserved
            if aapl {
                w.u64(UInt64(e.rsrcForkSize ?? 0))   // resource-fork logical size (8B)
                var fi = e.finderInfo ?? Data()      // FinderInfo — first 16 bytes (16B)
                fi = fi.prefix(16)
                w.bytes(fi)
                if fi.count < 16 { w.zeros(16 - fi.count) }
            } else {
                w.zeros(24)                          // ShortName[24]
            }
            if aapl {
                w.u16(e.isDir ? 0o040700 : 0o100600) // Reserved2 = POSIX mode (S_IFDIR|0700 / S_IFREG|0600)
            } else {
                w.u16(0)                             // Reserved2
            }
            w.u64(e.fileId)                          // FileId
            w.bytes(nameBytes)                       // FileName
            var chunk = w.data
            if !isLast, padded > chunk.count { chunk.append(Data(count: padded - chunk.count)) }
            out.append(chunk)
            count += 1
            i += 1
            if isLast { break }
        }
        return (out, count)
    }

    // MARK: helpers

    func readFileId(_ r: inout ByteReader) -> SMBFileId {
        let p = (try? r.u64()) ?? 0
        let v = (try? r.u64()) ?? 0
        return SMBFileId(persistent: p, volatile: v)
    }
}

// MARK: - Engine error → NTSTATUS

func ntStatus(for e: EngineError) -> NTStatus {
    if e.data?["diskFull"] == .bool(true) { return .diskFull }
    if e.data?["error"] == .string("directory_not_empty") { return .directoryNotEmpty }
    if e.data?["error"] == .string("invalid_parent") { return .objectPathNotFound }
    switch e.kind {
    case .unimplemented: return .notSupported
    case .notFound:         return .objectNameNotFound
    case .conflict:         return .objectNameCollision
    case .locked:           return .sharingViolation
    case .permissionDenied: return .accessDenied
    case .invalidParams:    return .invalidParameter
    default:                return .unsuccessful
    }
}

// MARK: - Parsed CREATE request

struct ParsedContext { var name: String; var data: Data }

struct ParsedCreate {
    var disposition: UInt32
    var options: UInt32
    var desiredAccess: UInt32
    var shareAccess: UInt32
    var name: String
    var contexts: [ParsedContext]
}

/// Directory-entry view used by QUERY_DIRECTORY packing.
public struct DirEntry {
    var name: String; var isDir: Bool; var size: Int; var version: String; var fileId: UInt64
    var createdAt: Date? = nil; var modifiedAt: Date? = nil
    var accessedAt: Date? = nil; var changedAt: Date? = nil; var fileAttributes: UInt32? = nil
    // AAPL readdir-attr enrichment (nil when the item carries no such streams).
    var rsrcForkSize: Int? = nil; var finderInfo: Data? = nil
}

/// SMB directory search-pattern matching. The mac client sends patterns like "*",
/// "clip.bin", "._" (and DOS wildcards `?`). Matching is case-insensitive —
/// smbfs folds case for lookups even against a case-sensitive volume. The DOS
/// meta-characters `<` `>` `"` map to `*` `?` `.` respectively ([MS-FSA]).
public enum SMBWildcard {
    public static func match(name: String, pattern: String) -> Bool {
        if pattern.isEmpty || pattern == "*" { return true }
        let p = Array(pattern.replacingOccurrences(of: "<", with: "*")
                             .replacingOccurrences(of: ">", with: "?")
                             .replacingOccurrences(of: "\"", with: ".")
                             .lowercased())
        let n = Array(name.lowercased())
        return glob(n, 0, p, 0)
    }

    private static func glob(_ n: [Character], _ i0: Int, _ p: [Character], _ j0: Int) -> Bool {
        var i = i0, j = j0
        while j < p.count {
            let pc = p[j]
            if pc == "*" {
                // Collapse consecutive stars, then try to match the remainder.
                while j < p.count, p[j] == "*" { j += 1 }
                if j == p.count { return true }
                var k = i
                while k <= n.count {
                    if glob(n, k, p, j) { return true }
                    k += 1
                }
                return false
            } else if pc == "?" {
                if i >= n.count { return false }
                i += 1; j += 1
            } else {
                if i >= n.count || n[i] != pc { return false }
                i += 1; j += 1
            }
        }
        return i == n.count
    }
}

extension SMBServer {
    func parseCreate(_ body: Data) -> ParsedCreate? {
        var r = ByteReader(body)
        guard (try? r.u16()) == 57 else { return nil }   // StructureSize
        _ = try? r.u8()                                  // SecurityFlags
        _ = try? r.u8()                                  // RequestedOplockLevel
        _ = try? r.u32()                                 // ImpersonationLevel
        _ = try? r.u64()                                 // SmbCreateFlags
        _ = try? r.u64()                                 // Reserved
        let desired = (try? r.u32()) ?? 0
        _ = try? r.u32()                                 // FileAttributes
        let shareAccess = (try? r.u32()) ?? 0
        let disposition = (try? r.u32()) ?? 1
        let options = (try? r.u32()) ?? 0
        guard let nameOffset = try? r.u16(),
              let nameLength = try? r.u16(),
              let ctxOffset = try? r.u32(),
              let ctxLength = try? r.u32() else { return nil }

        var name = ""
        if nameLength > 0 {
            let rel = Int(nameOffset) - SMB2Header.size
            if rel >= 0, rel + Int(nameLength) <= body.count {
                name = SMBString.decodeUTF16le(body.subdata(in: rel..<(rel + Int(nameLength))))
            }
        }
        var contexts: [ParsedContext] = []
        if ctxLength > 0 {
            let rel = Int(ctxOffset) - SMB2Header.size
            if rel >= 0, rel + Int(ctxLength) <= body.count {
                contexts = parseCreateContexts(body.subdata(in: rel..<(rel + Int(ctxLength))))
            }
        }
        return ParsedCreate(disposition: disposition, options: options,
                            desiredAccess: desired, shareAccess: shareAccess,
                            name: name, contexts: contexts)
    }

    private func parseCreateContexts(_ data: Data) -> [ParsedContext] {
        var out: [ParsedContext] = []
        var cursor = 0
        while cursor + 16 <= data.count {
            let slice = data.subdata(in: cursor..<data.count)
            var r = ByteReader(slice)
            let next = Int((try? r.u32()) ?? 0)
            let nameOffset = Int((try? r.u16()) ?? 0)
            let nameLen = Int((try? r.u16()) ?? 0)
            _ = try? r.u16()                             // Reserved
            let dataOffset = Int((try? r.u16()) ?? 0)
            let dataLen = Int((try? r.u32()) ?? 0)
            var name = ""
            if nameOffset + nameLen <= slice.count {
                name = String(decoding: slice.subdata(in: nameOffset..<(nameOffset + nameLen)), as: UTF8.self)
            }
            var cdata = Data()
            if dataLen > 0, dataOffset + dataLen <= slice.count {
                cdata = slice.subdata(in: dataOffset..<(dataOffset + dataLen))
            }
            out.append(ParsedContext(name: name, data: cdata))
            if next == 0 { break }
            cursor += next
        }
        return out
    }
}

// MARK: - Actor-hop helpers (state mutation lives on the connection thread, but the
// NodeTable is an actor; these keep the bridge closures readable).

enum MainActorFree {
    static func newId(_ state: SMBConnectionState) async -> SMBFileId { state.newFileId() }
    static func register(_ state: SMBConnectionState, _ open: SMBOpen) async { state.register(open) }
}
