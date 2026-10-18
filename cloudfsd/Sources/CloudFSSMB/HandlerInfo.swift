// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — QUERY_INFO ([MS-SMB2] §2.2.37/§2.2.38): FILE and FILESYSTEM info
// classes. FILE classes report per-item attributes (times synthesized in P1b);
// FILESYSTEM classes report volume shape, crucially advertising case sensitivity
// (and, from P4, FILE_NAMED_STREAMS). SECURITY/QUOTA → NOT_SUPPORTED.

import Foundation
import CloudFSCore

extension SMBServer {

    func handleQueryInfo(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        var r = ByteReader(body)
        guard (try? r.u16()) == 41 else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        let infoType = (try? r.u8()) ?? 0
        let infoClass = (try? r.u8()) ?? 0
        let outMax = Int((try? r.u32()) ?? 0)
        _ = try? r.u16()                             // InputBufferOffset
        _ = try? r.u16()                             // Reserved
        _ = try? r.u32()                             // InputBufferLength
        _ = try? r.u32()                             // AdditionalInformation
        _ = try? r.u32()                             // Flags
        let fileId = readFileId(&r)
        if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil {
            SMBLog.line("queryinfo type=\(infoType) class=\(infoClass) max=\(outMax) related=\(fileId.isRelated)")
        }

        switch InfoType(rawValue: infoType) {
        case .file:
            guard let open = state.open(fileId) else { return (.fileClosed, errorBody(), DispatchExtra()) }
            let table = self.table
            let result: (NTStatus, Data) = SMBServer.bridgeSync {
                // Refresh meta so size/version are current (TTL-cached).
                var meta = (try? await table.meta(open.node)) ?? ItemMetadata(
                    id: open.node, parent: nil, name: "", isDir: open.isDir,
                    size: open.size, contentVersion: open.contentVersion, metadataVersion: "0")
                // FileStreamInformation (class 22): enumerate the item's named
                // streams (xattrs) — this is how macOS lists xattrs over SMB.
                if infoClass == 22 {
                    let streams = (try? await table.engineRef().listStreams(open.node)) ?? []
                    let buf = self.packStreamInfo(streams, fileSize: meta.size)
                    if buf.count > outMax { return (.infoLengthMismatch, errorBody()) }
                    return (.success, self.queryInfoResponse(buf))
                }
                // Standard/all information for an alternate-data-stream handle
                // must describe that stream, not the carrier's main data fork.
                // A wrong EOF can make smbfs discard dirty cached stream pages.
                if let streamName = open.streamName {
                    let size: Int
                    do { size = try await table.engineRef().listStreams(open.node).first { $0.name == streamName }?.size ?? 0 }
                    catch let error as EngineError { return (ntStatus(for: error), errorBody()) }
                    catch { return (.unsuccessful, errorBody()) }
                    open.size = size
                    meta = ItemMetadata(id: meta.id, parent: meta.parent, name: streamName,
                        isDir: false, size: open.size, contentVersion: meta.contentVersion,
                        metadataVersion: meta.metadataVersion, createdAt: meta.createdAt, modifiedAt: meta.modifiedAt, accessedAt: meta.accessedAt, changedAt: meta.changedAt, fileAttributes: meta.fileAttributes)
                }
                // Freeze the index identity at CREATE so a remote move cannot
                // change the identity observed through an already-held handle.
                let indexNumber = open.presentationFileID
                if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil,
                   infoClass == FileInfoClass.internalInformation.rawValue || infoClass == FileInfoClass.allInformation.rawValue {
                    SMBLog.line("queryinfo node=\(open.node.rawValue) index=\(indexNumber)")
                }
                guard let buf = self.fileInfo(class: infoClass, meta: meta, indexNumber: indexNumber) else {
                    return (.notImplemented, errorBody())
                }
                if buf.count > outMax { return (.infoLengthMismatch, errorBody()) }
                return (.success, self.queryInfoResponse(buf))
            }
            return (result.0, result.1, DispatchExtra())

        case .fileSystem:
            guard let buf = fsInfo(class: infoClass) else { return (.notImplemented, errorBody(), DispatchExtra()) }
            if buf.count > outMax { return (.infoLengthMismatch, errorBody(), DispatchExtra()) }
            return (.success, queryInfoResponse(buf), DispatchExtra())

        default:
            return (.notSupported, errorBody(), DispatchExtra())
        }
    }

    /// FileStreamInformation ([MS-FSCC] §2.4.40): the main `::$DATA` data stream
    /// (with the file size) followed by each named stream as `:<name>:$DATA`.
    /// macOS enumerates xattrs from this.
    private func packStreamInfo(_ streams: [StreamInfo], fileSize: Int) -> Data {
        var entries: [(name: String, size: Int)] = [("", fileSize)]   // "" → the main data stream
        entries.append(contentsOf: streams.map { ($0.name, $0.size) })
        var out = Data()
        for (i, e) in entries.enumerated() {
            let wireName = ":\(e.name):$DATA"
            let nameBytes = SMBString.utf16le(wireName)
            var w = ByteWriter()
            let fixed = 24
            let entryLen = fixed + nameBytes.count
            let padded = (entryLen + 7) & ~7
            let isLast = i == entries.count - 1
            w.u32(isLast ? 0 : UInt32(padded))       // NextEntryOffset
            w.u32(UInt32(nameBytes.count))           // StreamNameLength
            w.u64(UInt64(e.size))                    // StreamSize
            w.u64(SMBAttrs.allocationSize(e.size))   // StreamAllocationSize
            w.bytes(nameBytes)
            var chunk = w.data
            if !isLast, padded > chunk.count { chunk.append(Data(count: padded - chunk.count)) }
            out.append(chunk)
        }
        return out
    }

    private func queryInfoResponse(_ buffer: Data) -> Data {
        var w = ByteWriter()
        w.u16(9)                                    // StructureSize
        w.u16(UInt16(SMB2Header.size + 8))          // OutputBufferOffset = 72
        w.u32(UInt32(buffer.count))                 // OutputBufferLength
        w.bytes(buffer)
        return w.data
    }

    // MARK: FILE info classes

    private func fileInfo(class infoClass: UInt8, meta: ItemMetadata, indexNumber: UInt64) -> Data? {
        let ts = SMBAttrs.times(created: meta.createdAt, modified: meta.modifiedAt, accessed: meta.accessedAt, changed: meta.changedAt,
                                contentVersion: meta.contentVersion)
        let attrs = SMBAttrs.fileAttributes(isDir: meta.isDir, stored: meta.fileAttributes)
        let alloc = SMBAttrs.allocationSize(meta.size)

        func basic() -> Data {
            var w = ByteWriter()
            w.u64(ts.creation); w.u64(ts.access); w.u64(ts.write); w.u64(ts.change)
            w.u32(attrs); w.u32(0)                   // FileAttributes + Reserved
            return w.data
        }
        func standard() -> Data {
            var w = ByteWriter()
            w.u64(alloc)                             // AllocationSize
            w.u64(UInt64(meta.size))                 // EndOfFile
            w.u32(meta.isDir ? 1 : 1)                // NumberOfLinks
            w.u8(0)                                  // DeletePending
            w.u8(meta.isDir ? 1 : 0)                 // Directory
            w.u16(0)                                 // Reserved
            return w.data
        }

        switch FileInfoClass(rawValue: infoClass) {
        case .basicInformation:
            return basic()
        case .standardInformation:
            return standard()
        case .internalInformation:
            var w = ByteWriter(); w.u64(indexNumber); return w.data   // IndexNumber
        case .eaInformation:
            var w = ByteWriter(); w.u32(0); return w.data                   // EaSize
        case .attributeTagInformation:
            var w = ByteWriter(); w.u32(attrs); w.u32(0); return w.data     // Attr + ReparseTag
        case .networkOpenInformation:
            var w = ByteWriter()
            w.u64(ts.creation); w.u64(ts.access); w.u64(ts.write); w.u64(ts.change)
            w.u64(alloc); w.u64(UInt64(meta.size)); w.u32(attrs); w.u32(0)
            return w.data
        case .allInformation:
            // FileAllInformation = Basic + Standard + Internal + EA + Access +
            // Position + Mode + Alignment + Name ([MS-FSCC] §2.4.2).
            var w = ByteWriter()
            w.bytes(basic())                         // 40
            w.bytes(standard())                      // 24
            w.u64(indexNumber)                       // InternalInformation.IndexNumber
            w.u32(0)                                 // EaInformation.EaSize
            w.u32(0x001F_01FF)                       // AccessInformation.AccessFlags
            w.u64(0)                                 // PositionInformation.CurrentByteOffset
            w.u32(0)                                 // ModeInformation.Mode
            w.u32(0)                                 // AlignmentInformation.AlignmentRequirement
            let nameBytes = SMBString.utf16le(meta.name)
            w.u32(UInt32(nameBytes.count))           // NameInformation.FileNameLength
            w.bytes(nameBytes)
            return w.data
        default:
            return nil
        }
    }

    // MARK: FILESYSTEM info classes

    private func fsInfo(class infoClass: UInt8) -> Data? {
        switch FsInfoClass(rawValue: infoClass) {
        case .attributeInformation:
            // FileFsAttributeInformation ([MS-FSCC] §2.5.1). Case-sensitive volume.
            // FILE_NAMED_STREAMS is added in P4.
            let label = SMBString.utf16le("CloudFS")
            var w = ByteWriter()
            let table = self.table
            let readOnly = SMBServer.bridgeSync { await table.engineRef().isReadOnly }
            w.u32(FSAttributeFlags.caseSensitiveSearch | FSAttributeFlags.casePreservedNames
                  | FSAttributeFlags.unicodeOnDisk | FSAttributeFlags.namedStreams | (readOnly ? 0x0008_0000 : 0))
            w.u32(255)                               // MaximumComponentNameLength
            w.u32(UInt32(label.count))               // FileSystemNameLength
            w.bytes(label)
            return w.data
        case .sizeInformation:
            // FileFsSizeInformation ([MS-FSCC] §2.5.5). Report a large volume; P6
            // wires real numbers from the engine.
            var w = ByteWriter()
            w.u64(1 << 40)                           // TotalAllocationUnits (1 Ti units)
            w.u64(1 << 39)                           // AvailableAllocationUnits
            w.u32(1)                                 // SectorsPerAllocationUnit
            w.u32(UInt32(kDefaultBlockSize))         // BytesPerSector = 1 MiB
            return w.data
        case .fullSizeInformation:
            var w = ByteWriter()
            w.u64(1 << 40); w.u64(1 << 39); w.u64(1 << 39)
            w.u32(1); w.u32(UInt32(kDefaultBlockSize))
            return w.data
        case .volumeInformation:
            // FileFsVolumeInformation ([MS-FSCC] §2.5.9).
            let label = SMBString.utf16le("CloudFS")
            var w = ByteWriter()
            w.u64(nowFiletime())                     // VolumeCreationTime
            w.u32(0x434C_4653)                       // VolumeSerialNumber ("CLFS")
            w.u32(UInt32(label.count))               // VolumeLabelLength
            w.u8(0); w.u8(0)                         // SupportsObjects + Reserved
            w.bytes(label)
            return w.data
        case .deviceInformation:
            var w = ByteWriter()
            w.u32(0x0000_0007)                       // DeviceType = FILE_DEVICE_DISK
            w.u32(0x0000_0010)                       // Characteristics = REMOTE
            return w.data
        default:
            return nil
        }
    }
}
