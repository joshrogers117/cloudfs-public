// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import Observation
import CloudFSKit

// MARK: - ActivityFeatureModel  (WS3 — owned by the activity-split agent)
//
// State for the Activity split: the LIVE feed (`LiveActivityView`) and the
// HISTORICAL audit log (`AuditLogView`). Factored into its OWN @Observable model
// + file so the WS3 agent never touches AppModel.swift (FROZEN) or the other
// feature files. `AppModel.liveLog` holds the single instance.
//
//   • Live  — `loadLiveActivity()` calls `GatewayClient.liveActivity(in:)` →
//             `LiveActivity { transfers, events }` (in-flight + hot ring + bulk
//             rollups). Bulk events (`ActivityKind.bulk`, `bulkOp`, `bulkCount`)
//             render distinctly in `LiveActivityView`. The live feed is EPHEMERAL:
//             it reflects what is happening right now and is not the durable record.
//   • Audit — `loadAudit(...)` / `loadMoreAudit()` page via
//             `GatewayClient.auditRange(in:since:until:cursor:limit:)` →
//             `AuditPage { events, cursor }` (DO ring → R2 fallback). The cursor is
//             retained for page-back so the surface stays responsive over a large
//             history (a bounded page is loaded at a time, never the whole log).

@MainActor
@Observable
final class ActivityFeatureModel {

    // --- Live feed (ephemeral) ---
    var live: LiveActivity = LiveActivity(transfers: [], events: [])
    var liveState: LoadState<LiveActivity> = .idle

    // --- Audit log (paged, durable history) ---
    /// The accumulated rows for the current filter window. Grows as the user pages
    /// back; a bounded number of rows is fetched per page so the view stays light.
    var auditEvents: [ActivityEvent] = []
    var auditState: LoadState<[ActivityEvent]> = .idle
    /// Continuation cursor for paging back into history. `nil` once the range is
    /// exhausted (no older segments) — drives "Load older" availability.
    var auditCursor: String?
    /// True while a page-back fetch is in flight (so the footer shows a spinner
    /// without flipping the whole pane back to `.loading`).
    var auditLoadingMore = false

    // --- Audit query window (filters drive a fresh `loadAudit`) ---
    /// Free-text filter applied client-side over actor / verb / path. The wire
    /// query is the time window + cursor; text narrows the rendered rows.
    var auditSearch: String = ""
    /// Bounded look-back window for the audit query (maps to `since`).
    var auditWindow: AuditWindow = .week

    /// Page size requested from the audit reader. Bounded so large histories never
    /// materialize all at once — the DO ring → R2 fallback is paged via `cursor`.
    static let auditPageSize = 50

    init() {}

    /// The rows to render, after applying the client-side text filter. The wire
    /// already constrained the time window; this is a cheap in-memory narrow.
    var filteredAuditEvents: [ActivityEvent] {
        let q = auditSearch.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return auditEvents }
        return auditEvents.filter {
            $0.actor.lowercased().contains(q)
                || $0.verb.lowercased().contains(q)
                || $0.path.lowercased().contains(q)
        }
    }

    /// Whether more history may exist (a non-nil cursor means another page can be
    /// requested). Drives the "Load older" affordance in `AuditLogView`.
    var canLoadMoreAudit: Bool { auditCursor != nil }
}

/// A bounded look-back window for the audit query. Keeps the historical reader
/// responsive by constraining the `since` bound the DO/R2 reader must scan.
enum AuditWindow: String, CaseIterable, Identifiable, Sendable {
    case day   = "24h"
    case week  = "7 days"
    case month = "30 days"
    case all   = "All"

    var id: String { rawValue }

    /// The `since` date for the query (nil = unbounded / all history).
    var since: Date? {
        switch self {
        case .day:   return Date().addingTimeInterval(-86_400)
        case .week:  return Date().addingTimeInterval(-7 * 86_400)
        case .month: return Date().addingTimeInterval(-30 * 86_400)
        case .all:   return nil
        }
    }
}

extension AppModel {

    // MARK: Live feed (ephemeral)

    /// Load the LIVE activity feed for the selected filespace — in-flight transfers
    /// + the DO hot ring + rolled-up bulk ops (CONTRACTS §5.3). This is the
    /// ephemeral "what's happening now" surface; the durable record is the audit
    /// log (`loadAudit`). Folds the result into `liveLog.live` / `liveLog.liveState`.
    func loadLiveActivity() async {
        guard canReadWorkspaceActivity, let id = selectedFilespaceID else {
            liveLog.liveState = .idle
            return
        }
        liveLog.liveState = .loading
        do {
            let live = try await gateway.liveActivity(in: id)
            guard canReadWorkspaceActivity, selectedFilespaceID == id else { return }
            liveLog.live = live
            liveLog.liveState = .loaded(live)
        } catch {
            liveLog.liveState = .failed(error.localizedDescription)
        }
    }

    // MARK: Audit log (durable, paged)

    /// Load (or reload) the FIRST page of the historical audit log for the current
    /// filter window. Replaces any accumulated rows and resets the page cursor.
    /// Engine-agnostic: reads the DO ring then falls back to R2 segments for older
    /// ranges (CONTRACTS §5.4). A bounded page is fetched so a large history never
    /// materializes all at once; `loadMoreAudit()` pages back via the cursor.
    func loadAudit(since: Date? = nil, until: Date? = nil) async {
        guard canReadWorkspaceActivity, let id = selectedFilespaceID else {
            liveLog.auditState = .idle
            return
        }
        let sinceBound = since ?? liveLog.auditWindow.since
        liveLog.auditState = .loading
        liveLog.auditCursor = nil
        liveLog.auditEvents = []
        do {
            let page = try await gateway.auditRange(
                in: id, since: sinceBound, until: until,
                cursor: nil, limit: ActivityFeatureModel.auditPageSize)
            guard canReadWorkspaceActivity, selectedFilespaceID == id else { return }
            liveLog.auditEvents = page.events
            liveLog.auditCursor = page.cursor
            liveLog.auditState = .loaded(page.events)
        } catch {
            liveLog.auditState = .failed(error.localizedDescription)
        }
    }

    /// Page back into history: append the next bounded page using the retained
    /// cursor. No-op when there is no cursor (range exhausted) or a page-back is
    /// already in flight. Keeps the pane content stable while the footer spins.
    func loadMoreAudit() async {
        guard canReadWorkspaceActivity, let id = selectedFilespaceID,
              let cursor = liveLog.auditCursor,
              !liveLog.auditLoadingMore else { return }
        liveLog.auditLoadingMore = true
        defer { liveLog.auditLoadingMore = false }
        do {
            let page = try await gateway.auditRange(
                in: id, since: liveLog.auditWindow.since, until: nil,
                cursor: cursor, limit: ActivityFeatureModel.auditPageSize)
            guard canReadWorkspaceActivity, selectedFilespaceID == id else { return }
            liveLog.auditEvents.append(contentsOf: page.events)
            liveLog.auditCursor = page.cursor
            liveLog.auditState = .loaded(liveLog.auditEvents)
        } catch {
            // Keep the already-loaded rows visible; surface the failure inline only
            // if nothing has loaded yet.
            if liveLog.auditEvents.isEmpty {
                liveLog.auditState = .failed(error.localizedDescription)
            }
        }
    }
}
