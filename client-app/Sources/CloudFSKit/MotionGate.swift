// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - MotionGate — the reduce-motion decision (pure, testable)
//
// One place that decides whether a transition should animate. The SwiftUI layer
// (`Theme.Motion.resolve`) delegates here so the gating rule is unit-tested
// without importing SwiftUI: when the system's Reduce Motion setting is on, every
// animated transition collapses to an instant change.

public enum MotionGate {
    /// True when transitions should animate, false when Reduce Motion is on.
    public static func shouldAnimate(reduceMotion: Bool) -> Bool {
        !reduceMotion
    }
}
