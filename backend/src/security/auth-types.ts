// SPDX-License-Identifier: AGPL-3.0-or-later
/// auth-types.ts — the FROZEN shared auth/account types (CONTRACTS-AUTH.md §1, §2).
///
/// Per CONTRACTS-AUTH.md §3 this is the single shared file the integration agent owns and
/// freezes. The module lanes (auth-password/session/totp/webauthn/email/service-tokens/signup)
/// each re-declare the *slice* they need locally (byte-for-byte with the contract) so they
/// stay self-contained and tsc-clean before this file exists. This file is the canonical
/// home those declarations mirror; the integration adapters (`auth-stores.ts`) and the route
/// wiring (`index.ts`) reference THESE types so there is one authoritative shape.
///
/// Because every lane's local copy is structurally identical to the types here, the adapter
/// classes in `auth-stores.ts` satisfy BOTH this file's interfaces AND each lane's narrowed
/// store interface by structural typing — no lane edit required.

import type { Scope } from "./auth";
import type { OrgRole } from "../permissions";

// ---------------------------------------------------------------------------------------
// §1.1 Account
// ---------------------------------------------------------------------------------------

export type AccountRole = OrgRole; // "owner" | "admin" | "space_admin" | "standard"
export type AccountStatus = "active" | "suspended" | "deprovisioned";

export interface Account {
  authEpoch?: number; // password-reset admission generation
  id: string; //            "acc-<uuid>"; STABLE. NOT the OrgDO user id.
  userId: string; //        the OrgDO `User.id` ("usr-..."); 1:1 link. Principal.sub uses THIS.
  orgId: string;
  email: string; //         THE USERNAME. Stored lowercased+trimmed (the canonical form).
  displayName: string;
  role: AccountRole; //     mirror of OrgDO User.role; OrgDO remains source of truth for role
  status: AccountStatus; // mirror of OrgDO User.status; suspended/deprovisioned => no login
  emailVerified: boolean;
  createdAt: number;
}

// ---------------------------------------------------------------------------------------
// §1.2 Password credential
// ---------------------------------------------------------------------------------------

export type PasswordAlgo = "scrypt";

export interface PasswordCredential {
  accountId: string; // PK (one password per account)
  algo: PasswordAlgo;
  N: number;
  r: number;
  p: number;
  dkLen: number;
  salt: string; // base64url of 16 random bytes
  hash: string; // base64url of the scrypt-derived key (dkLen bytes)
  updatedAt: number;
}

// ---------------------------------------------------------------------------------------
// §1.3 TOTP credential + recovery codes
// ---------------------------------------------------------------------------------------

export interface TotpCredential {
  accountId: string; // PK
  secret: string; //    base32 TOTP secret (RFC 4648, no padding)
  confirmed: boolean;
  createdAt: number;
  confirmedAt: number | null;
}

export interface RecoveryCode {
  accountId: string;
  codeHash: string; // sha256(base64url) of a single-use recovery code
  usedAt: number | null; // null = unused
}

// ---------------------------------------------------------------------------------------
// §1.4 WebAuthn credential
// ---------------------------------------------------------------------------------------

export type AuthnTransport = "usb" | "nfc" | "ble" | "internal" | "hybrid";

export interface WebAuthnCredential {
  id: string; //           "wac-<uuid>" internal row id
  accountId: string;
  credentialId: string; // base64url of the raw credential id
  publicKey: string; //    base64url of the COSE public key bytes
  signCount: number;
  transports: AuthnTransport[];
  label: string | null;
  createdAt: number;
  lastUsedAt: number | null;
}

// ---------------------------------------------------------------------------------------
// §1.5 Browser session
// ---------------------------------------------------------------------------------------

export interface BrowserSession {
  authEpoch?: number;
  id: string; //           "sess-<uuid>"; ALSO the jti of the minted session JWS (1:1)
  accountId: string;
  userId: string; //       == Account.userId; the Principal.sub
  orgId: string;
  scopes: Scope[];
  csrfToken: string;
  issuedAt: number;
  expiresAt: number; //    absolute cap (default 12h)
  lastSeenAt: number;
  revokedAt: number | null;
}

// ---------------------------------------------------------------------------------------
// §1.6 ServiceToken
// ---------------------------------------------------------------------------------------

export interface ServiceToken {
  id: string; //           "svc-<uuid>"; ALSO the jti of the minted service JWS
  orgId: string;
  userId: string;
  label: string;
  scopes: Scope[];
  spaceId: string | null;
  hashedSecret: string;
  createdByUserId: string;
  createdAt: number;
  lastUsedAt: number | null;
  expiresAt: number | null;
  revoked: boolean;
  /// auth-spec §4.1 (schema v2, additive): the device session that minted this token via the
  /// daemon-token route (§2.7). Null/absent for admin-minted tokens. Revoking the device
  /// CASCADES to tokens carrying its id; a re-mint soft-expires the prior token.
  deviceSessionId?: string | null;
}

// ---------------------------------------------------------------------------------------
// §1.7 EmailVerification / reset token
// ---------------------------------------------------------------------------------------

export type EmailTokenPurpose = "verify_email" | "password_reset" | "invite" | "legacy_enrollment";

export interface EmailTokenRecord {
  id: string; //          "evt-<uuid>"
  orgId: string;
  accountId: string;
  email: string;
  purpose: EmailTokenPurpose;
  tokenHash: string;
  createdAt: number;
  expiresAt: number;
  consumedAt: number | null;
}

// ---------------------------------------------------------------------------------------
// Short-lived challenge row (MFA step, webauthn register/auth, totp replay guard)
// ---------------------------------------------------------------------------------------

export interface ChallengeRecord {
  authEpoch?: number;
  id: string;
  accountId: string | null;
  purpose: string;
  value: string;
  expiresAt: number;
}
