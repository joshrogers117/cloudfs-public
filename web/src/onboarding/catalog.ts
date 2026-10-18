/*
 * Provider onboarding catalog — a typed, extensible registry that turns raw
 * "endpoint / bucket / key" configuration into a guided, step-by-step experience.
 *
 * Every storage and email provider self-hosters can wire cloud-fs to is described
 * here ONCE: a display name, a logo/initial, the fields it needs, the S3 endpoint
 * template + default region (storage), and an ordered list of real, accurate steps
 * — each with an optional deep link straight to the right console page, and the DNS
 * records where the provider requires domain verification.
 *
 * The Create-Filespace storage wizard and the Settings → Email wizard both read
 * from this catalog so the guidance always matches the picked provider. Adding a
 * new provider is a single entry here — no screen changes required.
 *
 * Doc links were chosen to point at the canonical official documentation; they are
 * stable landing pages rather than deep-version-pinned URLs so they keep resolving.
 */

export type ProviderCategory = 'storage' | 'email' | 'auth'

/** A field the provider's wizard collects (drives copy + the auto-fill defaults). */
export interface CatalogField {
  /** Stable key, e.g. 'endpoint' | 'region' | 'bucket' | 'fromAddress' | 'secret'. */
  key: string
  /** Human label shown above the input. */
  label: string
  /** Short helper text under the label. */
  hint?: string
  /** Placeholder / example value. */
  placeholder?: string
  /** Marks the secret field (rendered masked, write-only). */
  secret?: boolean
  /** Optional — some fields are auto-filled / advanced. */
  optional?: boolean
}

/** A single guided step, with an optional deep link to the right console page. */
export interface CatalogStep {
  title: string
  body: string
  /** Deep link straight to the console page this step refers to. */
  link?: { label: string; href: string }
  /**
   * An optional value to render as a copyable mono/code block under the body —
   * e.g. the redirect URI the user must register. May carry the `<redirectUri>`
   * token, substituted by `withRedirectUri()`.
   */
  code?: string
}

/** A DNS record the provider asks you to publish to verify a sending domain. */
export interface DnsRecord {
  type: 'TXT' | 'CNAME' | 'MX'
  /** Host / name, e.g. "resend._domainkey" or "@". `<domain>` is a placeholder. */
  host: string
  /** The value to publish (often provider-generated; shown as guidance). */
  value: string
  note?: string
}

export interface CatalogEntry {
  id: string
  name: string
  category: ProviderCategory
  /** Single-character initial used as a logo fallback tile. */
  initial: string
  /** Optional inline SVG logo markup (kept tiny; falls back to `initial`). */
  logo?: string
  /** Accent color for the logo tile (token or hex). */
  tint?: string
  /** Fields the wizard collects for this provider. */
  fields: CatalogField[]
  /**
   * S3 endpoint template (storage only). `<accountId>` / `<region>` placeholders are
   * substituted by `resolveEndpoint()` when the user supplies them, so the endpoint
   * field auto-fills the moment the provider is picked.
   */
  endpointTemplate?: string
  /** Default region prefilled when the provider is chosen (storage only). */
  regionDefault?: string
  /**
   * When true the endpoint is fully derived from the region (AWS S3 / SES), so the
   * raw endpoint field is hidden and computed from `endpointTemplate`.
   */
  endpointDerivedFromRegion?: boolean
  /** Self-hosted endpoint (MinIO) — the user must supply the whole origin. */
  endpointUserSupplied?: boolean
  /** Whether path-style addressing should default on (MinIO typically needs it). */
  forcePathStyle?: boolean
  /** Ordered, accurate setup steps with deep links. */
  steps: CatalogStep[]
  /** DNS records to publish for domain verification, where relevant (email). */
  dns?: DnsRecord[]
  /** Canonical official documentation landing page. */
  docsUrl: string
  /** One-line description shown on the picker tile. */
  blurb: string
}

/* ========================================================================== *
 *  STORAGE PROVIDERS                                                          *
 * ========================================================================== */

const STORAGE: CatalogEntry[] = [
  {
    id: 'r2',
    name: 'Cloudflare R2',
    category: 'storage',
    initial: 'R',
    tint: '#f6821f',
    blurb: 'Zero-egress object storage on Cloudflare.',
    endpointTemplate: 'https://<accountId>.r2.cloudflarestorage.com',
    regionDefault: 'auto',
    fields: [
      { key: 'endpoint', label: 'S3 endpoint', placeholder: 'https://<accountId>.r2.cloudflarestorage.com', hint: 'Auto-filled from your R2 account ID.' },
      { key: 'region', label: 'Region', placeholder: 'auto', hint: 'R2 uses the literal value "auto".' },
      { key: 'bucket', label: 'Bucket', placeholder: 'my-filespace-bucket', hint: 'A dedicated, empty R2 bucket.' },
      { key: 'accessKeyId', label: 'Access Key ID', placeholder: 'R2 token Access Key ID' },
      { key: 'secretAccessKey', label: 'Secret Access Key', secret: true, placeholder: '••••••••••••••••' },
    ],
    docsUrl: 'https://developers.cloudflare.com/r2/api/s3/tokens/',
    steps: [
      {
        title: 'Open the R2 dashboard',
        body: 'In the Cloudflare dashboard, open R2 Object Storage from the left sidebar. Note your Account ID — it appears in the R2 overview and forms the start of your endpoint URL.',
        link: { label: 'Open Cloudflare R2', href: 'https://dash.cloudflare.com/?to=/:account/r2/overview' },
      },
      {
        title: 'Create a dedicated bucket',
        body: 'Click “Create bucket” and give it a clear name (for example studio-a-editorial). Use a brand-new, EMPTY bucket for each filespace — cloud-fs writes content-addressed encrypted blocks under a prefix, and sharing a bucket risks key collisions and lifecycle-rule data loss.',
        link: { label: 'Create an R2 bucket', href: 'https://dash.cloudflare.com/?to=/:account/r2/new' },
      },
      {
        title: 'Manage R2 API Tokens',
        body: 'Back on the R2 overview page, open “Manage R2 API Tokens” (top-right). This is where you mint the S3-compatible Access Key ID / Secret Access Key pair — different from a global API token.',
        link: { label: 'Manage R2 API Tokens', href: 'https://dash.cloudflare.com/?to=/:account/r2/api-tokens' },
      },
      {
        title: 'Create the token',
        body: 'Create a token scoped to Object Read & Write. Scope it to just the bucket you created (Apply to specific buckets) for least privilege. Submit to generate the keys.',
      },
      {
        title: 'Copy the keys',
        body: 'Copy the Access Key ID and Secret Access Key shown once. Paste them into the credential fields here — the secret is stored encrypted and never shown again. Your endpoint is https://<accountId>.r2.cloudflarestorage.com and the region is "auto".',
      },
    ],
  },
  {
    id: 's3',
    name: 'AWS S3',
    category: 'storage',
    initial: 'S',
    tint: '#ff9900',
    blurb: 'Amazon S3 — endpoint derived from the region.',
    endpointTemplate: 'https://s3.<region>.amazonaws.com',
    regionDefault: 'us-east-1',
    endpointDerivedFromRegion: true,
    fields: [
      { key: 'region', label: 'Region', placeholder: 'us-east-1', hint: 'The bucket’s region — the endpoint is derived from it.' },
      { key: 'bucket', label: 'Bucket', placeholder: 'my-filespace-bucket', hint: 'A dedicated, empty S3 bucket.' },
      { key: 'accessKeyId', label: 'Access Key ID', placeholder: 'AKIA…' },
      { key: 'secretAccessKey', label: 'Secret Access Key', secret: true, placeholder: '••••••••••••••••' },
    ],
    docsUrl: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
    steps: [
      {
        title: 'Create a dedicated bucket',
        body: 'In the S3 console, create a new, empty bucket in the region closest to your team. Keep “Block all public access” ON — cloud-fs reaches the bucket with signed requests, never public URLs. Note the bucket name and region.',
        link: { label: 'Open the S3 console', href: 'https://s3.console.aws.amazon.com/s3/buckets' },
      },
      {
        title: 'Create an IAM user',
        body: 'In IAM, add a user (for example cloud-fs-studio-a) for programmatic / application access. Do NOT attach AdministratorAccess — you’ll grant a tight, bucket-scoped policy next.',
        link: { label: 'Open IAM users', href: 'https://console.aws.amazon.com/iam/home#/users' },
      },
      {
        title: 'Attach a least-privilege bucket policy',
        body: 'Attach an inline policy granting only s3:GetObject, s3:PutObject, s3:DeleteObject, and s3:ListBucket on arn:aws:s3:::YOUR-BUCKET and arn:aws:s3:::YOUR-BUCKET/*. This limits the key to exactly this one bucket.',
        link: { label: 'IAM policy reference', href: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-iam.html' },
      },
      {
        title: 'Create an access key',
        body: 'Open the user → Security credentials → Create access key (use case: Application running outside AWS). Copy the Access Key ID and Secret Access Key. The endpoint is computed automatically from the region as https://s3.<region>.amazonaws.com.',
      },
    ],
  },
  {
    id: 'b2',
    name: 'Backblaze B2',
    category: 'storage',
    initial: 'B',
    tint: '#e21e29',
    blurb: 'B2 Cloud Storage via the S3-compatible API.',
    endpointTemplate: 'https://s3.<region>.backblazeb2.com',
    regionDefault: 'us-west-004',
    fields: [
      { key: 'endpoint', label: 'S3 endpoint', placeholder: 'https://s3.us-west-004.backblazeb2.com', hint: 'Shown on your bucket — the part after s3. is your region.' },
      { key: 'region', label: 'Region', placeholder: 'us-west-004', hint: 'Matches the endpoint, e.g. us-west-004.' },
      { key: 'bucket', label: 'Bucket', placeholder: 'my-filespace-bucket' },
      { key: 'accessKeyId', label: 'keyID', placeholder: 'Application Key ID' },
      { key: 'secretAccessKey', label: 'applicationKey', secret: true, placeholder: '••••••••••••••••' },
    ],
    docsUrl: 'https://www.backblaze.com/docs/cloud-storage-s3-compatible-api',
    steps: [
      {
        title: 'Create a dedicated bucket',
        body: 'In the Backblaze B2 console, open Buckets → Create a Bucket. Keep it Private. After creation, the bucket’s “Endpoint” is shown, e.g. s3.us-west-004.backblazeb2.com — the us-west-004 part is your region.',
        link: { label: 'Open B2 Buckets', href: 'https://secure.backblaze.com/b2_buckets.htm' },
      },
      {
        title: 'Create an Application Key',
        body: 'Open App Keys → Add a New Application Key. Scope it to just the bucket you created and grant Read and Write. Create the key.',
        link: { label: 'Open App Keys', href: 'https://secure.backblaze.com/app_keys.htm' },
      },
      {
        title: 'Copy keyID and applicationKey',
        body: 'Copy the keyID (this is your Access Key ID) and applicationKey (this is your Secret Access Key) — the applicationKey is shown only once. Paste them, set the endpoint to your bucket’s S3 endpoint, and use the matching region.',
      },
    ],
  },
  {
    id: 'minio',
    name: 'MinIO',
    category: 'storage',
    initial: 'M',
    tint: '#c72c48',
    blurb: 'Self-hosted, S3-compatible object storage.',
    endpointUserSupplied: true,
    regionDefault: 'us-east-1',
    forcePathStyle: true,
    fields: [
      { key: 'endpoint', label: 'Endpoint', placeholder: 'https://minio.your-domain.com', hint: 'Your MinIO server’s URL (HTTPS strongly recommended).' },
      { key: 'region', label: 'Region', placeholder: 'us-east-1', hint: 'Match your MinIO MINIO_REGION (default us-east-1).' },
      { key: 'bucket', label: 'Bucket', placeholder: 'my-filespace-bucket' },
      { key: 'accessKeyId', label: 'Access Key', placeholder: 'service account access key' },
      { key: 'secretAccessKey', label: 'Secret Key', secret: true, placeholder: '••••••••••••••••' },
    ],
    docsUrl: 'https://min.io/docs/minio/linux/administration/console/security-and-access.html',
    steps: [
      {
        title: 'Point to your MinIO server',
        body: 'Enter your MinIO endpoint, e.g. https://minio.your-domain.com. Use HTTPS in production. cloud-fs uses path-style addressing for MinIO, which is enabled automatically.',
        link: { label: 'MinIO Console docs', href: 'https://min.io/docs/minio/linux/administration/minio-console.html' },
      },
      {
        title: 'Create a dedicated bucket',
        body: 'In the MinIO Console, open Buckets → Create Bucket and create a fresh, empty bucket for this filespace.',
      },
      {
        title: 'Create an access key (service account)',
        body: 'In the Console, open Access Keys → Create access key (or run `mc admin user svcacct add`). Restrict the key’s policy to read/write/delete + list on just this bucket for least privilege.',
        link: { label: 'Access keys docs', href: 'https://min.io/docs/minio/linux/administration/console/security-and-access.html' },
      },
      {
        title: 'Copy the key pair',
        body: 'Copy the Access Key and Secret Key. Paste them here along with your endpoint, region, and bucket.',
      },
    ],
  },
  {
    id: 'wasabi',
    name: 'Wasabi',
    category: 'storage',
    initial: 'W',
    tint: '#01cd3e',
    blurb: 'Hot cloud storage, S3-compatible.',
    endpointTemplate: 'https://s3.<region>.wasabisys.com',
    regionDefault: 'us-east-1',
    fields: [
      { key: 'endpoint', label: 'Service endpoint', placeholder: 'https://s3.us-east-1.wasabisys.com', hint: 'Use the endpoint for your bucket’s region.' },
      { key: 'region', label: 'Region', placeholder: 'us-east-1', hint: 'The region you created the bucket in.' },
      { key: 'bucket', label: 'Bucket', placeholder: 'my-filespace-bucket' },
      { key: 'accessKeyId', label: 'Access Key', placeholder: 'Wasabi Access Key' },
      { key: 'secretAccessKey', label: 'Secret Key', secret: true, placeholder: '••••••••••••••••' },
    ],
    docsUrl: 'https://docs.wasabi.com/docs/access-keys-1',
    steps: [
      {
        title: 'Create a dedicated bucket',
        body: 'In the Wasabi console, create a new bucket and note its region. The service endpoint follows the pattern s3.<region>.wasabisys.com (for example s3.us-east-1.wasabisys.com).',
        link: { label: 'Open the Wasabi console', href: 'https://console.wasabisys.com/' },
      },
      {
        title: 'Create an access key',
        body: 'Open Access Keys → Create New Access Key (root, or a sub-user scoped to this bucket for least privilege). Wasabi shows the Secret Key only once.',
        link: { label: 'Wasabi access keys docs', href: 'https://docs.wasabi.com/docs/access-keys-1' },
      },
      {
        title: 'Copy the key pair',
        body: 'Copy the Access Key and Secret Key and paste them here with the matching region endpoint and your bucket name.',
      },
    ],
  },
]

/* ========================================================================== *
 *  EMAIL PROVIDERS                                                            *
 * ========================================================================== */

const EMAIL: CatalogEntry[] = [
  {
    id: 'cloudflare',
    name: 'Cloudflare Email Sending',
    category: 'email',
    initial: 'C',
    tint: '#f6821f',
    blurb: 'Send invitations and account emails from your domain.',
    fields: [
      { key: 'fromAddress', label: 'From address', placeholder: 'no-reply@your-domain.com', hint: 'Use a domain onboarded to Cloudflare Email Sending.' },
      { key: 'fromName', label: 'From name', placeholder: 'cloud-fs', optional: true },
    ],
    docsUrl: 'https://developers.cloudflare.com/email-service/get-started/send-emails/',
    steps: [
      {
        title: 'Enable Email Sending',
        body: 'In Cloudflare, open Compute → Email Service → Email Sending. Sending invitations to arbitrary recipients requires a Workers Paid plan.',
        link: { label: 'Email Sending setup guide', href: 'https://developers.cloudflare.com/email-service/get-started/send-emails/' },
      },
      {
        title: 'Add and verify your domain',
        body: 'Choose Onboard Domain and follow Cloudflare’s steps for the domain in your From address. Review and apply the exact DNS records Cloudflare provides, then wait for verification.',
        link: { label: 'Domain setup instructions', href: 'https://developers.cloudflare.com/email-service/configuration/domains/' },
      },
      {
        title: 'Confirm the Worker binding',
        body: 'Ask your server operator to confirm the send_email binding is named EMAIL and permits your sender and intended recipients. Set the From address below and send a test to an inbox you control before saving.',
        link: { label: 'Email binding settings', href: 'https://developers.cloudflare.com/email-service/configuration/send-bindings/' },
      },
    ],
  },
  {
    id: 'resend',
    name: 'Resend',
    category: 'email',
    initial: 'R',
    tint: '#5b5bd6',
    blurb: 'Developer email API — key + verified domain.',
    fields: [
      { key: 'fromAddress', label: 'From address', placeholder: 'no-reply@your-domain.com', hint: 'Must be on a domain verified in Resend.' },
      { key: 'fromName', label: 'From name', placeholder: 'cloud-fs', optional: true },
      { key: 'secret', label: 'API key', secret: true, placeholder: 're_••••••••••••', hint: 'Starts with re_. Stored encrypted; never shown again.' },
    ],
    docsUrl: 'https://resend.com/docs/dashboard/domains/introduction',
    steps: [
      {
        title: 'Create an API key',
        body: 'In the Resend dashboard open API Keys → Create API Key. Give it Sending access. Copy the key (it starts with re_) — it’s shown only once.',
        link: { label: 'Open Resend API Keys', href: 'https://resend.com/api-keys' },
      },
      {
        title: 'Add your sending domain',
        body: 'Open Domains → Add Domain and enter the domain you’ll send from. Resend generates DKIM and SPF records for you to publish.',
        link: { label: 'Open Resend Domains', href: 'https://resend.com/domains' },
      },
      {
        title: 'Publish the DNS records',
        body: 'Add the DKIM (CNAME/TXT) and SPF (TXT) records Resend shows for your domain at your DNS host, then click Verify. The exact DKIM values are generated per-domain in the dashboard.',
        link: { label: 'Domain verification docs', href: 'https://resend.com/docs/dashboard/domains/introduction' },
      },
      {
        title: 'Set the From address',
        body: 'Once the domain shows Verified, enter a From address on that domain below and send a test email to yourself.',
      },
    ],
    dns: [
      { type: 'TXT', host: 'send.<domain>', value: 'v=spf1 include:amazonses.com ~all', note: 'SPF for Resend’s sending subdomain.' },
      { type: 'TXT', host: 'resend._domainkey.<domain>', value: 'p=… (DKIM public key shown in the Resend dashboard)', note: 'DKIM — copy the exact value Resend generates.' },
    ],
  },
  {
    id: 'postmark',
    name: 'Postmark',
    category: 'email',
    initial: 'P',
    tint: '#ffde00',
    blurb: 'Transactional email — server token + verified signature.',
    fields: [
      { key: 'fromAddress', label: 'From address', placeholder: 'no-reply@your-domain.com', hint: 'Must match a confirmed Sender Signature or verified domain.' },
      { key: 'fromName', label: 'From name', placeholder: 'cloud-fs', optional: true },
      { key: 'secret', label: 'Server API token', secret: true, placeholder: '••••••••-••••-••••', hint: 'The Server token from a Postmark server. Stored encrypted.' },
    ],
    docsUrl: 'https://postmarkapp.com/support/article/1080-how-to-verify-a-domain',
    steps: [
      {
        title: 'Get the Server API token',
        body: 'In Postmark, open (or create) a Server, then go to the API Tokens tab and copy the Server API Token. This token authorizes sending for that server.',
        link: { label: 'Open Postmark servers', href: 'https://account.postmarkapp.com/servers' },
      },
      {
        title: 'Add a Sender Signature or domain',
        body: 'Open Sender Signatures → Add Domain or Add Signature. A single From address can be confirmed via a one-click email (Sender Signature); a whole domain is verified via DNS.',
        link: { label: 'Open Sender Signatures', href: 'https://account.postmarkapp.com/signature_domains' },
      },
      {
        title: 'Verify with DNS (recommended)',
        body: 'For a domain, publish the DKIM (TXT) and Return-Path (CNAME) records Postmark generates, then click Verify. The DKIM selector and values are shown per-domain in your account.',
        link: { label: 'How to verify a domain', href: 'https://postmarkapp.com/support/article/1080-how-to-verify-a-domain' },
      },
      {
        title: 'Set the From address',
        body: 'Use a From address that matches your confirmed signature or verified domain, paste the Server token below, and send a test email.',
      },
    ],
    dns: [
      { type: 'TXT', host: 'pm._domainkey.<domain>', value: 'k=rsa; p=… (DKIM public key shown in Postmark)', note: 'DKIM — copy the exact value from your account.' },
      { type: 'CNAME', host: 'pm-bounces.<domain>', value: 'pm.mtasv.net', note: 'Return-Path / custom bounce domain.' },
    ],
  },
  {
    id: 'ses',
    name: 'Amazon SES',
    category: 'email',
    initial: 'S',
    tint: '#ff9900',
    blurb: 'Amazon SES — IAM creds + a verified identity.',
    fields: [
      { key: 'fromAddress', label: 'From address', placeholder: 'no-reply@your-domain.com', hint: 'Must be a verified SES identity (domain or email).' },
      { key: 'fromName', label: 'From name', placeholder: 'cloud-fs', optional: true },
      { key: 'sesRegion', label: 'SES region', placeholder: 'us-east-1', hint: 'The region where you verified your identity.' },
      { key: 'sesAccessKeyId', label: 'AWS Access Key ID', placeholder: 'AKIA…' },
      { key: 'sesSecretAccessKey', label: 'AWS Secret Access Key', secret: true, placeholder: '••••••••••••••••', hint: 'Stored encrypted; never shown again.' },
    ],
    docsUrl: 'https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html',
    steps: [
      {
        title: 'Verify a domain (or email) identity',
        body: 'In the SES console for your chosen region, open Identities → Create identity and verify a domain (recommended) or a single email address. Domain verification uses Easy DKIM and publishes three CNAME records.',
        link: { label: 'Open SES Identities', href: 'https://console.aws.amazon.com/ses/home#/verified-identities' },
      },
      {
        title: 'Publish the DKIM records',
        body: 'Add the three Easy DKIM CNAME records SES generates for your domain at your DNS host. SES marks the identity Verified once they propagate. The selectors are unique per identity.',
        link: { label: 'Creating identities (DKIM)', href: 'https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html' },
      },
      {
        title: 'Request production access (leave the sandbox)',
        body: 'New SES accounts are in the SANDBOX: you can only send TO verified addresses, with low limits. Open SES → Account dashboard → Request production access before sending to real recipients. The “Send test” here only works to a verified address until you’re out of the sandbox.',
        link: { label: 'Move out of the sandbox', href: 'https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html' },
      },
      {
        title: 'Create sending IAM credentials',
        body: 'In IAM, create a user with an inline policy allowing ses:SendEmail and ses:SendRawEmail, then create an access key. Paste the Access Key ID, Secret Access Key, and the SES region below.',
        link: { label: 'Open IAM users', href: 'https://console.aws.amazon.com/iam/home#/users' },
      },
    ],
    dns: [
      { type: 'CNAME', host: '<selector1>._domainkey.<domain>', value: '<selector1>.dkim.amazonses.com', note: 'Easy DKIM record 1 of 3 (values are per-identity).' },
      { type: 'CNAME', host: '<selector2>._domainkey.<domain>', value: '<selector2>.dkim.amazonses.com', note: 'Easy DKIM record 2 of 3.' },
      { type: 'CNAME', host: '<selector3>._domainkey.<domain>', value: '<selector3>.dkim.amazonses.com', note: 'Easy DKIM record 3 of 3.' },
    ],
  },
]

/* ========================================================================== *
 *  AUTH / SIGN-IN PROVIDERS                                                   *
 * ========================================================================== *
 *
 * The identity provider that backs sign-in for the whole organization. The
 * default is cloud-fs's BUILT-IN auth (password + TOTP + passkeys) — zero setup.
 * Every other entry is an OIDC identity provider: the owner creates an app/client
 * in the provider's console, copies the issuer + client id + secret, registers the
 * redirect URI cloud-fs shows them, and (optionally) restricts to a domain.
 *
 * Steps that reference the redirect URI carry the literal `<redirectUri>` token;
 * the wizard substitutes the real `<gateway origin>/v1/auth/oidc/callback` before
 * rendering (see `resolveRedirectUri()` / the wizard's `withRedirectUri`).
 */

/** The OIDC redirect/callback path appended to the gateway origin. */
export const OIDC_CALLBACK_PATH = '/v1/auth/oidc/callback'

const AUTH: CatalogEntry[] = [
  {
    id: 'builtin',
    name: 'Built-in',
    category: 'auth',
    initial: '◆',
    tint: '#a08cff', // CloudFS purple drive; third-party provider colors remain their own.
    blurb: 'Passwords and an authenticator app. Passkeys when enabled.',
    fields: [],
    docsUrl: 'https://developers.cloudflare.com/',
    steps: [
      {
        title: 'Nothing to configure',
        body: 'Built-in authentication is on by default. Members sign in with an email + password, can add an authenticator app (TOTP) for two-factor, and can register passkeys when enabled on the deployment. There is no external identity provider to set up and no redirect URI to register.',
      },
      {
        title: 'Manage members and security',
        body: 'Invite members, require two-factor, and let people add passkeys from their own account settings. You can switch to a single-sign-on (OIDC) provider at any time below — when you do, you choose whether passwords keep working or whether everyone must sign in through your IdP.',
      },
    ],
  },
  {
    id: 'clerk',
    name: 'Clerk',
    category: 'auth',
    initial: 'C',
    tint: '#6c47ff',
    blurb: 'Clerk-hosted auth via OIDC — drop-in users, OAuth, and SSO.',
    fields: [
      { key: 'issuer', label: 'Issuer / Frontend API URL', placeholder: 'https://your-app.clerk.accounts.dev', hint: 'Your Clerk Frontend API URL — the OIDC issuer. cloud-fs discovers the rest from /.well-known/openid-configuration.' },
      { key: 'clientId', label: 'Client ID', placeholder: 'Clerk OAuth application Client ID' },
      { key: 'clientSecret', label: 'Client Secret', secret: true, placeholder: '••••••••••••••••', hint: 'Stored encrypted; never shown again.' },
      { key: 'allowedDomains', label: 'Allowed email domains', placeholder: 'acme.com, studio.tv', hint: 'Comma-separated. Only users with these email domains may sign in.', optional: true },
    ],
    docsUrl: 'https://clerk.com/docs/advanced-usage/clerk-idp',
    steps: [
      {
        title: 'Create a Clerk application',
        body: 'In the Clerk dashboard, create an application (or open an existing one). Clerk hosts your users and exposes a standard OIDC issuer that cloud-fs federates with.',
        link: { label: 'Open Clerk dashboard', href: 'https://dashboard.clerk.com/' },
      },
      {
        title: 'Enable Clerk as an OAuth / OIDC provider',
        body: 'Open Configure → OAuth Applications and create an OAuth application (Clerk-as-IdP). Enable the openid, email, and profile scopes so cloud-fs receives the user’s email and name.',
        link: { label: 'Clerk as OIDC provider', href: 'https://clerk.com/docs/advanced-usage/clerk-idp' },
      },
      {
        title: 'Register the redirect URI',
        body: 'Add this exact Redirect URI (Allowed callback URL) to the OAuth application — cloud-fs only accepts the IdP round-trip back to this address:',
        code: '<redirectUri>',
      },
      {
        title: 'Copy the issuer, Client ID, and Client Secret',
        body: 'From the OAuth application, copy the Frontend API URL (the Issuer), the Client ID, and the Client Secret. Paste them into the fields here — the secret is stored encrypted and never shown again.',
      },
      {
        title: 'Restrict to your email domain (optional)',
        body: 'Set the allowed email domain(s) below so only people with your organization’s email addresses can be provisioned. Then click Validate to confirm cloud-fs can reach your issuer’s discovery document.',
      },
    ],
  },
  {
    id: 'okta',
    name: 'Okta',
    category: 'auth',
    initial: 'O',
    tint: '#007dc1',
    blurb: 'Okta OIDC — create an app integration and federate sign-in.',
    fields: oidcFields('https://your-org.okta.com'),
    docsUrl: 'https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/',
    steps: oidcSteps({
      provider: 'Okta',
      createTitle: 'Create an OIDC app integration',
      createBody: 'In the Okta Admin console, open Applications → Create App Integration → OIDC - OpenID Connect, Web Application. Grant the openid, email, and profile scopes.',
      createLink: { label: 'Open Okta Applications', href: 'https://login.okta.com/' },
      issuerLabel: 'Issuer (your Okta org URL, e.g. https://your-org.okta.com)',
    }),
  },
  {
    id: 'entra',
    name: 'Microsoft Entra ID',
    category: 'auth',
    initial: 'E',
    tint: '#0078d4',
    blurb: 'Microsoft Entra ID (Azure AD) OIDC — register an app and federate.',
    fields: oidcFields('https://login.microsoftonline.com/<tenant-id>/v2.0'),
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc',
    steps: oidcSteps({
      provider: 'Microsoft Entra ID',
      createTitle: 'Register an application',
      createBody: 'In the Entra admin center (Azure AD), open Identity → Applications → App registrations → New registration. Choose Web as the platform. Under Certificates & secrets, create a new client secret.',
      createLink: { label: 'Open Entra App registrations', href: 'https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade' },
      issuerLabel: 'Issuer (https://login.microsoftonline.com/<tenant-id>/v2.0)',
    }),
  },
  {
    id: 'auth0',
    name: 'Auth0',
    category: 'auth',
    initial: 'A',
    tint: '#eb5424',
    blurb: 'Auth0 OIDC — create a Regular Web Application and federate.',
    fields: oidcFields('https://your-tenant.us.auth0.com'),
    docsUrl: 'https://auth0.com/docs/get-started/applications/application-settings',
    steps: oidcSteps({
      provider: 'Auth0',
      createTitle: 'Create a Regular Web Application',
      createBody: 'In the Auth0 dashboard, open Applications → Create Application → Regular Web Application. The Domain (e.g. your-tenant.us.auth0.com) is your issuer; the Client ID and Client Secret are on the Settings tab.',
      createLink: { label: 'Open Auth0 Applications', href: 'https://manage.auth0.com/#/applications' },
      issuerLabel: 'Issuer (https://your-tenant.us.auth0.com — note the trailing slash Auth0 uses)',
    }),
  },
  {
    id: 'google',
    name: 'Google Workspace',
    category: 'auth',
    initial: 'G',
    tint: '#ea4335',
    blurb: 'Google Workspace OIDC — federate with an OAuth 2.0 client.',
    fields: oidcFields('https://accounts.google.com'),
    docsUrl: 'https://developers.google.com/identity/openid-connect/openid-connect',
    steps: oidcSteps({
      provider: 'Google Workspace',
      createTitle: 'Create an OAuth 2.0 Client ID',
      createBody: 'In Google Cloud Console, open APIs & Services → Credentials → Create Credentials → OAuth client ID → Web application. The issuer is always https://accounts.google.com. Copy the Client ID and Client Secret.',
      createLink: { label: 'Open Google Cloud Credentials', href: 'https://console.cloud.google.com/apis/credentials' },
      issuerLabel: 'Issuer (always https://accounts.google.com for Google)',
    }),
  },
]

/** Shared OIDC field set (issuer / clientId / clientSecret / allowed domains). */
function oidcFields(issuerPlaceholder: string): CatalogField[] {
  return [
    { key: 'issuer', label: 'Issuer URL', placeholder: issuerPlaceholder, hint: 'The OIDC issuer. cloud-fs reads /.well-known/openid-configuration from it to discover the auth + token endpoints.' },
    { key: 'clientId', label: 'Client ID', placeholder: 'OAuth client / application ID' },
    { key: 'clientSecret', label: 'Client Secret', secret: true, placeholder: '••••••••••••••••', hint: 'Stored encrypted; never shown again.' },
    { key: 'allowedDomains', label: 'Allowed email domains', placeholder: 'acme.com, studio.tv', hint: 'Comma-separated. Only users with these email domains may sign in.', optional: true },
  ]
}

/** Shared 5-step OIDC walkthrough, parameterized per provider. */
function oidcSteps(opts: {
  provider: string
  createTitle: string
  createBody: string
  createLink: { label: string; href: string }
  issuerLabel: string
}): CatalogStep[] {
  return [
    { title: opts.createTitle, body: opts.createBody, link: opts.createLink },
    {
      title: 'Register the redirect URI',
      body: `Add this exact Redirect URI (Allowed callback / Sign-in redirect URL) to the ${opts.provider} app — cloud-fs only accepts the IdP round-trip back to this address:`,
      code: '<redirectUri>',
    },
    {
      title: 'Copy the issuer, Client ID, and Client Secret',
      body: `Copy the ${opts.issuerLabel}, the Client ID, and the Client Secret into the fields below. The secret is stored encrypted and never shown again.`,
    },
    {
      title: 'Restrict to your organization’s domain (optional)',
      body: 'Set the allowed email domain(s) below so only people with your organization’s email addresses can be provisioned. Enable auto-provision to create accounts on first sign-in.',
    },
    {
      title: 'Validate and save',
      body: 'Click Validate to confirm cloud-fs can fetch the issuer’s OpenID configuration and resolve its endpoints, then Save. Switching to OIDC-only will disable password sign-in for everyone in the organization.',
    },
  ]
}

/* ========================================================================== *
 *  Registry + lookup helpers                                                 *
 * ========================================================================== */

export const CATALOG: CatalogEntry[] = [...STORAGE, ...EMAIL, ...AUTH]

export const STORAGE_PROVIDERS: CatalogEntry[] = STORAGE
export const EMAIL_PROVIDERS: CatalogEntry[] = EMAIL
export const AUTH_PROVIDERS: CatalogEntry[] = AUTH

/** The OIDC auth providers (everything except the built-in default). */
export const OIDC_PROVIDERS: CatalogEntry[] = AUTH.filter((e) => e.id !== 'builtin')

/** Look up any catalog entry by id (within a category when ambiguous). */
export function catalogEntry(id: string, category?: ProviderCategory): CatalogEntry | undefined {
  return CATALOG.find((e) => e.id === id && (category ? e.category === category : true))
}

export function storageProvider(id: string): CatalogEntry | undefined {
  return STORAGE.find((e) => e.id === id)
}

export function emailProvider(id: string): CatalogEntry | undefined {
  return EMAIL.find((e) => e.id === id)
}

export function authProvider(id: string): CatalogEntry | undefined {
  return AUTH.find((e) => e.id === id)
}

/**
 * The redirect/callback URI the user must register with their IdP:
 * `<gateway origin>/v1/auth/oidc/callback`. Pass the gateway origin (e.g.
 * `https://gateway.example.com`); falls back to the current page origin when the
 * gateway is reverse-proxied same-origin (the common dev/prod case here).
 */
export function resolveRedirectUri(gatewayOrigin?: string): string {
  const origin = (gatewayOrigin ?? '').replace(/\/+$/, '')
  if (origin) return `${origin}${OIDC_CALLBACK_PATH}`
  if (typeof window !== 'undefined') return `${window.location.origin}${OIDC_CALLBACK_PATH}`
  return OIDC_CALLBACK_PATH
}

/**
 * Substitute the `<redirectUri>` token in a catalog entry's step bodies with the
 * concrete callback URL, so the guided steps show the exact URI to register.
 */
export function withRedirectUri(entry: CatalogEntry, redirectUri: string): CatalogEntry {
  const needsSub = (s: CatalogStep) =>
    s.body.includes('<redirectUri>') || (s.code?.includes('<redirectUri>') ?? false)
  if (!entry.steps.some(needsSub)) return entry
  return {
    ...entry,
    steps: entry.steps.map((s) =>
      needsSub(s)
        ? {
            ...s,
            body: s.body.replaceAll('<redirectUri>', redirectUri),
            code: s.code?.replaceAll('<redirectUri>', redirectUri),
          }
        : s,
    ),
  }
}

/**
 * Resolve the concrete S3 endpoint for a storage provider, substituting any
 * `<accountId>` / `<region>` placeholders the user has supplied. Returns '' when
 * the template needs a value that isn't available yet (e.g. R2 before the account
 * id is typed), so callers can leave the field for the user to complete.
 */
export function resolveEndpoint(
  entry: CatalogEntry,
  ctx: { accountId?: string; region?: string },
): string {
  const tmpl = entry.endpointTemplate
  if (!tmpl) return ''
  let out = tmpl
  if (out.includes('<region>')) {
    const region = (ctx.region ?? entry.regionDefault ?? '').trim()
    if (!region) return ''
    out = out.replaceAll('<region>', region)
  }
  if (out.includes('<accountId>')) {
    const acct = (ctx.accountId ?? '').trim()
    if (!acct) return '' // R2: wait for the account id before auto-filling.
    out = out.replaceAll('<accountId>', acct)
  }
  return out
}
