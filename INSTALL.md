# Install CloudFS

CloudFS has two parts: a server in your Cloudflare account and a Mac app for each teammate. Start with a small trial using copies of files. The current release is a preview, with filesystem compatibility limits described below. Source builds are covered in [Build CloudFS](docs/BUILD.md); customers can use the supplied Mac app without compiling it.

If you received a team invitation, skip to **Join an existing team**. You do not need a Cloudflare account, storage key, setup secret, Node.js, Xcode, or an Apple Developer account.

## Set up a new server

One administrator does this once. Download the versioned **CloudFS Server** archive and matching signed **CloudFS for Mac** DMG from [Releases](https://github.com/joshrogers117/cloudfs-public/releases). Verify each downloaded file against the release SHA-256 checksums (`shasum -a 256 <file>` on macOS). Extract the server archive into a folder you will keep for updates. The server runs entirely on Cloudflare after installation; this computer does not need to stay on.

### Have these ready

| Required from the administrator | Why it is needed |
| --- | --- |
| Cloudflare account with Workers Paid and R2 enabled | Runs the service and stores encrypted file blocks. Cloudflare bills this account. The installer does not activate a paid plan. |
| Cloudflare account ID | Selects the correct account, especially if you belong to several. Find it in the Cloudflare dashboard. |
| A unique server name | Names the Worker and its data/audit buckets. Example: `cloudfs-studio`. |
| A temporary provisioning API token | Creates the server, buckets and a separate bucket-scoped storage credential. See permissions below. |
| Node.js 22.12 or newer, including npm | Runs the setup program on macOS or Linux. Download from [nodejs.org](https://nodejs.org/). Only the administrator needs this. |
| The signed, notarized CloudFS Mac DMG | The installer places this download on your own server for invited teammates. No rebuilding or re-signing is required. |

For invitation and password-reset email, also choose a sender such as `files@your-company.com`. Onboard its domain in Cloudflare **Email Service → Email Sending** first. This requires a domain using Cloudflare DNS; Cloudflare may add mail-authentication records. Review those changes in its dashboard. [Cloudflare email setup](https://developers.cloudflare.com/email-service/get-started/send-emails/).

You can configure email later and copy invitation links manually during a private test. Password-reset email is unavailable until delivery is configured. Before inviting a real team, send a test to an external mailbox and check both Inbox and Junk. Successful submission does not guarantee inbox placement.

If you skip email during installation, onboard the sender domain later, add `EMAIL_PROVIDER=cloudflare` and `EMAIL_FROM=files@your-company.com` to your profile's `deployment.vars`, then redeploy that profile. This adds the required sender-restricted Worker binding. Use the console's email settings to send a delivery test; the browser alone cannot create the Cloudflare binding or verify DNS.

### Provisioning permissions

Create a temporary API token restricted to the intended account with **Workers Scripts Write**, **Workers R2 Storage Write**, and **Account API Tokens Write**. The last permission lets setup create a separate storage credential. It is powerful: use it only on the administrator's computer, give it a short lifetime, and revoke it when setup is complete. Do not distribute it with the server package or Mac app.

The guided installer accepts this token in a hidden terminal prompt, after dependencies are installed. It does not save the provisioning token. The separately generated storage key remains in your protected configuration and Worker secrets and is restricted to the data bucket. Keep that storage credential active. [Cloudflare R2 token permissions](https://developers.cloudflare.com/r2/api/tokens/).

If your organization does not allow account-token creation permissions, use the [manual deployment path](docs/SELF-HOSTING.md#the-config-split-generic-wranglerjsonc--git-ignored-prodvars): deploy using your permitted Cloudflare identity and supply a separately created, bucket-scoped R2 key. The guided path currently requires all three permissions.

### Run the guided installer

In Terminal, change into the extracted server folder and run:

```sh
node scripts/install-cloudflare.mjs --check
node scripts/install-cloudflare.mjs --profile studio
```

The local check makes no network calls or changes. Setup asks for the account ID, server name, optional email sender and Mac DMG path. Review the resource list before typing `install`.

Setup then:

1. Installs the pinned backend and console dependencies from lockfiles.
2. Generates the authentication, setup and encryption keys once.
3. Creates or resumes the data and audit buckets and the scoped storage credential.
4. Deploys the Worker, Durable Objects, web console and Mac download together.
5. Checks metadata services, storage and the deployed API.
6. Offers to copy the setup secret on Mac and open your browser at `/setup`.

Your initial address is `https://<server-name>.<your-subdomain>.workers.dev`. Choose a workers.dev subdomain in Cloudflare before installing. A custom domain is optional; configure it before introducing passkeys or SSO. Existing buckets, another S3 provider, or jurisdiction restrictions use the [advanced guide](docs/SELF-HOSTING.md).

Fresh setup uses automatic R2 placement. A filespace's region follows its storage bucket; choosing a display label later cannot move existing objects. Location preferences and jurisdiction restrictions are distinct. The guided installer does not yet provision jurisdiction-restricted buckets.

### Finish in the browser

Paste the generated setup secret into **your server's** setup page. It proves you control the deployment and permits creation of the first owner. Setup closes after that account is created. Normal users never see or need this secret. It remains an operator credential for diagnostics and recovery, so keep it private.

Create the workspace and owner account with your email, name and a new password. Add two-factor authentication, create your first filespace, then invite teammates with **Standard user** and the appropriate **Read** or **Edit** filespace access. An invitation with no filespace access creates an account that cannot open any files yet.

The browser runs health checks automatically. Successful checks continue quietly. If a check fails, use its diagnosis/fix details and rerun it. Storage, authentication and encryption failures must be fixed before testing files. Email warnings require an actual delivery test before onboarding a team.

### Save the recovery material

Keep `.deployments/studio/` private and back it up securely outside this computer. It contains configuration, setup checkpoints and `secrets.json`. Losing or casually replacing `STORAGE_ENC_KEY` can make stored filespace keys unreadable. The installer refuses to invent replacement keys for an existing deployment.

That configuration backup alone does not contain your files or metadata. Arrange an [independent encrypted backup and recovery rehearsal](docs/BACKUP-RESTORE.md). Snapshots provide file-history recovery within this server; they do not replace an independent backup of the server and its keys.

If setup stops, rerun the same command with the same profile. Keep the setup folder intact. If it reports an uncertain token-creation result, inspect Cloudflare account tokens before trying to create another. If keys are missing, restore the private profile from backup. Do not start a new profile to repair the old server.

To return to the browser handoff without redeploying:

```sh
node scripts/install-cloudflare.mjs --profile studio --finish
```

## Join an existing team

1. Open the invitation email and choose your account password. Check Junk if the invitation is missing; ask the administrator to resend an expired link.
2. Download **CloudFS for Mac**, open the DMG and drag CloudFS to Applications.
3. Open CloudFS. On the invitation success page, choose **Open Mac app** to pass your server address to it.
4. Choose **Sign in with browser**, approve the device on your team's server, and allow the browser to open CloudFS. Use the displayed code fallback if your browser blocks the return to the app.
5. Connect the filespace and choose **Browse files**. Files appear in Finder and download into the local cache when used.

The Mac app contains the background filesystem engine and Finder integration. It uses macOS's built-in SMB client over loopback; no macFUSE or kernel-extension installation is required. Approve expected macOS background-item or Keychain prompts as explained by the app. Do not disable Gatekeeper or reduce system security. The declared minimum is macOS 14 on Apple Silicon or Intel; release testing coverage is recorded in [Compatibility](docs/COMPATIBILITY.md), separately from that minimum.

Normal users can manage their local cache, connection and permitted file recovery. Server administration, storage credentials, membership management and snapshot schedules require administrator authorization, including through CLI/API calls.

## Verify the trial

Upload a disposable file, wait for **All changes saved to cloud**, and compare it after a download and reconnect. Test your actual editing applications on copies. Have a second user open the files from another Mac. Ask an administrator to create a snapshot, then mount it read-only, copy a historical file out, and restore a selected file to the current filespace. Verify both the restored bytes and the unchanged snapshot.

Known preview limits include an SMB resource-fork open-and-truncate operation that some apps may use, snapshot lists that can need **View → Refresh** after another device creates a snapshot, and email that may land in Junk. Current Mac updates are manual and require a restart to load the new engine. General editing-app compatibility and macOS 14/Intel qualification are not implied by a successful test on a newer Apple Silicon VM.

## Update or get help

For a server update, extract the new version alongside the old one, securely transfer the same `.deployments/<profile>/` directory, update `CLOUDFS_MAC_INSTALLER` in `deployment.vars` to the new signed DMG, install backend/web dependencies with `npm ci --prefix backend` and `npm ci --prefix web`, then run `node scripts/deployment.mjs studio check` and `node scripts/deployment.mjs studio deploy`. Follow release-specific backup/migration instructions first. Never run fresh setup or generate new keys over an existing server. Keep the old package and configuration until the update is validated; code rollback alone may not undo metadata migrations.

For a Mac update, wait for uploads to finish, quit CloudFS, replace it in Applications, and restart the Mac. Keep credentials and cache intact. Do not remove app state as an update step.

| Problem | Next step |
| --- | --- |
| Local setup check fails | Install the required Node/npm version and extract the complete server package. |
| Cloudflare rejects setup | Check the selected account, token permissions, Workers plan, R2 and workers.dev subdomain. Resume the same profile. |
| Setup secret is unknown | Run `--finish` or retrieve `BOOTSTRAP_SECRET` from your private profile. An invited teammate should use the invitation, not `/setup`. |
| No invitation/reset email | Check the sender domain and delivery configuration, send a test, and check Junk. Use a manual invitation link only for a controlled test. |
| App cannot return from the browser | Confirm the app is in Applications, retry **Open Mac app**, then use the code fallback. |
| Signed in but no filespace | Ask an administrator to grant filespace/folder access. Signing in does not grant file access. |
| Uploads remain pending | Keep the app and its pending-write cache intact; check connectivity and the reported storage error before restarting. |

When requesting support, include app/server versions, macOS version, the failing step and redacted diagnostics. Never include the deployment secrets file, password, setup secret, invitation/reset URL, raw API token or encryption key.
