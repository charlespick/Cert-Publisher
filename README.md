# Cert-Publisher

Use Kubernetes certificate infrastructure to provision certificates for your
entire infrastructure and securely install them on hosts that don't run in
Kubernetes.

Cert-Publisher lets [cert-manager](https://cert-manager.io/) do what it's good
at — issuing and renewing certificates — and takes care of the last mile:
pushing the issued certificate to a Linux box over SSH or a Windows box over
WinRM, and reloading whatever needs to pick it up.

## How it works

A `CertPublication` custom resource declares the certificate you want (DNS
names, issuer) and where it should be installed (the provisioner). The
controller runs as a single-replica Kubernetes `StatefulSet` and **watches**: it reacts to a new
or edited `CertPublication`, and to cert-manager issuing a certificate, within
seconds. For each publication it:

1. **Ensures a cert-manager `Certificate` exists and matches the spec.** If
   it's missing, the controller creates one owned by the `CertPublication` and
   moves on — the watch on that `Certificate` brings it straight back the moment
   cert-manager issues. If the
   publication's subjects, issuer, or renewal settings later change, the
   controller patches the owned `Certificate` so cert-manager reissues.
   cert-manager owns renewal and rotation timing throughout.
2. **Reads the issued certificate** from the Secret cert-manager populates.
3. **Compares** the issued leaf against what's actually installed on the target
   host (by fingerprint).
4. **Installs** the certificate if they differ, then runs an optional
   post-install hook (e.g. `systemctl reload nginx`).

Because the compare step is fingerprint-based and cert-manager drives renewal
timing, a reconcile is idempotent: it's a no-op until there's genuinely new
material to push.

```
     CertPublication ──────watch──────┐
            │                         ▼
            │                  Cert-Publisher ── SSH/WinRM/WS-Man ──▶ target host
            │                    ▲        │
            ▼                    │        └── writes .status + Events
      cert-manager ──issues──▶ Certificate + Secret (tls.crt/tls.key)
                                 └──────watch──────┘
```

### Watching, not polling

Three watches feed one work queue:

| Watched | Wakes | Because |
| --- | --- | --- |
| `CertPublication` | itself | a publication was created or edited |
| cert-manager `Certificate` | its owning publication | material was issued or reissued |
| cert-manager `CertificateRequest` | its owning publication | a host-generated CSR was signed |

Certificates and CertificateRequests map back through the `ownerReferences`
cert-publisher sets when it creates them, so only the publication actually
waiting on a piece of material is woken — and Certificates managed by anything
else are ignored. Nothing watches `Secret`s: the operator learns that a
certificate was issued from the `Certificate` resource, so it never needs
`list`/`watch` on every Secret in the cluster.

Everything else about the queue exists to make that safe:

- **Deduplication.** A publication edited, issued and reissued in the same
  second is one reconcile, not three.
- **Per-publication serialisation.** A key being reconciled is never handed to
  a second worker, so two workers never talk to the same target host at once.
  Different publications do run concurrently (`controller.workers`, 4 by
  default) — one unreachable host doesn't hold up the rest.
- **Exponential backoff.** A reconcile that fails is retried after
  `controller.backoffBase`, doubling to `controller.backoffMax`, per
  publication.
- **Resync.** Every publication is looked at again every
  `controller.resyncInterval` (30 minutes by default), scattered so a fleet
  issued on the same afternoon doesn't reconcile in lockstep. This is what
  catches the state no API event can report: a certificate replaced on the host
  by hand, an iDRAC that reverted, a host-keyed certificate ageing into its
  renewal window.

### Failure is per-publication

A host that is down is a `CertPublication` in `Error` with the reason on it and
a retry scheduled — not a failed pod, and not something that stops the other
ninety-nine publications from being reconciled at all.

Each reconcile records its outcome on the resource's `.status`: `phase`,
`message`, a machine-readable `reason`, a standard `Ready` condition, the
published leaf fingerprint, `nextRetryTime` while a retry is pending, and
last-published/last-reconcile timestamps. Transitions are also recorded as
Events, so `kubectl describe` shows the history rather than just the latest
state.

```
$ kubectl get certpublications -A
NAME    DNS                  PROVISIONER   READY   PHASE       PUBLISHED
web01   web01.example.com    ssh           True    Published   5m
idrac1  idrac1.example.com   idrac8        False   Pending     2d
win01   win01.example.com    winrm         False   Error       9m
```

```sh
# Block until a publication has actually reached its host.
kubectl wait --for=condition=Ready certpublication/web01 --timeout=5m
```

### One pod, never two

Publishing a certificate writes to a host: it installs files, imports a PFX,
reboots an iDRAC. Two pods doing that at once would install twice and, on the
iDRAC path, rotate the host's key out from under each other's pending
`CertificateRequest`. So the chart runs the controller as a single-replica
`StatefulSet`, which — unlike a `Deployment` — does not start a replacement pod
until the old one is gone. On a rollout the old pod drains first: it stops
taking new work and gives any publish in flight up to
`controller.shutdownTimeout` to finish, and only then does its replacement
start. The trade-off is that if the pod's node stops responding, nothing
replaces it until the node recovers or the pod is force-deleted; certificate
publishing can wait for that far more easily than it can survive two
controllers writing to the same host.

`/healthz` fails on the two things that stop the controller without stopping
the process: a watch gone silent — neither delivering events nor erroring —
and a reconcile still running after `controller.reconcileTimeout`, which means
a provisioner call has hung and is holding a worker that every publication
behind it is waiting on. Either restarts the pod. A watch that is *failing*
(missing RBAC, a missing cert-manager CRD) does not fail liveness, because a
restart would not fix it; it logs each failure and keeps retrying. `/readyz`
passes once every watch has listed successfully, which proves the pod can
reach the apiserver with the access it needs.

## Provisioners

### SSH (Linux)

Verifies the host against a pinned OpenSSH `SHA256:` host-key fingerprint,
authenticates with a password or private key, writes the cert and key over
SFTP with the requested file modes, and runs an optional post-install script.

### WinRM (Windows)

Pins the WinRM HTTPS listener to a configured SHA-1 thumbprint — enforced on
the connection that actually carries the session, so PKI validation is not
relied on — authenticates over the configured transport (NTLM by default),
and either:

- **`certStore`** — imports the cert + key as a PFX into a certificate store
  (`LocalMachine\My` by default), or
- **`file`** — writes the cert (and key) to a path.

Both modes support an optional post-install PowerShell script. The script
runs with `$env:CERT_PUBLISHER_THUMBPRINT` set to the newly installed certificate's
SHA-1 thumbprint (40 uppercase hex characters, no colons or spaces — the
literal form Windows and most .NET tooling expect). It runs under Windows
PowerShell 5.1 by default; set `powershell: "7"` to run it in the
`PowerShell.7` remoting endpoint instead (see below).

#### How it executes on the host

Commands run over PSRP (PowerShell Remoting Protocol) — the same protocol
`Enter-PSSession` and Ansible's `psrp` connection plugin use — not a WinRS
`cmd.exe` shell. This matters if the target host is watched by EDR or forwards
process telemetry to a SIEM:

- Everything executes inside a remote runspace hosted by `wsmprovhost.exe`.
  There is no `cmd.exe`, no `powershell.exe` child process, and no
  `-EncodedCommand` on any command line — the patterns that make an ordinary
  certificate install look like a commodity dropper.
- The PFX and its one-time password are **bound parameters** (a `byte[]` and a
  `SecureString`) carried as CLIXML in the SOAP body. They never touch a
  command line, so they never reach Sysmon EID 1, the WSMan operational log, or
  anything forwarding those onward.
- `certStore` installs are done fully in memory via the .NET store API. No PFX
  or private key is written to the remote filesystem, and there is no temp-file
  window to ACL.
- Each operation is a single pipeline running one of the static, parameterised
  scripts bundled in the package
  ([`src/cert_publisher/provisioners/scripts/`](src/cert_publisher/provisioners/scripts/)),
  so the script text on the host is byte-identical every run — reviewable, and
  stable enough to hash and allowlist.

The one remaining exception is `postInstallScript`, which is still written to a
temp `.ps1` and run by path so operator scripts keep working unchanged.

The hook must be non-interactive — no `Read-Host`, `Get-Credential`, nested
prompts, or mandatory parameters left without a value. There is nobody attached
to a reconcile, so any prompt fails the publication immediately with a message
naming the call that was refused.

`powershell: "7"` selects the `PowerShell.7` PSRP session configuration rather
than launching `pwsh.exe`. That endpoint is registered by PowerShell 7's
"Enable PowerShell remoting" installer option, or by running `Enable-PSRemoting`
from within `pwsh`; simply having PowerShell 7 installed is not enough.

#### Exportable private keys

`certStore` mode also supports `exportablePrivateKey`, which marks the
imported private key exportable. Windows fixes a private key's exportability
at import time — there's no supported way to flip it on an already-imported
certificate short of deleting and reimporting it, which cert-publisher won't
do on your behalf since that's a destructive operation cert-manager didn't
ask for. So enabling `exportablePrivateKey` on a publication that's already
published takes effect the next time the certificate is renewed; until then
the reconcile is a no-op and the status message says the setting is pending.

#### Transport names

`transport` accepts pypsrp's names: `ntlm` (the default), `kerberos`,
`negotiate`, `basic`, `credssp` and `certificate`. The pywinrm spellings `ssl`
and `plaintext` are still accepted and both authenticate with `basic` over the
HTTPS listener — the only listener cert-publisher talks to, which is what those
two names distinguished. Existing publications keep reconciling unchanged;
prefer `basic` in new ones.

### Credentials

No secret material is ever stored in a `CertPublication`. Every provisioner's
`auth.secretRef` points at a `Secret` **in the same namespace** as the
publication, which supplies the SSH password/private key (+ optional
passphrase) or the WinRM password. Host-identity values (`hostFingerprint`,
`thumbprint`) are public verification data, not secrets, and stay in the spec.

See [`examples/`](examples/) for full manifests.

### Dell iDRAC8 (PowerEdge 12G/13G)

Publishes the iDRAC's web GUI certificate over WS-Man. **No private key is sent
to the host.** An iDRAC8 will not accept an externally generated private key by
any route this project can use -- Redfish on this generation has no certificate
schema at all, its SSH is an SM-CLP/racadm interpreter with no SFTP, and
`racadm sslkeyupload` exists only in the remote racadm binary -- so the BMC
keeps its own key instead:

1. The iDRAC generates a fresh keypair and a CSR.
2. cert-manager signs the CSR through a `CertificateRequest`.
3. The signed certificate is imported back and the iDRAC is reset, which is
   what makes the new certificate take effect.

The private key never crosses the wire in either direction, which is a stronger
position than shipping a PFX. The trade-off is renewal ownership: a
`CertificateRequest` is signed once and never renewed, so **cert-publisher owns
renewal timing for this provisioner** rather than cert-manager. It renews once
the installed certificate is within `renewBefore` of expiry, defaulting to the
final third of its lifetime -- and also whenever the installed certificate stops
covering the publication's `dnsNames`, or is not the one cert-publisher last
installed (which is what makes the first run against a factory certificate do
the right thing).

The "is this current?" check reads the certificate off the iDRAC's live TLS
handshake -- the certificate clients actually see. That catches a host that has
never been published to, one whose certificate has drifted from the
publication's DNS names, one approaching expiry, and one where an import
succeeded but the restart that applies it did not. It is the same
handshake that authenticates the host, so a reconcile with nothing to do costs
one TLS connection and sends no credentials at all.

Host identity is established before any credential is sent, by either of two
complementary signals, so a host moves from first setup to steady state with no
configuration change:

- **`bootstrapThumbprint`** -- SHA-256 of the certificate the iDRAC serves
  today, for the first run against the factory self-signed certificate; or
- **currently valid** -- the live certificate chains to a trusted CA, matches
  the hostname, and is unexpired. `caBundle`, when set, *replaces* the system
  trust store rather than adding to it: a BMC has no public identity, so
  trusting every public CA would widen the check rather than tighten it. Set it
  to the CA that signs the published certificate.

Whichever signal accepts the host, the hash of *that exact certificate* is then
pinned onto the connection carrying the WS-Man session, so a man-in-the-middle
cannot satisfy the check on one connection and serve the session on another.

Standard certificate validation rules apply to the second signal, expiry
included, and that is deliberate: **an iDRAC whose certificate has already
expired cannot be renewed unattended.** Renewal starts well before expiry, so
reaching that state means the host was unreachable or failing for most of a
certificate lifetime -- in which case an operator should look at it rather than
have cert-publisher accept an expired credential as proof of identity. Recovery
is to set `bootstrapThumbprint` to what the host is serving now, exactly as on
first run. This mirrors how MDM and other PKI-based enrolment systems treat an
expired device credential.

> **Derive `bootstrapThumbprint` from a path that is not TLS-inspected.** Run
> from a workstation behind Cloudflare Zero Trust, Netskope, Zscaler or similar,
> `openssl s_client` shows you the proxy's certificate, and you would pin that
> instead of the iDRAC's.

Note that the iDRAC reboots to apply a new certificate, which drops active
iKVM and virtual media sessions. The host OS is unaffected.

The WS-Man calls follow Dell's iDRAC Card Profile (DCIM1043): `SetAttributes`
to stage the CSR subject, `GenerateSSLCSR`, then `ImportSSLCertificate`.

## Deploying

Cert-Publisher ships as a Helm chart, published to GHCR as an OCI artifact.

```sh
# Requires cert-manager already installed in the cluster.
helm install cert-publisher \
  oci://ghcr.io/charlespick/charts/cert-publisher \
  --namespace cert-publisher --create-namespace
```

This installs the CRD, RBAC, a ServiceAccount, and the controller as a
single-replica StatefulSet (image `ghcr.io/charlespick/cert-publisher`). By default the controller
reconciles `CertPublication`s across the whole cluster; scope it to one
namespace with `--set config.watchNamespace=<namespace>`.

To install from a checkout of this repository instead:

```sh
helm install cert-publisher charts/cert-publisher \
  --namespace cert-publisher --create-namespace
```

### Configuration

Common values (see [`charts/cert-publisher/values.yaml`](charts/cert-publisher/values.yaml)
for the full list):

| Value | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/charlespick/cert-publisher` | Controller image |
| `image.tag` | chart `appVersion` | Controller image tag |
| `config.logLevel` | `INFO` | Log level |
| `config.watchNamespace` | `""` (whole cluster) | Namespace to scope reconciliation to |
| `controller.workers` | `4` | Publications reconciled concurrently |
| `controller.resyncInterval` | `1800` | Seconds between re-checks of a settled publication |
| `controller.backoffBase` / `.backoffMax` | `5` / `900` | Retry backoff, in seconds, for a failing publication |
| `controller.reconcileTimeout` | `900` | Seconds one reconcile may run before liveness treats the pod as wedged |
| `crds.install` | `true` | Install the `CertPublication` CRD with the release |

The CRD carries a `helm.sh/resource-policy: keep` annotation, so uninstalling
the release leaves the CRD and any `CertPublication`s in place.

There is no replica count to set: the controller always runs as exactly one
pod (see [One pod, never two](#one-pod-never-two)).

### Upgrading from the CronJob

`helm upgrade` and nothing else. Helm creates the `StatefulSet` and then
removes the `CronJob`; the CRD's `spec` schema is unchanged, so every existing
`CertPublication` keeps working untouched. Three notes:

- Helm creates the new workload before deleting the old one. A CronJob run
  already in progress when you upgrade can overlap the new controller's first
  reconciles. To rule that out, suspend the CronJob directly
  (`kubectl patch cronjob <name> -p '{"spec":{"suspend":true}}'`) and wait for
  any running Job to finish before upgrading. (Setting `cronjob.suspend` in
  Helm would instead keep the new controller scaled to zero.)

- Values under `cronjob.` no longer do anything, except `cronjob.suspend`,
  which still pauses the release (it now scales the StatefulSet to zero). If you
  were using `cronjob.schedule` to control how often hosts get re-checked, set
  `controller.resyncInterval` (in **seconds**) instead. The upgrade notes say
  so if the release still sets them.
- The ClusterRole gains `list`/`watch` on cert-manager `Certificates` and
  `CertificateRequests` and `create` on Events. All of that is in the chart;
  if you manage RBAC yourself (`rbac.create=false`), apply the equivalent from
  [`charts/cert-publisher/templates/rbac.yaml`](charts/cert-publisher/templates/rbac.yaml).

## Development

```sh
pip install -e ".[dev]"
pytest
ruff check .
```

The package lives in `src/cert_publisher/`:

| Module | Responsibility |
| --- | --- |
| `main.py` | Entrypoint: signals, shutdown, exit codes |
| `controller.py` | Watches, work queue, workers, backoff, resync |
| `workqueue.py` | Deduplicating, rate-limited, delaying key queue |
| `health.py` | `/healthz`, `/readyz` |
| `reconcile.py` | Per-publication reconcile logic |
| `status.py` | `.status`, conditions and Events |
| `certmanager.py` | Builds the owned cert-manager `Certificate` |
| `kube.py` | Kubernetes API access |
| `provisioners/` | `ssh`, `winrm` and `idrac8` install backends |
| `provisioners/scripts/` | Static PowerShell run by the WinRM provisioner |
| `utils.py` | Certificate parsing / fingerprints |

## License

MIT
