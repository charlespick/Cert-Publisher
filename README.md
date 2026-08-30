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
controller runs as a Kubernetes `CronJob`. On each run it scans every
`CertPublication` and, for each one:

1. **Ensures a cert-manager `Certificate` exists and matches the spec.** If
   it's missing, the controller creates one owned by the `CertPublication` and
   moves on — the cert is published on a later run once it's been issued. If the
   publication's subjects, issuer, or renewal settings later change, the
   controller patches the owned `Certificate` so cert-manager reissues.
   cert-manager owns renewal and rotation timing throughout.
2. **Reads the issued certificate** from the Secret cert-manager populates.
3. **Compares** the issued leaf against what's actually installed on the target
   host (by fingerprint).
4. **Installs** the certificate if they differ, then runs an optional
   post-install hook (e.g. `systemctl reload nginx`).

Because the compare step is fingerprint-based and cert-manager drives renewal
timing, the job is idempotent: it's a no-op until there's genuinely new
material to push.

Each reconcile records its outcome on the resource's `.status` (phase,
message, the published leaf fingerprint, and last-published/last-reconcile
timestamps), so `kubectl get certpublications` shows what's been pushed and
`kubectl describe` surfaces the last error:

```
NAME    DNS                  PROVISIONER   PHASE       PUBLISHED
web01   web01.example.com    ssh           Published   5m
win01   win01.example.com    winrm         Pending     
```

```
cert-manager  ──issues──▶  Secret (tls.crt/tls.key)
                                │
                                ▼
        CronJob ── reads ──▶ Cert-Publisher ── SSH/WinRM ──▶ target host
                                ▲
                     CertPublication (desired state)
```

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
prompts, or mandatory parameters left without a value. There is no operator
attached to a CronJob run, so any prompt fails the publication immediately with
a message naming the call that was refused.

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

## Deploying

Cert-Publisher ships as a Helm chart, published to GHCR as an OCI artifact.

```sh
# Requires cert-manager already installed in the cluster.
helm install cert-publisher \
  oci://ghcr.io/charlespick/charts/cert-publisher \
  --namespace cert-publisher --create-namespace
```

This installs the CRD, RBAC, a ServiceAccount, and the CronJob (image
`ghcr.io/charlespick/cert-publisher`). By default the controller reconciles
`CertPublication`s across the whole cluster; scope it to one namespace with
`--set config.watchNamespace=<namespace>`.

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
| `cronjob.schedule` | `*/30 * * * *` | Reconcile schedule |
| `cronjob.suspend` | `false` | Pause reconciliation without uninstalling |
| `crds.install` | `true` | Install the `CertPublication` CRD with the release |

The CRD carries a `helm.sh/resource-policy: keep` annotation, so uninstalling
the release leaves the CRD and any `CertPublication`s in place.

## Development

```sh
pip install -e ".[dev]"
pytest
ruff check .
```

The package lives in `src/cert_publisher/`:

| Module | Responsibility |
| --- | --- |
| `main.py` | CronJob entrypoint; scans and reconciles every publication |
| `reconcile.py` | Per-publication reconcile logic |
| `certmanager.py` | Builds the owned cert-manager `Certificate` |
| `kube.py` | Kubernetes API access |
| `provisioners/` | `ssh` and `winrm` install backends |
| `provisioners/scripts/` | Static PowerShell run by the WinRM provisioner |
| `utils.py` | Certificate parsing / fingerprints |

## License

MIT
