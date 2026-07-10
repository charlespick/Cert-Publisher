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

1. **Ensures a cert-manager `Certificate` exists.** If it's missing, the
   controller creates one owned by the `CertPublication` and moves on — the
   cert is published on a later run once it's been issued. From then on
   cert-manager owns renewal and rotation (including when the subjects change).
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

Verifies the WinRM HTTPS listener against a pinned SHA-1 thumbprint,
authenticates over the configured transport (NTLM by default), and either:

- **`certStore`** — imports the cert + key as a PFX into a `Cert:\` store
  (`LocalMachine\My` by default), or
- **`file`** — writes the cert (and key) to a path.

Both modes support an optional post-install PowerShell script.

### Credentials

No secret material is ever stored in a `CertPublication`. Every provisioner's
`auth.secretRef` points at a `Secret` **in the same namespace** as the
publication, which supplies the SSH password/private key (+ optional
passphrase) or the WinRM password. Host-identity values (`hostFingerprint`,
`thumbprint`) are public verification data, not secrets, and stay in the spec.

See [`examples/`](examples/) for full manifests.

## Deploying

```sh
# Requires cert-manager already installed in the cluster.
kubectl apply -k deploy/
```

This installs the CRD, a namespace, RBAC, and the CronJob (image
`ghcr.io/charlespick/cert-publisher`). By default the controller reconciles
`CertPublication`s across the whole cluster; set `WATCH_NAMESPACE` on the
CronJob to scope it to one namespace.

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
| `utils.py` | Certificate parsing / fingerprints |

## License

MIT
