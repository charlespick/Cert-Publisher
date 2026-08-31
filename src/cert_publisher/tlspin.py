"""Pin a TLS peer certificate on the connection that actually carries a request.

Both provisioners that speak HTTPS to a management controller face the same
problem: the endpoint's certificate chains to no CA the cluster trusts (a WinRM
listener's self-signed cert, an iDRAC's factory cert), so ordinary PKI
validation has to be switched off -- and once it is, urllib3 will accept *any*
certificate on the connection that carries the credentials and key material.

Verifying the endpoint with a separate probe socket does not close that hole: a
man-in-the-middle can answer the probe on one connection and serve the session
on another. The fix is to make the check a property of the pooled connection
itself, which is what this adapter does.
"""

from __future__ import annotations

from requests.adapters import HTTPAdapter


class PinnedHTTPAdapter(HTTPAdapter):
    """A ``requests`` adapter that pins the TLS peer to a certificate hash.

    Every connection urllib3 takes from the pool must present a leaf
    certificate whose hash equals ``fingerprint``, or the socket is refused
    before a single request byte is written. urllib3 selects the digest from
    the value's length (32 hex = MD5, 40 = SHA-1, 64 = SHA-256) and accepts it
    with or without colons in any case.

    Because the check runs on the pooled connection, it cannot be satisfied by
    one connection while the session data rides another -- closing the gap
    between "verify" and "use".
    """

    def __init__(self, fingerprint: str, **kwargs) -> None:
        self._assert_fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs) -> None:
        kwargs["assert_fingerprint"] = self._assert_fingerprint
        kwargs["cert_reqs"] = "CERT_NONE"
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self._assert_fingerprint
        kwargs["cert_reqs"] = "CERT_NONE"
        return super().proxy_manager_for(*args, **kwargs)
