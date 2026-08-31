"""A small WS-Management client for invoking Dell DCIM methods on an iDRAC.

Only what this project needs: HTTP Basic over TLS, and ``wsman:Invoke`` of a
method on a singleton DCIM service instance. There is no enumeration/pull
support, no eventing, and no session state -- each invoke is one SOAP request.

The transport is a ``requests.Session`` whose TLS peer is pinned to a single
certificate hash (see :mod:`cert_publisher.tlspin`). The caller decides *which*
certificate to trust; this module only guarantees that every request it sends
travels over a connection presenting that exact certificate.
"""

from __future__ import annotations

import logging
import uuid
import xml.etree.ElementTree as ET
from typing import Self
from xml.sax.saxutils import escape, quoteattr

import requests

from .tlspin import PinnedHTTPAdapter

log = logging.getLogger("cert-publisher.wsman")

# WS-Management / SOAP namespaces (DMTF DSP0226).
_SOAP = "http://www.w3.org/2003/05/soap-envelope"
_WSA = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
_WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"

# Dell's CIM schema namespace; every DCIM_* class hangs off this prefix.
DELL_SCHEMA = "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/"

_ANONYMOUS = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
_GET_ACTION = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"

# DCIM methods answer with a ReturnValue rather than a SOAP fault for
# domain-level failures. 0 is success; 4096 means "job created, poll it".
RC_SUCCESS = "0"
RC_JOB_CREATED = "4096"


class WSManError(RuntimeError):
    """A SOAP fault, an HTTP error, or a non-success DCIM ReturnValue."""


class WSManClient:
    """Invoke DCIM methods over WS-Man against one iDRAC.

    ``pin_sha256`` is the hex SHA-256 of the DER certificate the endpoint must
    present. Callers obtain it by authenticating the host first (see
    ``idrac8._authenticate_endpoint``) and pass the hash of the very
    certificate they accepted, so verification and use are bound to the same
    peer.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        pin_sha256: str,
        timeout: int = 60,
    ) -> None:
        self.host = host
        self.port = port
        self.url = f"https://{host}:{port}/wsman"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers["Content-Type"] = "application/soap+xml;charset=UTF-8"
        # Never fall back to PKI validation: the pin is the whole check.
        self.session.verify = False
        self.session.mount("https://", PinnedHTTPAdapter(pin_sha256))

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- request construction --------------------------------------------

    def _wrap(self, action: str, resource_uri: str, selectors: dict, body: str) -> str:
        selector_xml = "".join(
            f"<wsman:Selector Name={quoteattr(k)}>{escape(v)}</wsman:Selector>"
            for k, v in selectors.items()
        )
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            f'<s:Envelope xmlns:s="{_SOAP}" xmlns:wsa="{_WSA}" xmlns:wsman="{_WSMAN}">'
            "<s:Header>"
            f"<wsa:To>{escape(self.url)}</wsa:To>"
            f"<wsman:ResourceURI>{escape(resource_uri)}</wsman:ResourceURI>"
            f"<wsa:ReplyTo><wsa:Address>{_ANONYMOUS}</wsa:Address></wsa:ReplyTo>"
            f"<wsa:Action>{escape(action)}</wsa:Action>"
            f"<wsa:MessageID>uuid:{uuid.uuid4()}</wsa:MessageID>"
            '<wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>'
            f"<wsman:OperationTimeout>PT{self.timeout}.000S</wsman:OperationTimeout>"
            f"<wsman:SelectorSet>{selector_xml}</wsman:SelectorSet>"
            "</s:Header>"
            f"<s:Body>{body}</s:Body>"
            "</s:Envelope>"
        )

    def get(self, cim_class: str, selectors: dict) -> dict[str, str]:
        """Fetch one CIM instance addressed by ``selectors``.

        Used to read an iDRAC attribute's CurrentValue/PendingValue directly,
        which is cheaper and far simpler than an Enumerate/Pull sweep of every
        attribute on the card.
        """
        resource_uri = DELL_SCHEMA + cim_class
        root = self._send(
            self._wrap(_GET_ACTION, resource_uri, selectors, ""),
            f"{cim_class} Get",
        )
        fields: dict[str, str] = {}
        for element in root.iter():
            if element.tag.split("}")[-1] != cim_class:
                continue
            for child in element:
                fields[child.tag.split("}")[-1]] = (child.text or "").strip()
        return fields

    def _send(self, envelope: str, what: str) -> ET.Element:
        """POST one envelope and return its parsed body, raising on failure."""
        response = self.session.post(
            self.url,
            data=envelope.encode("utf-8"),
            timeout=self.timeout + 10,
            # A SOAP endpoint has no legitimate redirect, and following one
            # would carry the Basic credentials over an unpinned (possibly
            # plaintext) connection, since the pin is mounted on https:// only.
            allow_redirects=False,
        )
        # An iDRAC reports domain failures as HTTP 500 with a SOAP fault body,
        # so the fault is parsed before the status code is judged: it carries
        # the only actionable text (InvalidParameter, AccessDenied, "method not
        # supported"). Falling through to a bare status code would discard it.
        root = None
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError:
            pass
        if root is not None and (fault := _fault_text(root)) is not None:
            raise WSManError(f"{what} on {self.host} faulted: {fault}")
        if response.status_code != 200:
            raise WSManError(
                f"{what} on {self.host} returned HTTP {response.status_code}"
            )
        if root is None:
            raise WSManError(f"{what} on {self.host} returned an unparseable body")
        return root

    def _envelope(
        self, resource_uri: str, method: str, params: dict, selectors: dict
    ) -> str:
        selector_xml = "".join(
            f"<wsman:Selector Name={quoteattr(k)}>{escape(v)}</wsman:Selector>"
            for k, v in selectors.items()
        )
        body = "".join(_param_elements(name, value) for name, value in params.items())
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            f'<s:Envelope xmlns:s="{_SOAP}" xmlns:wsa="{_WSA}" xmlns:wsman="{_WSMAN}">'
            "<s:Header>"
            f"<wsa:To>{escape(self.url)}</wsa:To>"
            f"<wsman:ResourceURI>{escape(resource_uri)}</wsman:ResourceURI>"
            f"<wsa:ReplyTo><wsa:Address>{_ANONYMOUS}</wsa:Address></wsa:ReplyTo>"
            f"<wsa:Action>{escape(resource_uri)}/{escape(method)}</wsa:Action>"
            f"<wsa:MessageID>uuid:{uuid.uuid4()}</wsa:MessageID>"
            '<wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>'
            f"<wsman:OperationTimeout>PT{self.timeout}.000S</wsman:OperationTimeout>"
            f"<wsman:SelectorSet>{selector_xml}</wsman:SelectorSet>"
            "</s:Header>"
            f"<s:Body><n1:{method}_INPUT xmlns:n1={quoteattr(resource_uri)}>{body}"
            f"</n1:{method}_INPUT></s:Body>"
            "</s:Envelope>"
        )

    # -- invocation -------------------------------------------------------

    def invoke(
        self,
        cim_class: str,
        method: str,
        params: dict | None = None,
        *,
        expect_return: bool = True,
    ) -> dict[str, str]:
        """Invoke ``method`` on ``cim_class`` and return its ``*_OUTPUT`` fields.

        Raises :class:`WSManError` on a SOAP fault, a non-200 response, or --
        when ``expect_return`` is set -- a ReturnValue that is neither success
        nor "job created". The DCIM ``Message`` is used as the error text
        because it is the only human-readable explanation the iDRAC gives.
        """
        selectors = _SELECTORS_BY_CLASS.get(cim_class)
        if selectors is None:
            raise WSManError(f"no WS-Man selectors are known for {cim_class}")
        resource_uri = DELL_SCHEMA + cim_class
        envelope = self._envelope(resource_uri, method, params or {}, selectors)

        log.debug("wsman invoke %s.%s on %s", cim_class, method, self.host)
        root = self._send(envelope, f"{cim_class}.{method}")

        output = _output_fields(root, method)
        if expect_return:
            rc = output.get("ReturnValue")
            if rc not in (RC_SUCCESS, RC_JOB_CREATED):
                message = output.get("Message") or "no message returned by the iDRAC"
                raise WSManError(
                    f"{cim_class}.{method} on {self.host} failed "
                    f"(ReturnValue={rc}): {message}"
                )
        return output


# Key properties addressing each singleton DCIM service instance; the values
# are fixed by Dell. Selectors are per-class, so invoking a class that has no
# entry here would silently address it with another class's keys -- refuse
# instead.
_SELECTORS_BY_CLASS = {
    "DCIM_iDRACCardService": {
        "CreationClassName": "DCIM_iDRACCardService",
        "Name": "DCIM:iDRACCardService",
        "SystemCreationClassName": "DCIM_ComputerSystem",
        "SystemName": "DCIM:ComputerSystem",
    },
}


def _param_elements(name: str, value) -> str:
    """Render one input parameter, repeating the element for array values."""
    values = value if isinstance(value, (list, tuple)) else [value]
    return "".join(f"<n1:{name}>{escape(str(v))}</n1:{name}>" for v in values)


def _fault_text(root: ET.Element) -> str | None:
    fault = root.find(f".//{{{_SOAP}}}Fault")
    if fault is None:
        return None
    return " ".join(t.strip() for t in fault.itertext() if t.strip())[:500]


def _output_fields(root: ET.Element, method: str) -> dict[str, str]:
    """Collect the children of the ``<Method_OUTPUT>`` element into a dict.

    Repeated elements are joined with ", " so an array-valued output does not
    silently lose all but its last entry.
    """
    fields: dict[str, str] = {}
    for element in root.iter():
        # Exact local-name match: endswith() would also fold in a differently
        # prefixed element such as DCIM_SetAttributes_OUTPUT, merging two
        # results into one and corrupting ReturnValue.
        if element.tag.split("}")[-1] != f"{method}_OUTPUT":
            continue
        for child in element:
            key = child.tag.split("}")[-1]
            text = (child.text or "").strip()
            fields[key] = f"{fields[key]}, {text}" if key in fields else text
    return fields
