"""The backend's credential at Cloudflare for rpc.erth.network and lcd.erth.network.

The node's public hostnames sit behind a Cloudflare allowlist: rpc. answers
only a few GET routes and no JSON-RPC POST, and both hostnames are rate
limited per client address (the deploy repo's akash/README.md, "Public RPC
and LCD limits"). The backend needs more than the public gets: `earthd
gas-check` speaks JSON-RPC over POST (CometBFT's HTTP client, abci_query with
prove=true), the indexer and the known-DSC refresh read /store/ subspaces,
and one address does every user's grants and a full re-index. So it presents
a shared secret, CHAIN_EDGE_TOKEN, as HTTP Basic credentials
(`earth-backend:<token>`), and a WAF custom rule that matches that exact
Authorization header skips the allowlist and the rate limits (rule 0 there).

A secret, not the provider's egress address: the address is shared with the
provider's other tenants and changes with the lease; the token is neither.
It is sent only to CHAIN_EDGE_HOSTS, never to an operator's own node set in
EARTH_RPC_URL/INDEXER_RPC_URL, and it never appears in a log line: the
header is set on the request, and CometBFT's client strips the userinfo
from every address it prints.
"""
import base64
import logging
import re
from urllib.parse import urlsplit, urlunsplit

import config

logger = logging.getLogger(__name__)

USER = "earth-backend"
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}")


def _host(url: str) -> str:
    return (urlsplit(url.removeprefix("rest+").removeprefix("grpc+")).hostname or "").lower()


def applies(url: str) -> bool:
    """Whether requests to url carry the token: it is set, and url is one of ours."""
    return bool(config.CHAIN_EDGE_TOKEN) and _host(url) in config.CHAIN_EDGE_HOSTS


def _token() -> str:
    t = config.CHAIN_EDGE_TOKEN
    if not TOKEN.fullmatch(t):
        raise RuntimeError("CHAIN_EDGE_TOKEN must be 32-128 characters of [A-Za-z0-9_-]")
    return t


def header_value() -> str:
    """The exact Authorization value the Cloudflare rule matches."""
    return "Basic " + base64.b64encode(f"{USER}:{_token()}".encode()).decode()


def headers(url: str) -> dict[str, str]:
    return {"Authorization": header_value()} if applies(url) else {}


def node_flag(url: str) -> str:
    """url with the credentials as userinfo, for `earthd --node`: CometBFT's
    HTTP client sends them as Basic auth and has no header option."""
    if not applies(url):
        return url
    p = urlsplit(url)
    netloc = p.netloc.rsplit("@", 1)[-1]
    return urlunsplit((p.scheme, f"{USER}:{_token()}@{netloc}", p.path, p.query, p.fragment))


def check() -> None:
    """At startup: a malformed token stops the service; a missing one where
    it is needed is a warning (gas-check and the indexer's reads will be
    refused by the allowlist). Names hosts and settings, never the token."""
    if config.CHAIN_EDGE_TOKEN:
        _token()
        return
    wanted = [name for name, url in (("EARTH_RPC_URL", config.EARTH_RPC_URL),
                                     ("INDEXER_RPC_URL", config.INDEXER_RPC_URL),
                                     ("EARTH_NODE_URL", config.EARTH_NODE_URL))
              if _host(url) in config.CHAIN_EDGE_HOSTS]
    if wanted:
        logger.warning("CHAIN_EDGE_TOKEN is unset, so %s reach Cloudflare's public allowlist: "
                       "gas-check's JSON-RPC POSTs are refused there", ", ".join(wanted))
