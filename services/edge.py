"""The backend's credential at Cloudflare for rpc.erth.network and lcd.erth.network.

The node's public RPC and LCD sit behind earth-edge, a request filter in the
validator's lease that serves an allowlist to everyone (the deploy repo's
akash/README.md, "Public RPC and LCD"). Every call the backend makes is in
it: gas-check's JSON-RPC POSTs and store reads, the indexer's ranges, the
known-DSC refresh. The filter reads no credential and strips Authorization.

What the backend still needs is to skip Cloudflare's per-IP rate limits: one
address does every user's grants and a full re-index from height 1. So it
presents a shared secret, CHAIN_EDGE_TOKEN, as HTTP Basic credentials
(`earth-backend:<token>`), and a WAF rule that matches that exact
Authorization header skips the rate limiting rules and nothing else (rule 0
there, round-4 R4-E-6). A leaked token buys an address the backend's rate,
not a way past the filter.

A secret, not the provider's egress address: the address is shared with the
provider's other tenants and changes with the lease; the token is neither.
It is sent only over HTTPS to CHAIN_EDGE_HOSTS (R4-E-5: an http:// URL would
send it in the clear to whatever answers port 80), never to an operator's
own node set in EARTH_RPC_URL/INDEXER_RPC_URL, and it never appears in a log
line: the header is set on the request, and CometBFT's client strips the
userinfo from every address it prints.
"""
import base64
import logging
import re
from urllib.parse import urlsplit, urlunsplit

import config

logger = logging.getLogger(__name__)

USER = "earth-backend"
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}")


def _split(url: str):
    return urlsplit(url.removeprefix("rest+").removeprefix("grpc+"))


def _host(url: str) -> str:
    return (_split(url).hostname or "").lower()


def applies(url: str) -> bool:
    """Whether requests to url carry the token: it is set, url is one of ours,
    and the connection is TLS."""
    return (bool(config.CHAIN_EDGE_TOKEN) and _host(url) in config.CHAIN_EDGE_HOSTS
            and _split(url).scheme.lower() == "https")


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


_URLS = ("EARTH_RPC_URL", "INDEXER_RPC_URL", "EARTH_NODE_URL")


def check() -> None:
    """At startup: a malformed token, or one of our hosts configured over
    plain http while a token is set, stops the service; a missing token where
    it would be used is a warning (the backend works, but meets the per-IP
    rate limits). Names hosts and settings, never the token."""
    ours = [(name, getattr(config, name)) for name in _URLS
            if _host(getattr(config, name)) in config.CHAIN_EDGE_HOSTS]
    if config.CHAIN_EDGE_TOKEN:
        _token()
        plain = [name for name, url in ours if _split(url).scheme.lower() != "https"]
        if plain:
            raise RuntimeError("%s point at %s over plain http: CHAIN_EDGE_TOKEN is sent only "
                               "over https" % (", ".join(plain), "/".join(sorted(config.CHAIN_EDGE_HOSTS))))
        return
    if ours:
        logger.warning("CHAIN_EDGE_TOKEN is unset, so %s meet Cloudflare's per-IP rate limits "
                       "(re-index and grant bursts may see 429)", ", ".join(n for n, _ in ours))
