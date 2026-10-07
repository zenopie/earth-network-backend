"""The passport register circuits too large to bundle in the wallets.

    GET /circuits/<variant>.<sha256>.json.gz   content-addressed, immutable
    GET /circuits/<variant>.json.gz            the current build, 5-minute cache

The wallets bundle the circuits a 2^18 proving setup covers (nearly every
passport) and fetch the rest on demand: the compiled circuit (bytecode and
ABI), gzipped, from circuits/ in this repo. Nothing here is trusted: each
wallet pins the sha256 of every circuit in its bundled manifest
(passport_variants.json) and refuses a file that does not hash to it. A
request names its variant, which the registration it is for makes public
anyway (MsgRegister.signature_algorithm).

Caching (round-3 R3-BD-6). Cloudflare caches .gz and honours max-age, so a
year-long `immutable` on a name that a circuit change reuses leaves colos
serving the old build, and wallets there refuse it (pinned hash) until the
entry is evicted. So only a name that carries the content's hash is
immutable: `<variant>.<sha256>.json.gz`, where the sha256 is that of the
inflated JSON, the same value the wallet pins. The name is served only when
circuits/SHA256SUMS says this build has that hash AND the file on disk
inflates to it (round-4 R4-E-7): a circuits/ directory replaced without
regenerating the sums would otherwise serve a different build as immutable
for a year. Each file is hashed once (at startup, and again only if it
changes on disk); any other hash, or a file that does not match its sum, is
a 404, never a stale or different file. The plain name, which wallets up to
final-mobile 355f4b2 build, gets a 5-minute cache, so a circuit change
reaches them within minutes of the deploy.
"""
import asyncio
import gzip
import hashlib
import logging
import os
import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

logger = logging.getLogger(__name__)

DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "circuits")
_NAME = re.compile(r"(lean_poa_[a-z0-9_]{1,64})(?:\.([0-9a-f]{64}))?\.json\.gz")
SUMS = "SHA256SUMS"
IMMUTABLE = "public, max-age=31536000, immutable"
SHORT = "public, max-age=300"

router = APIRouter()


def sums(directory: str | None = None) -> dict[str, str]:
    """variant -> sha256 of its inflated JSON, from circuits/SHA256SUMS
    (`sha256sum` format over the .json the wallet hashes)."""
    out = {}
    path = os.path.join(directory or DIR, SUMS)
    if not os.path.isfile(path):
        return out
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        digest, name = line.split(None, 1)
        out[name.lstrip("*").removesuffix(".json")] = digest
    return out


# path -> ((mtime_ns, size), sha256 of the inflated file)
_hashed: dict[str, tuple[tuple[int, int], str]] = {}


def file_digest(path: str) -> str | None:
    """sha256 of the inflated file, cached until the file changes on disk."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (st.st_mtime_ns, st.st_size)
    hit = _hashed.get(path)
    if hit and hit[0] == key:
        return hit[1]
    h = hashlib.sha256()
    try:
        with gzip.open(path) as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except (OSError, EOFError, gzip.BadGzipFile):
        return None
    _hashed[path] = (key, h.hexdigest())
    return h.hexdigest()


def verify(directory: str | None = None) -> list[str]:
    """Hash every listed circuit; returns the variants whose file does not
    match SHA256SUMS (their content-addressed name is then a 404). Logs the
    mismatches by variant name: a deploy error, nothing about a client."""
    d = directory or DIR
    bad = [v for v, digest in sums(d).items()
           if file_digest(os.path.join(d, v + ".json.gz")) != digest]
    if bad:
        logger.warning("circuits not matching SHA256SUMS (content-addressed names refused): %s",
                       ", ".join(sorted(bad)))
    return bad


@router.get("/circuits/{name}")
async def circuit(name: str) -> FileResponse:
    m = _NAME.fullmatch(name)
    if not m:
        raise HTTPException(404, "no such circuit")
    variant, digest = m.group(1), m.group(2)
    path = os.path.join(DIR, variant + ".json.gz")
    if not os.path.isfile(path):
        raise HTTPException(404, "no such circuit")
    if digest is not None and sums().get(variant) != digest:
        # Another build's hash (older or newer): this server does not have it.
        raise HTTPException(404, "no such circuit build")
    if digest is not None and await asyncio.to_thread(file_digest, path) != digest:
        # SHA256SUMS vouches for a build this file is not (R4-E-7).
        raise HTTPException(404, "no such circuit build")
    # Already gzip: the wallet inflates it and checks the hash itself. The
    # explicit identity encoding keeps GZipMiddleware from compressing it again.
    return FileResponse(path, media_type="application/gzip", headers={
        "Content-Encoding": "identity",
        "Cache-Control": IMMUTABLE if digest is not None else SHORT,
    })
