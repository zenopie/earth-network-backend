"""Container entrypoint: hand the state volume to `app`, then drop root for good.

The app holds the hot wallet's mnemonic, so it runs unprivileged. Root is kept
only for the chown: a volume made by an earlier, root-running image is
root-owned, and an app that cannot write the replay table there would find
every callback payable again. Plain Python rather than gosu or setpriv, so the
image needs nothing it does not already have.
"""
import os
import pwd

STATE = os.path.dirname(os.environ.get("STATE_DB", "/app/state/ads_for_gas.db"))

user = pwd.getpwnam("app")

if os.getuid() == 0:
    # Never through a symlink (audit-5 L2): the app can write this volume, so
    # a link it planted (state/x -> /etc/passwd) would have root hand the
    # target to `app` on the next start. os.walk does not descend into
    # linked directories; lchown changes the link itself, not its target.
    for root, dirs, files in os.walk(STATE):
        for name in [root, *(os.path.join(root, n) for n in dirs + files)]:
            os.chown(name, user.pw_uid, user.pw_gid, follow_symlinks=False)
    os.setgroups([])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)

os.environ["HOME"] = STATE
# No access log and no proxy headers (audit-5 L11): an access line beside
# a grant's second ties a client address to a public shield, and with
# proxy headers on, any proxy on 127.0.0.1 would put the client's real
# address there. The client the rate limits key by comes from
# CF-Connecting-IP (services/ratelimit), never from uvicorn.
os.execvp("uvicorn", ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000",
                      "--no-access-log", "--no-proxy-headers"])
