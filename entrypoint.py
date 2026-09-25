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
    for root, dirs, files in os.walk(STATE):
        for name in [root, *(os.path.join(root, n) for n in dirs + files)]:
            os.chown(name, user.pw_uid, user.pw_gid)
    os.setgroups([])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)

os.environ["HOME"] = STATE
os.execvp("uvicorn", ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"])
