"""orch-apps host: shares under /s/<id>/ and mini apps under /<slug>/ on one VPS.

Everything that changes the server arrives through the forced SSH command (bin/orch-apps-gate) and is run by
`orch-apps-host` (cli.py) with root rights through one sudoers line. The share server (server.py) runs as the
unprivileged user orch-apps-web and only reads.
"""

__version__ = "0.1.0"
