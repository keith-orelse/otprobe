"""Low-level network access. The ONLY package in OTProbe allowed to import sockets, subprocess or network
libraries (enforced by tests/unit/test_live_safety.py). Everything that sends a packet does it inside
``NetworkGate.permit``."""
