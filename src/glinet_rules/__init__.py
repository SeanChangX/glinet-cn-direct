"""Generate auditable, fail-closed GL.iNet routing rules from upstream datasets.

The pipeline is deliberately linear and side-effect free until the very last
step:

    fetch -> normalize -> validate -> compare -> security gates -> write

Every stage can only ever *reject*. Nothing in this package repairs, guesses at
or silently drops upstream data, because a false positive here routes traffic
that the user expects to be inside a VPN tunnel around that tunnel instead.
"""

__version__ = "1.0.0"

GENERATOR_NAME = "glinet-cn-direct"
