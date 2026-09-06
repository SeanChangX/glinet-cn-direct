"""Exception types shared across the pipeline."""


class GlinetRulesError(Exception):
    """Base class for every error this package raises deliberately."""


class ConfigError(GlinetRulesError):
    """Configuration on disk is missing, malformed or self-inconsistent."""


class FetchError(GlinetRulesError):
    """An upstream download failed, or returned something we refuse to trust."""


class SecurityGateError(GlinetRulesError):
    """A fail-closed gate rejected the candidate output.

    Raising this must always leave the previously published artifacts untouched.
    """

    def __init__(self, gate: str, detail: str) -> None:
        super().__init__(f"{gate}: {detail}")
        self.gate = gate
        self.detail = detail
