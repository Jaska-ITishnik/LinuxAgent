"""Safe application-level errors shared across interfaces and services."""
from __future__ import annotations


class ApplicationError(RuntimeError):
    """An expected application failure with a non-sensitive user-facing message."""

    def __init__(self, code: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message


class ToolExecutionError(ApplicationError):
    """A tool failure with a safe, user-facing status."""


class AuthorizationCancelled(ApplicationError):
    """A trusted user explicitly cancelled a pending tool approval."""


class ApprovalInterfaceError(ApplicationError):
    """A trusted approval UI failed and the requested action was denied."""
