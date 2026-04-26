"""Domain exceptions for Context Integrity Gate."""


class ContextRejection(Exception):
    """Raised when context fails canonicalization, validation, or policy checks."""


class PersistenceError(Exception):
    """Raised when persistence of trusted context fails."""
