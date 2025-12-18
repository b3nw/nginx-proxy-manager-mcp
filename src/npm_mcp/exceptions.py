"""Custom exceptions for NPM API client."""


class NpmClientError(Exception):
    """Base exception for NPM client errors."""

    pass


class NpmAuthenticationError(NpmClientError):
    """Raised when authentication fails."""

    pass


class NpmConnectionError(NpmClientError):
    """Raised when connection to NPM fails."""

    pass


class NpmNotFoundError(NpmClientError):
    """Raised when a resource is not found."""

    pass


class NpmApiError(NpmClientError):
    """Raised for general API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code
