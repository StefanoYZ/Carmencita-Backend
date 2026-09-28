from collections.abc import Callable

from fastapi import FastAPI


integration_registrars: tuple[Callable[[FastAPI], None], ...] = ()


def register_integrations(application: FastAPI) -> None:
    """Register external integrations without connecting to providers."""
    for registrar in integration_registrars:
        registrar(application)
