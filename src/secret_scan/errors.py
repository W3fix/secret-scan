class SecretScanError(Exception):
    """A usage or configuration problem. The CLI reports it and exits 2.

    Messages must never contain file content: they can end up in CI logs.
    """
