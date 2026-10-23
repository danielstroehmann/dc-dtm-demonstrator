def pytest_configure(config):
    """Never print local variables of live tests – they may hold the API key."""
    config.option.showlocals = False
    if config.option.tbstyle in ("auto", "long"):
        config.option.tbstyle = "short"
