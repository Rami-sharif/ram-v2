"""Logging configuration.

Python's logging works as a tree: every module's logger ultimately feeds the single
"root" logger. Configure the root once (a handler = WHERE lines go, a formatter = how
they LOOK, a level = the minimum severity to keep) and every module inherits it. We
deliberately never log secret values (API keys) or full request bodies that might
contain them.
"""
# Standard library logging framework used for all app logging.
import logging
# sys.stdout is the program's standard output stream; we log there so Docker/other
# container tools, which capture stdout, pick the logs up automatically.
import sys


# Sets up the root logger once; `level` is a string like "INFO"/"DEBUG" from settings.
def configure_logging(level: str = "INFO") -> None:
    # getLogger() with no name returns the ROOT logger — configuring it affects every logger.
    root = logging.getLogger()
    if root.handlers:  # avoid duplicate handlers on reload
        # If handlers already exist, this ran before (e.g. the dev server re-imported the
        # module on reload). Returning now prevents attaching a second handler, which would
        # otherwise print every log line twice.
        return
    # A "handler" decides where log records go. StreamHandler(sys.stdout) sends them to
    # standard output.
    handler = logging.StreamHandler(sys.stdout)
    # A "formatter" defines the text layout of each line. The %(...)s placeholders are
    # filled in by logging: asctime=timestamp, levelname=severity (padded to 8 chars),
    # name=which logger emitted it, message=the actual text.
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    # Attach the handler to the root logger so all child loggers route through it.
    root.addHandler(handler)
    # The level is the minimum severity that gets logged (DEBUG < INFO < WARNING < ...).
    # .upper() lets an env value like "info" work as well as "INFO".
    root.setLevel(level.upper())
    # Quiet noisy libraries a notch.
    # httpx logs every outbound HTTP call at INFO; bump to WARNING to reduce noise.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    # uvicorn's access log is useful, so keep it at INFO explicitly (in case root level is higher).
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
