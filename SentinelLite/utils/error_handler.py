import logging
import sys
import traceback
from pathlib import Path


DEFAULT_LOG = Path(__file__).resolve().parents[1] / "runtime_errors.log"


def setup_global_exception_handler(log_path=DEFAULT_LOG):
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=True)

    logging.basicConfig(
        filename=str(log_path),
        level=logging.ERROR,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    def handle_exception(exc_type, exc, tb):
        logging.error("Unhandled exception", exc_info=(exc_type, exc, tb))
        message = "".join(traceback.format_exception(exc_type, exc, tb))
        print(message, file=sys.stderr)

    sys.excepthook = handle_exception


def log_exception(message, exc):
    logging.error(message, exc_info=exc)


def log_exception_info(message, exc_type, exc, tb):
    logging.error(message, exc_info=(exc_type, exc, tb))
