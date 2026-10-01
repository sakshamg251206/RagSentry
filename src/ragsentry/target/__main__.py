"""Build the target's vector index ahead of time: `python -m ragsentry.target`."""

import logging

from ragsentry.config import get_settings
from ragsentry.target.pipeline import build_index


def main() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s: %(message)s")
    build_index(settings)


if __name__ == "__main__":
    main()
