import logging
import sys


def setup_logger(name="ghost_mapper", level=logging.INFO):
    """Configure and return a logger instance for the application.

    Args:
        name: Logger name identifier.
        level: Logging level (default: INFO).

    Returns:
        Configured logger instance with console output.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid adding duplicate handlers if logger already configured
    if logger.handlers:
        return logger

    # Console handler with formatted output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    formatter = logging.Formatter(
        "\033[90m[\033[36m%(asctime)s\033[90m]\033[0m \033[32m%(levelname)s\033[0m \033[90m»\033[0m %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
