import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "security_events.log")

os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("DynamicFirewall")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    handler = logging.FileHandler(LOG_FILE)
    handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(handler)


def log_event(event):
    logger.info(event)
