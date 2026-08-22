import logging
from config import Config

def get_logger(name: str):
    return logging.getLogger(name)
