"""
Basic Logger for the ShipIn demo app
"""
import logging
import traceback

shipin_logger = logging.getLogger()
logging.basicConfig(format='[SHIPIN_REPORTER] %(asctime)s %(message)s')
shipin_logger.setLevel(logging.INFO)

def info(message):
    """
    Log an INFO level message
    """
    return shipin_logger.info(f"[INFO] {message}")

def debug(message):
    """
    Log a DEBUG level message
    """
    return shipin_logger.debug(f"[DEBUG] {message}")

def error(message):
    """
    Log an ERROR level message
    """
    return shipin_logger.error(f"[ERROR] {message}")

def logException(err):
    """
    Log an Exception message
    
    Args:
        err(Exception): The exception that we will extract the message from
    """
    err_msg = str(getattr(err, 'message', repr(err)))
    err_trace = ""
    if err.__traceback__:
        err_trace = ''.join(traceback.format_tb(err.__traceback__))
    shipin_logger.error(" [*ERROR*] : " + err_msg + "\n" + err_trace)
