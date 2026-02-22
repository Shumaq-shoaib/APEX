import sys
import logging
import json
from datetime import datetime
from app.core import config

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName
        }
        # Merge extra fields
        if hasattr(record, "props"):
            log_obj.update(record.props)
        
        return json.dumps(log_obj)

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(config.LOG_LEVEL)
    
    handler = logging.StreamHandler(sys.stdout)
    
    if config.LOG_FORMAT.lower() == "json":
        handler.setFormatter(JSONFormatter())
    else:
        # Development friendly format
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
    
    # Remove existing handlers to avoid duplicates
    logger.handlers = []
    logger.addHandler(handler)
    
    # Silence noisy libraries
    logging.getLogger("uvicorn.access").handlers = []
    logging.getLogger("uvicorn.access").propagate = False 

class StructuredLogger:
    def __init__(self, name):
        self.logger = logging.getLogger(name)
    
    def info(self, msg, **kwargs):
        self.logger.info(msg, extra={"props": kwargs})
    
    def error(self, msg, **kwargs):
        self.logger.error(msg, extra={"props": kwargs})
    
    def warning(self, msg, **kwargs):
        self.logger.warning(msg, extra={"props": kwargs})
    
    def debug(self, msg, **kwargs):
        self.logger.debug(msg, extra={"props": kwargs})

def get_logger(name):
    return StructuredLogger(name)
