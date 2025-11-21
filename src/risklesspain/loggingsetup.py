# -*- coding: utf-8 -*-
#  Copyright 2021 Pentagrid AG
import logging

COLOR_ANSI_CODE = {  # ANSI codes
    logging.WARNING: "93",  # bright yellow foreground color
    logging.ERROR: "91",  # bright red foreground color
    logging.CRITICAL: "91",  # bright red foreground color
}

class LoggingFormatter(logging.Formatter):
    def __init__(self, disable_color=False):
        super().__init__()
        self.disable_color = disable_color

    def format(self, record):
        # Determine prefix and suffix for colours first
        prefix = ""
        suffix = ""
        if record.levelno not in (logging.NOTSET, logging.DEBUG, logging.INFO) and not self.disable_color:
            color = COLOR_ANSI_CODE.get(record.levelno, 0)
            prefix = f"\033[{color}m"
            suffix = "\033[0m"

        if record.levelno <= logging.DEBUG:
            self._style._fmt = f"{prefix}[D] - %(threadName)s - %(asctime)s - %(filename)s:%(lineno)s - %(funcName)s(): %(message)s{suffix}"
        elif record.levelno in (logging.INFO, ):
            self._style._fmt = f"{prefix}%(message)s{suffix}"
        else:
            self._style._fmt = f"{prefix}[%(levelname)s]: %(message)s{suffix}"
        return super().format(record)


def get_default_logging_command_line_handler() -> logging.Handler:
    # log to stdout instead of stderr

    return ch
