import logging
import time

from third_lib.sqlmap.lib.core.data import conf


class LogRecorder(logging.StreamHandler):
    def emit(self, record):
        """
        Record emitted events to IPC database for asynchronous I/O
        communication with the parent process
        """
        conf.databaseCursor.execute("INSERT INTO logs VALUES(NULL, ?, ?, ?, ?)", 
                                    (conf.taskid, time.strftime("%X"), 
                                     record.levelname, 
                                     str(record.msg % record.args if
                                         record.args else record.msg)))
