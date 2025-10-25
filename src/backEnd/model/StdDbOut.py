import sys

from third_lib.sqlmap.lib.core.enums import CONTENT_STATUS
from third_lib.sqlmap.lib.core.data import kb
from third_lib.sqlmap.lib.core.dicts import PART_RUN_CONTENT_TYPES
from third_lib.sqlmap.lib.core.data import conf
from third_lib.sqlmap.lib.core.compat import xrange
from third_lib.sqlmap.lib.core.convert import dejsonize
from third_lib.sqlmap.lib.core.convert import jsonize


# Wrapper functions for sqlmap engine
class StdDbOut(object):
    def __init__(self, taskid, messagetype="stdout"):
        # Overwrite system standard output and standard error to write
        # to an IPC database
        self.messagetype = messagetype
        self.taskid = taskid

        if self.messagetype == "stdout":
            sys.stdout = self
        else:
            sys.stderr = self

    def write(self, value, status=CONTENT_STATUS.IN_PROGRESS, content_type=None):
        if self.messagetype == "stdout":
            if content_type is None:
                if kb.partRun is not None:
                    content_type = PART_RUN_CONTENT_TYPES.get(kb.partRun)
                else:
                    # Ignore all non-relevant messages
                    return

            output = conf.databaseCursor.execute("SELECT id, status, value FROM data WHERE taskid = ? AND content_type = ?", (self.taskid, content_type))

            # Delete partial output from IPC database if we have got a complete output
            if status == CONTENT_STATUS.COMPLETE:
                if len(output) > 0:
                    for index in xrange(len(output)):
                        conf.databaseCursor.execute("DELETE FROM data WHERE id = ?", (output[index][0],))

                conf.databaseCursor.execute("INSERT INTO data VALUES(NULL, ?, ?, ?, ?)", (self.taskid, status, content_type, jsonize(value)))
                if kb.partRun:
                    kb.partRun = None

            elif status == CONTENT_STATUS.IN_PROGRESS:
                if len(output) == 0:
                    conf.databaseCursor.execute("INSERT INTO data VALUES(NULL, ?, ?, ?, ?)", (self.taskid, status, content_type, jsonize(value)))
                else:
                    new_value = "%s%s" % (dejsonize(output[0][2]), value)
                    conf.databaseCursor.execute("UPDATE data SET value = ? WHERE id = ?", (jsonize(new_value), output[0][0]))
        else:
            conf.databaseCursor.execute("INSERT INTO errors VALUES(NULL, ?, ?)", (self.taskid, str(value) if value else ""))

    def flush(self):
        pass

    def close(self):
        pass

    def seek(self):
        pass