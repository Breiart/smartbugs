import multiprocessing, threading, os, sys, time, re
import sb.colors, sb.cfg

def logger_process(logfn, overwrite, queue, prolog):
    log_parent_folder = os.path.dirname(logfn)
    if log_parent_folder:
        os.makedirs(log_parent_folder, exist_ok=True)
    mode = "w" if overwrite else "a"
    with open(logfn, mode) as logfile:
        for log in prolog:
            print(log, file=logfile)
        while True:
            log = queue.get()
            if log is None:
                break
            print(log, file=logfile)

__prolog = []

def start(logfn, append, queue):
    """Start the asynchronous logger thread.

    Flushes any messages buffered before startup (prolog) once, and then
    clears the buffer to avoid duplicating prolog entries if logging is
    restarted later in the same process (e.g., during a second orchestration
    phase).
    """
    global logger, __prolog
    # Snapshot and clear prolog to avoid duplicate headers on subsequent starts
    prolog_snapshot = list(__prolog)
    __prolog = []
    logger = threading.Thread(target=logger_process, args=(logfn,append,queue,prolog_snapshot))
    logger.start()

quiet = False

def message(con=None, log=None, queue=None):
    """Unified console and file logging with basic level filtering.

    - If `log` is one of {"DEBUG", "INFO", "ERROR", ""}, it is treated as a
      level tag; otherwise it is treated as an explicit string to log to file.
    - DEBUG messages are suppressed in the log file unless sb.cfg.DEBUG is True.
    - If `log` is not an explicit string, the console text (stripped of ANSI)
      is written to the file.
    """
    # Determine logging level and text
    levels = {"DEBUG", "INFO", "ERROR", ""}
    level = log if isinstance(log, str) and log in levels else None
    to_file = None

    if isinstance(log, str) and log not in levels:
        # `log` is an explicit message destined for the file
        to_file = log
    elif con:
        # Fallback to the console message content
        to_file = sb.colors.strip(con)

    # Console output (suppress DEBUG unless debug mode)
    if con and not quiet:
        if level == "DEBUG" and not sb.cfg.DEBUG:
            pass
        else:
            print(con, flush=True)

    # Apply simple level filtering for file logs
    if level == "DEBUG" and not sb.cfg.DEBUG:
        return

    if to_file:
        if queue:
            queue.put(to_file)
        else:
            __prolog.append(to_file)

def stop(queue):
    queue.put(None)
    logger.join()
