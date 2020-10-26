"""
dispatcher.py
=============
The dispatcher service of Hermes that executes the DICOM transfer to the different targets.
"""
import logging
import os
import signal
import sys
from pathlib import Path
import daiquiri
import graphyte

import common.config as config
import common.helper as helper
import common.monitor as monitor
import common.version as version
from dispatch.status import has_been_send, is_ready_for_sending
from dispatch.send import execute


daiquiri.setup(
    level=logging.INFO,
    outputs=(
        daiquiri.output.Stream(
            formatter=daiquiri.formatter.ColorFormatter(
                fmt="%(color)s%(levelname)-8.8s " "%(name)s: %(message)s%(color_stop)s"
            )
        ),
    ),
)
logger = daiquiri.getLogger("dispatcher")


def receiveSignal(signalNumber, frame):
    """Function for testing purpose only. Should be removed."""
    logger.info("Received:", signalNumber)
    return


def terminateProcess(signalNumber, frame):
    """Triggers the shutdown of the service."""
    helper.g_log('events.shutdown', 1)
    logger.info("Shutdown requested")
    monitor.send_event(monitor.h_events.SHUTDOWN_REQUEST, monitor.severity.INFO)
    # Note: main_loop can be read here because it has been declared as global variable
    if 'main_loop' in globals() and main_loop.is_running:
        main_loop.stop()
    helper.triggerTerminate()


def dispatch(args):
    """ Main entry function. """
    if helper.isTerminated():
        return

    helper.g_log('events.run', 1)

    try:
        config.read_config()
    except Exception:
        logger.exception("Unable to read configuration. Skipping processing.")
        monitor.send_event(
            monitor.h_events.CONFIG_UPDATE,
            monitor.severity.WARNING,
            "Unable to read configuration (possibly locked)",
        )
        return

    success_folder = Path(config.hermes["success_folder"])
    error_folder = Path(config.hermes["error_folder"])
    retry_max = config.hermes["retry_max"]
    retry_delay = config.hermes["retry_delay"]

    with os.scandir(config.hermes["outgoing_folder"]) as it:
        for entry in it:
            if (
                entry.is_dir()
                and not has_been_send(entry.path)
                and is_ready_for_sending(entry.path)
            ):
                logger.info(f"Check if reading for {entry.path}")
                execute(Path(entry.path), success_folder, error_folder, retry_max, retry_delay)

            # If termination is requested, stop processing series after the
            # active one has been completed
            if helper.isTerminated():
                break


def exit_dispatcher(args):
    """ Stop the asyncio event loop. """
    helper.loop.call_soon_threadsafe(helper.loop.stop)


if __name__ == "__main__":
    logger.info("")
    logger.info(f"Hermes DICOM Dispatcher ver {version.hermes_version}")
    logger.info("----------------------------")
    logger.info("")

    # Register system signals to be caught
    signal.signal(signal.SIGINT, terminateProcess)
    signal.signal(signal.SIGQUIT, receiveSignal)
    signal.signal(signal.SIGILL, receiveSignal)
    signal.signal(signal.SIGTRAP, receiveSignal)
    signal.signal(signal.SIGABRT, receiveSignal)
    signal.signal(signal.SIGBUS, receiveSignal)
    signal.signal(signal.SIGFPE, receiveSignal)
    signal.signal(signal.SIGUSR1, receiveSignal)
    signal.signal(signal.SIGSEGV, receiveSignal)
    signal.signal(signal.SIGUSR2, receiveSignal)
    signal.signal(signal.SIGPIPE, receiveSignal)
    signal.signal(signal.SIGALRM, receiveSignal)
    signal.signal(signal.SIGTERM, terminateProcess)

    instance_name = "main"
    if len(sys.argv) > 1:
        instance_name = sys.argv[1]

    logger.info(sys.version)
    logger.info(f"Instance name = {instance_name}")
    logger.info(f"Dispatcher PID is: {os.getpid()}")

    try:
        config.read_config()
    except Exception:
        logger.exception("Cannot start service. Going down.")
        sys.exit(1)

    monitor.configure("dispatcher", instance_name, config.hermes["bookkeeper"])
    monitor.send_event(
        monitor.h_events.BOOT, monitor.severity.INFO, f"PID = {os.getpid()}"
    )

    graphite_prefix = "hermes.dispatcher." + instance_name

    if len(config.hermes["graphite_ip"]) > 0:
        logging.info(
            f'Sending events to graphite server: {config.hermes["graphite_ip"]}'
        )
        graphyte.init(
            config.hermes["graphite_ip"],
            config.hermes["graphite_port"],
            prefix=graphite_prefix,
        )

    logger.info(f"Dispatching folder: {config.hermes['outgoing_folder']}")

    global main_loop
    main_loop = helper.RepeatedTimer(
        config.hermes["dispatcher_scan_interval"], dispatch, exit_dispatcher, {}
    )
    main_loop.start()

    helper.g_log('events.boot', 1)

    # Start the asyncio event loop for asynchronous function calls
    helper.loop.run_forever()

    monitor.send_event(monitor.h_events.SHUTDOWN, monitor.severity.INFO)
    logging.info("Going down now")
