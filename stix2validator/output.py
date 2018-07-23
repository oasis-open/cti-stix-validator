import logging
import operator
import sys

from colorama import Fore, Style, init

from . import codes

init(autoreset=True)
_GREEN = Fore.GREEN
_YELLOW = Fore.YELLOW
_RED = Fore.RED + Style.BRIGHT
_VERBOSE = False
_SILENT = False

logger = logging.getLogger(__name__)


def set_level(verbose_output=False):
    """Set the output level for the application.
    If ``verbose_output`` is False then the application does not print
    informational messages to stdout; only results or fatal errors are printed
    to stdout.
    """
    global _VERBOSE
    _VERBOSE = verbose_output


def set_silent(silence_output=False):
    """Set the silent flag for the application.
    If ``silence_output`` is True then the application does not print
    any messages to stdout.
    """
    global _SILENT
    _SILENT = silence_output


def error(msg, status=codes.EXIT_FAILURE):
    """Prints a message to the stderr prepended by '[X]' and calls
    ```sys.exit(status)``.

    Args:
        msg: The error message to print.
        status: The exit status code. Defaults to ``EXIT_FAILURE`` (1).

    """
    logger.error(_RED + "[X] %s\n" % str(msg))
    sys.exit(status)


def info(msg):
    """Prints a message to stdout, prepended by '[-]'.

    Note:
        If the application is not running in verbose mode, this function will
        return immediately and no message will be printed.

    Args:
        msg: The message to print.

    """
    if not _VERBOSE:
        return

    logger.debug("[-] %s" % msg)


def print_level(log_function, fmt, level, *args):
    """Prints a formatted message to stdout prepended by spaces. Useful for
    printing hierarchical information, like bullet lists.

    Note:
        If the application is running in "Silent Mode"
        (i.e., ``_SILENT == True``), this function will return
        immediately and no message will be printed.

    Args:
        log_function: The function that will be called to output the formatted
            message.
        fmt (str): A Python formatted string.
        level (int): Used to determing how many spaces to print. The formula
            is ``'    ' * level ``.
        *args: Variable length list of arguments. Values are plugged into the
            format string.

    Examples:
        >>> print_level("%s %d", 0, "TEST", 0)
        TEST 0
        >>> print_level("%s %d", 1, "TEST", 1)
            TEST 1
        >>> print_level("%s %d", 2, "TEST", 2)
                TEST 2

    """
    if _SILENT:
        return

    msg = fmt % args
    spaces = '    ' * level
    log_function("%s%s" % (spaces, msg))


def print_fatal_results(results, level=0):
    """Prints fatal errors that occurred during validation runs.
    """
    print_level(logger.critical, _RED + "[X] Fatal Error: %s", level, results.error)


def print_schema_results(results, level=0):
    """Prints JSON Schema validation errors to stdout.

    Args:
        results: An instance of ObjectValidationResults.
        level: The level at which to print the results.

    """
    for error in results.errors:
        print_level(logger.error, _RED + "[X] %s", level, error)


def print_warning_results(results, level=0):
    """Prints warning messages found during validation.
    """
    marker = _YELLOW + "[!] "

    for warning in results.warnings:
        print_level(logger.warning, marker + "Warning: %s", level, warning)


def print_horizontal_rule():
    """Prints a horizontal rule.

    Note:
        If the application is running in "Silent Mode"
        (i.e., ``_SILENT == True``), this function will return
        immediately and nothing will be printed.
    """

    if _SILENT:
        return

    logger.info("=" * 80)


def print_results(results):
    """Prints `results` (the results of validation) to stdout.

    Args:
        results: A list of FileValidationResults instances.

    """
    if not isinstance(results, list):
        results = [results]

    if results[0].__class__.__name__ is 'FileValidationResults':
        for file_result in sorted(results, key=operator.attrgetter("filepath")):
            print_horizontal_rule()
            print_level(logger.info, "[-] Results for: %s", 0, file_result.filepath)

            if file_result.is_valid:
                marker = _GREEN + "[+]"
                verdict = "Valid"
                log_func = logger.info
            else:
                marker = _RED + "[X]"
                verdict = "Invalid"
                log_func = logger.error
            print_level(log_func, "%s STIX JSON: %s", 0, marker, verdict)

            for object_result in file_result.object_results:
                if object_result.warnings:
                    print_warning_results(object_result, 1)
                if object_result.errors:
                    print_schema_results(object_result, 1)

            if file_result.fatal:
                print_fatal_results(file_result.fatal, 1)
    elif results[0].__class__.__name__ is 'ObjectValidationResults':
        valid = True
        for obj_result in results:
            if obj_result.warnings:
                print_warning_results(obj_result)
                valid = False
            if obj_result.errors:
                print_schema_results(obj_result)
                valid = False
        if valid:
            print_level(logger.info, "STIX JSON: Valid", 0)
    else:
        raise ValueError('Argument to print_results() must be a list of '
                         'FileValidationResults or a list of ObjectValidationResults.')
