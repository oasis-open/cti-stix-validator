"""Exit status codes
"""

#: Execution finished successfully. All STIX documents were valid for all user-
#: specified validation scenarios.
EXIT_SUCCESS = 0x0

#: Execution finished with fatal system error. Some unhandled system exception
#: was raised during execution.
EXIT_FAILURE = 0x1

#: Execution finished with at least one input document found to be schema-
#: invalid.
EXIT_SCHEMA_INVALID = 0x2

#: An error occurred while validating an instance document. This can be caused
#: by malformed input documents or file names that do not resolve to actual
#: files.
EXIT_VALIDATION_ERROR = 0x10


def get_code(results):
    """Determines the exit status code to be returned from a script by
    inspecting the results returned from validating file(s).
    Status codes are binary OR'd together, so exit codes can communicate
    multiple error conditions.

    """
    status = EXIT_SUCCESS

    for file_result in results:
        error = any(object_result.errors for object_result in file_result.object_results)

        fatal = file_result.fatal

        if error:
            status |= EXIT_SCHEMA_INVALID
        if fatal:
            status |= EXIT_VALIDATION_ERROR

    return status
