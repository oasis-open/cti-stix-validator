Options
=======

These are the different options that can be set, whether the validator is used
as a command-line script or as a Python library. When using the validator as a
library, these options can be passed as parameters to the ``ValidationOptions``
constructor.

+--------------------------+-----------------------+--------------------------------------------------------+
| Script                   | Library               | Description                                            |
+==========================+=======================+========================================================+
| ``FILES``                | ``files``             | A whitespace separated list of STIX files or           |
|                          |                       | directories of STIX files to validate.                 |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``-r``, ``--recursive``  | ``recursive``         | Recursively descend into input directories.            |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``-s SCHEMA_DIR``,       | ``schema_dir``        | Custom schema directory. If provided, input will be    |
| ``--schemas SCHEMA_DIR`` |                       | validated against these schemas in addition to the     |
|                          |                       | STIX schemas bundled with this script.                 |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``--version``            | ``version``           | The version of the STIX specification to validate      |
|                          |                       | against (e.g. "2.0").                                  |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``-v``, ``--verbose``    | ``verbose``           | Print informational notes and more verbose error       |
|                          |                       | messages.                                              |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``-q``, ``--silent``     | ``silent``            | Silence all output to stdout.                          |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``-d DISABLED``,         | ``disabled``          | A comma-separated list of recommended best practice    |
| ``--disable DISABLED``,  |                       | checks to skip. By default, no checks are disabled.    |
| ``--ignore DISABLED``    |                       | Example: --disable 202,210                             |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``-e ENABLED``,          | ``enabled``           | A comma-separated list of recommended best practice    |
| ``--enable ENABLED``,    |                       | checks to enable. If the --disable option is not used, |
| ``--select ENABLED``     |                       | no other checks will be run. By default, all checks    |
|                          |                       | are enabled. Example: --enable 218                     |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``--strict``             | ``strict``            | Treat warnings as errors and fail validation if any    |
|                          |                       | are found.                                             |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``--strict-types``       | ``strict_types``      | Ensure that no custom object types are used, only      |
|                          |                       | those defined in the STIX specification.               |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``--strict-properties``  | ``strict_properties`` | Ensure that no custom properties are used, only those  |
|                          |                       | defined in the STIX specification.                     |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``--no-cache``           | ``no_cache``          | Disable the caching of external source values.         |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``--refresh-cache``      | ``refresh_cache``     | Clears the cache of external source values, then       |
|                          |                       | during validation downloads them again.                |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``--clear-cache``        | ``clear_cache``       | Clear the cache of external source values after        |
|                          |                       | validation.                                            |
+--------------------------+-----------------------+--------------------------------------------------------+
| ``--enforce-refs``       | ``enforce_refs``      | Ensures that all SDOs being referenced by SROs are     |
|                          |                       | contained within the same bundle.                      |
+--------------------------+-----------------------+--------------------------------------------------------+

For the list of checks that can be used with the "enabled" or "disabled" options, see the :doc:`Best Practices page <best-practices>`.
