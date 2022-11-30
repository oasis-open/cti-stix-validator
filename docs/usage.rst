Usage
=====

As A Script
-----------

The validator comes with a bundled script which you can use to
validate a JSON file containing STIX content:

::

  $ stix2_validator <stix_file.json>

As A Library
------------

You can also use this library to integrate STIX validation into your
own tools. You can validate a JSON file:

.. code:: python

  from stix2validator import validate_file, print_results

  results = validate_file("stix_file.json")
  print_results(results)

You can also validate a JSON string, and check if the input passed
validation:

.. code:: python

  from stix2validator import validate_string, print_results

  stix_json_string = "..."
  results = validate_string(stix_json_string)
  if results.is_valid:
      print_results(results)

If your STIX is already in a Python dictionary (for example if you
have already run ``json.loads()``), use ``validate_instance()`` instead:

.. code:: python

  import json
  from stix2validator import validate_instance, print_results

  stix_json_string = "..."
  stix_obj = json.loads(stix_json_string)
  results = validate_instance(stix_obj)
  if results.is_valid:
      print_results(results)

You can pass a ValidationOptions object into ``validate_file()``,
``validate_string()``, or ``validate_instance()`` if you want behavior
other than the default:

.. code:: python

  from stix2validator import ValidationOptions

  options = ValidationOptions(strict=True)
  results = validate_string(stix_json_string, options)

STIX 2 Versions
---------------

By default the validator will check content against the latest version of
the STIX 2 specification. However, older versions can be checked with the
``version`` option. For example:

::

  $ stix2_validator --version=2.0 <stix_file.json>

or in Python:

.. code:: python

  options = ValidationOptions(strict=True, version="2.0")
  results = validate_string(stix_json_string, options)

Additional Schemas
------------------

The validator uses the `STIX 2 JSON schemas <https://github.com/oasis-open/cti-stix2-
json-schemas>`_ as the basis for its validation, but you can also validate with
your own additional schemas. This can help if you want to validate STIX content
using extensions or (now deprecated) custom objects, properties, or observables.

To do this use the ``--schemas`` argument:

::

  $ stix2_validator --schemas /path/to/my/schemas <stix_file.json>

or in Python, using ``schema_dir``:

.. code:: python

  from stix2validator import ValidationOptions

  options = ValidationOptions(strict=True, version="2.1", schema_dir="/path/to/custom/schemas")
  results = validate_file("stix_file.json")
  print_results(results)

You can see some examples of custom schemas `here <https://github.com/oasis-open/cti-stix-validator/tree/master/stix2validator/test/v21/test_schemas>`_.

.. note::
  The schema's filename must match the extension definition id of the extension
  it describes so the validator can apply it correctly. For example, a schema
  defining a new extension with an id of
  ``extension-definition--bfaece0b-efa6-4dfa-8248-3d340e2030f8`` should be named
  `extension-definition--bfaece0b-efa6-4dfa-8248-3d340e2030f8.json`.

.. note::
  Custom objects and properties using the ``x_`` and ``x-`` prefixes have been
  deprecated in STIX 2.1. However, if you need a schema for validating them, the
  validator can parse it as long as the schema's filename matches the type name
  of the STIX object type it should apply to. For example, a schema defining a
  new property on Indicators should be named ``indicator.json``. A schema
  defining a new object type, “my-cool-thing”, would need to be named
  ``my-cool-thing.json``.

.. note::
  When using additional schemas, the validator's built-in schemas are still
  checked against. Thus custom schemas only need to contain the properties that
  differ from the standard.
