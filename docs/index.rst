Welcome to the stix2-validator documentation!
=============================================

The STIX Validator checks that STIX JSON content conforms to the
requirements specified in the STIX 2.0 specification. In addition to
checking conformance with the `JSON schemas <https://github.com/oasis-
open/cti-stix2-json-schemas>`_, the validator checks conformance with
requirements that cannot be specified in JSON schema, as well as with
established "best practices." This validator is non-normative; in
cases of conflict with the STIX 2.0 specification, the specification
takes precedence.

The STIX 2.0 specification contains two types of requirements:
mandatory "MUST" requirements, and recommended "SHOULD" best practice
requirements. The validator checks documents against the "MUST"
requirements using JSON schemas. Some of these mandatory requirements
cannot be implemented in JSON Schema, however, so the validator uses
Python functions to check them. The "SHOULD" requirements are all
checked by Python functions, and options may be used to ignore some or
all of these recommended "best practices."

The STIX Validator uses the `stix2-patterns validator
<https://github.com/oasis-open/cti-pattern-validator>`_ to check that
Indicator patterns conform to the STIX Patterning language and only
reference properties valid for the objects in the pattern.

The validator also color-codes its output to make it easier to tell at
a glance whether validation passed.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   install
   usage
   options
   best-practices


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
