README
======

.. _readme-general:

`OASIS Open Repository: cti-stix-validator`
-------------------------------------------
This GitHub public repository ( `https://github.com/oasis-open/cti-stix-validator <https://github.com/oasis-open/cti-stix-validator>`_ ) was created at the request of the `OASIS Cyber Threat Intelligence (CTI) TC <https://www.oasis-open.org/committees/cti/>`_ as an `OASIS Open Repository <https://www.oasis-open.org/resources/open-repositories/>`_ to support development of open source resources related to Technical Committee work.

While this Open Repository remains associated with the sponsor TC, its development priorities, leadership, intellectual property terms, participation rules, and other matters of governance are `separate and distinct <https://github.com/oasis-open/cti-stix-validator/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-process>`_ from the OASIS TC Process and related policies.

All contributions made to this Open Repository are subject to open source license terms expressed in the `BSD-3-Clause License <https://www.oasis-open.org/sites/www.oasis-open.org/files/BSD-3-Clause.txt>`_. That license was selected as the declared `"Applicable License" <https://www.oasis-open.org/resources/open-repositories/licenses>`_ when the Open Repository was created.

As documented in `"Public Participation Invited" <https://github.com/oasis-open/cti-stix-validator/blob/master/CONTRIBUTING.md#public-participation-invited>`_, contributions to this OASIS Open Repository are invited from all parties, whether affiliated with OASIS or not. Participants must have a GitHub account, but no fees or OASIS membership obligations are required. Participation is expected to be consistent with the `OASIS Open Repository Guidelines and Procedures <https://www.oasis-open.org/policies-guidelines/open-repositories>`_, the open source `LICENSE <https://github.com/oasis-open/cti-stix-validator/blob/master/LICENSE>`_ designated for this particular repository, and the requirement for an `Individual Contributor License Agreement <https://www.oasis-open.org/resources/open-repositories/cla/individual-cla>`_ that governs intellectual property.

.. _purposeStatement:

`Statement of Purpose`
----------------------
Statement of Purpose for this OASIS Open Repository (cti-stix-validator) as `proposed <https://lists.oasis-open.org/archives/cti/201609/msg00001.html>`_ and `approved <https://www.oasis-open.org/committees/ballot.php?id=2971>`_ [`bis <https://issues.oasis-open.org/browse/TCADMIN-2434>`_] by the TC:

The STIX validator checks that STIX JSON content conforms to the requirements specified in the STIX 2.0 specification. In addition to checking conformance with the JSON schemas, the validator checks conformance with requirements that cannot be specified in JSON schema, as well as with established "best practices." This validator is non-normative; in cases of conflict with the STIX 2.0 specification, the specification takes precedence.

.. _purposeClarifications:

`Additions to Statement of Purpose`
-----------------------------------
Some requirements in the STIX 2.0 specification are mandatory; others are merely recommended. The validator checks documents against the mandatory requirements using JSON schemas. Some of the mandatory requirements cannot be implemented in JSON Schema, however, so the validator uses Python functions to check these. The recommended requirements are all checked by Python functions, and options can be set to ignore all or some of these recommended "best practices." 

The only exception to this is the mandatory requirement that an object's 'type' be one of those defined by a STIX Object in the specification. This rules out custom objects, so this check was made optional.

The validator also color-codes its output to make it easier to tell at a glance whether validation passed.

.. _usage:

`Usage`
,,,,,,,

**As A Script**

The validator comes with a bundled script which you can use to validate a JSON file containing STIX content:

::

  $ stix2_validator <stix_file.json>

**As A Library**

You can also use this library to integrate STIX validation into your own tools. You can validate a JSON file:

.. code:: python

  from stix2validator import validate_file
  from stix2validator.output import print_results

  results = validate_file("stix_file.json")
  print_results(results)

You can also validate a JSON string, and check if the input passed validation:

.. code:: python

  from stix2validator import validate_string
  from stix2validator.output import print_results

  stix_json_string = "..."
  results = validate_string(stix_json_string)
  if results.is_valid:
      print_results(results)

.. _maintainers:

`Maintainers`
-------------
Open Repository `Maintainers <https://www.oasis-open.org/resources/open-repositories/maintainers-guide>`__ are responsible for oversight of this project's community development activities, including evaluation of GitHub `pull requests <https://github.com/oasis-open/cti-stix-validator/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model>`_ and `preserving <https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement>`_ open source principles of openness and fairness. Maintainers are recognized and trusted experts who serve to implement community goals and consensus design preferences.

Initially, the associated TC members have designated one or more persons to serve as Maintainer(s); subsequently, participating community members may select additional or substitute Maintainers, per `consensus agreements <https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers>`_.

.. _currentMaintainers:

**Current Maintainers of this Open Repository**

.. Initial Maintainers: Greg Back & Ivan Kirillov

*  `Greg Back <mailto:gback@mitre.org>`_; GitHub ID: `https://github.com/gtback <https://github.com/gtback>`_; WWW: `MITRE <https://www.mitre.org>`__
*  `Ivan Kirillov <mailto:ikirillov@mitre.org>`_; GitHub ID: `https://github.com/ikiril01 <https://github.com/ikiril01>`_; WWW: `MITRE <https://www.mitre.org>`__

.. _aboutOpenRepos:

`About OASIS Open Repositories`
-------------------------------
*  `Open Repositories: Overview and Resources <https://www.oasis-open.org/resources/open-repositories/>`_
*  `Frequently Asked Questions <https://www.oasis-open.org/resources/open-repositories/faq>`_
*  `Open Source Licenses <https://www.oasis-open.org/resources/open-repositories/licenses>`_
*  `Contributor License Agreements (CLAs) <https://www.oasis-open.org/resources/open-repositories/cla>`_
*  `Maintainers' Guidelines and Agreement <https://www.oasis-open.org/resources/open-repositories/maintainers-guide>`__

.. _feedback:

`Feedback`
----------
Questions or comments about this Open Repository's activities should be composed as GitHub issues or comments. If use of an issue/comment is not possible or appropriate, questions may be directed by email to the Maintainer(s) `listed above <#currentMaintainers>`_. Please send general questions about Open Repository participation to OASIS Staff at `repository-admin@oasis-open.org <mailto:repository-admin@oasis-open.org>`_ and any specific CLA-related questions to `repository-cla@oasis-open.org <mailto:repository-cla@oasis-open.org>`_.
