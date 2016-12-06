====================
`cti-stix-validator`
====================
*This is an `OASIS Open Repository <https://www.oasis-open.org/resources/open-repositories>`_. See the `Governance`_ section for more information.*

The STIX validator checks that STIX JSON content conforms to the requirements specified in the STIX 2.0 specification. In addition to checking conformance with the JSON schemas, the validator checks conformance with requirements that cannot be specified in JSON schema, as well as with established "best practices." This validator is non-normative; in cases of conflict with the STIX 2.0 specification, the specification takes precedence.

The STIX 2.0 specification contains two types of requirements: mandatory "MUST" requirements, and recommended "SHOULD" best practice requirements. The validator checks documents against the "MUST" requirements using JSON schemas. Some of these mandatory requirements cannot be implemented in JSON Schema, however, so the validator uses Python functions to check them. The "SHOULD" requirements are all checked by Python functions, and options may be used to ignore some or all of these recommended "best practices."

The only exception to this is the mandatory requirement that an object's 'type' be one of those defined by a STIX Object in the specification. This rules out custom objects, so this check was made optional.

The validator also color-codes its output to make it easier to tell at a glance whether validation passed.

.. _install:

`Installation`
--------------

The easiest way to install the STIX validator is with pip:

::

  $ pip install git+https://github.com/oasis-open/cti-stix-validator.git

Note that if you instead install it by cloning or downloading the repository, you will need to set up the submodules before you install it:

::

  $ git clone https://github.com/oasis-open/cti-stix-validator.git
  $ cd cti-stix-validator/
  $ git submodule update --init --recursive
  $ python setup.py install

.. _usage:

`Usage`
-------

As A Script
~~~~~~~~~~~

The validator comes with a bundled script which you can use to validate a JSON file containing STIX content:

::

  $ stix2_validator <stix_file.json>

As A Library
~~~~~~~~~~~~

You can also use this library to integrate STIX validation into your own tools. You can validate a JSON file:

.. code:: python

  from stix2validator import validate_file, print_results

  results = validate_file("stix_file.json")
  print_results(results)

You can also validate a JSON string, and check if the input passed validation:

.. code:: python

  from stix2validator import validate_string, print_results

  stix_json_string = "..."
  results = validate_string(stix_json_string)
  if results.is_valid:
      print_results(results)

You can pass in a ValidationOptions object if you want behavior other than the default:

.. code:: python

  from stix2validator import ValidationOptions

  options = ValidationOptions(strict=True)
  results = validate_string(stix_json_string, options)

.. _options:

Checking Best Practices
~~~~~~~~~~~~~~~~~~~~~~~

The validator will always validate input against all of the mandatory "MUST" requirements from the spec. By default it will issue warnings if the input fails any of the "SHOULD" recommendations, but validation will still pass. To turn these "best practice" warnings into errors and cause validation to fail, use the :code:`--strict` option with the command-line script, or create a ValidationOptions object with :code:`strict=True` when using the library.

You cannot select which of the "MUST" requirement checks will be performed; all of them will always be performed. However, you may select which of the "SHOULD" checks to perform. Use the codes from the table below to enable or disable these checks. For example, to disable the checks for the report label and tool label vocabularies, use :code:`--disable 218,222` or :code:`disabled="218,222"`. All the other checks will still be performed. Conversely, to only check that custom property names adhere to the recommended format but not run any of the other "best practice" checks, use :code:`--enable 103` or :code:`enabled="103"`.

Enabling supersedes disabling. Simultaneously enabling and disabling the same check will result in the validator performing that check.

**Recommended Best Practice Check Codes**

+--------+-----------------------------+----------------------------------------+
|**Code**|**Name**                     |**Ensures...**                          |
+--------+-----------------------------+----------------------------------------+
|   1    | format-checks               | all 1xx checks are run                 |
+--------+-----------------------------+----------------------------------------+
|  101   | custom-object-prefix        | custom object type names follow the    |
|        |                             | correct format                         |
+--------+-----------------------------+----------------------------------------+
|  102   | custom-object-prefix-lax    | same as 101 but more lenient; no       |
|        |                             | source identifier needed in prefix     |
+--------+-----------------------------+----------------------------------------+
|  103   | custom-property-prefix      | custom object property names follow    |
|        |                             | the correct format                     |
+--------+-----------------------------+----------------------------------------+
|  104   | custom-property-prefix-lax  | same as 103 but more lenient; no       |
|        |                             | source identifier needed in prefix     |
+--------+-----------------------------+----------------------------------------+
|  111   | open-vocab-format           | values of open vocabularies follow the |
|        |                             | correct format                         |
+--------+-----------------------------+----------------------------------------+
|  121   | kill-chain-names            | kill-chain-phase name and phase follow |
|        |                             | the correct format                     |
|        |                             |                                        |
+--------+-----------------------------+----------------------------------------+
|   2    | approved-values             | all 2xx checks are run                 |
+--------+-----------------------------+----------------------------------------+
|  210   | all-vocabs                  | all of the following open vocabulary   |
|        |                             | checks are run                         |
+--------+-----------------------------+----------------------------------------+
|  211   | attack-motivation           | certain property values are from the   |
|        |                             | attack_motivation vocabulary           |
+--------+-----------------------------+----------------------------------------+
|  212   | attack-resource-level       | certain property values are from the   |
|        |                             | attack_resource_level vocabulary       |
+--------+-----------------------------+----------------------------------------+
|  213   | identity-class              | certain property values are from the   |
|        |                             | identity_class vocabulary              |
+--------+-----------------------------+----------------------------------------+
|  214   | indicator-label             | certain property values are from the   |
|        |                             | indicator_label vocabulary             |
+--------+-----------------------------+----------------------------------------+
|  215   | industry-sector             | certain property values are from the   |
|        |                             | industry_sector vocabulary             |
+--------+-----------------------------+----------------------------------------+
|  216   | malware-label               | certain property values are from the   |
|        |                             | malware_label vocabulary               |
+--------+-----------------------------+----------------------------------------+
|  217   | pattern-lang                | certain property values are from the   |
|        |                             | pattern_lang vocabulary                |
+--------+-----------------------------+----------------------------------------+
|  218   | report-label                | certain property values are from the   |
|        |                             | report_label vocabulary                |
+--------+-----------------------------+----------------------------------------+
|  219   | threat-actor-label          | certain property values are from the   |
|        |                             | threat_actor_label vocabulary          |
+--------+-----------------------------+----------------------------------------+
|  220   | threat-actor-role           | certain property values are from the   |
|        |                             | threat_actor_role vocabulary           |
+--------+-----------------------------+----------------------------------------+
|  221   | threat-actor-sophistication | certain property values are from the   |
|        |                             | threat_actor_sophistication vocabulary |
+--------+-----------------------------+----------------------------------------+
|  222   | tool-label                  | certain property values are from the   |
|        |                             | tool_label vocabulary                  |
+--------+-----------------------------+----------------------------------------+
|  229   | marking-definition-type     | marking definitions use a valid        |
|        |                             | definition_type                        |
+--------+-----------------------------+----------------------------------------+
|  250   | relationship-types          | relationships are among those defined  |
|        |                             | in the specification                   |
+--------+-----------------------------+----------------------------------------+

Governance
==========

This GitHub public repository ( `https://github.com/oasis-open/cti-stix-validator <https://github.com/oasis-open/cti-stix-validator>`_ ) was `proposed <https://lists.oasis-open.org/archives/cti/201609/msg00001.html>`_ and `approved <https://www.oasis-open.org/committees/ballot.php?id=2971>`_ [`bis <https://issues.oasis-open.org/browse/TCADMIN-2434>`_] by the `OASIS Cyber Threat Intelligence (CTI) TC <https://www.oasis-open.org/committees/cti/>`_ as an `OASIS Open Repository <https://www.oasis-open.org/resources/open-repositories/>`_ to support development of open source resources related to Technical Committee work.

While this Open Repository remains associated with the sponsor TC, its development priorities, leadership, intellectual property terms, participation rules, and other matters of governance are `separate and distinct <https://github.com/oasis-open/cti-stix-validator/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-process>`_ from the OASIS TC Process and related policies.

All contributions made to this Open Repository are subject to open source license terms expressed in the `BSD-3-Clause License <https://www.oasis-open.org/sites/www.oasis-open.org/files/BSD-3-Clause.txt>`_. That license was selected as the declared `"Applicable License" <https://www.oasis-open.org/resources/open-repositories/licenses>`_ when the Open Repository was created.

As documented in `"Public Participation Invited" <https://github.com/oasis-open/cti-stix-validator/blob/master/CONTRIBUTING.md#public-participation-invited>`_, contributions to this OASIS Open Repository are invited from all parties, whether affiliated with OASIS or not. Participants must have a GitHub account, but no fees or OASIS membership obligations are required. Participation is expected to be consistent with the `OASIS Open Repository Guidelines and Procedures <https://www.oasis-open.org/policies-guidelines/open-repositories>`_, the open source `LICENSE <https://github.com/oasis-open/cti-stix-validator/blob/master/LICENSE>`_ designated for this particular repository, and the requirement for an `Individual Contributor License Agreement <https://www.oasis-open.org/resources/open-repositories/cla/individual-cla>`_ that governs intellectual property.

.. _maintainers:

`Maintainers`
=============
Open Repository `Maintainers <https://www.oasis-open.org/resources/open-repositories/maintainers-guide>`__ are responsible for oversight of this project's community development activities, including evaluation of GitHub `pull requests <https://github.com/oasis-open/cti-stix-validator/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model>`_ and `preserving <https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement>`_ open source principles of openness and fairness. Maintainers are recognized and trusted experts who serve to implement community goals and consensus design preferences.

Initially, the associated TC members have designated one or more persons to serve as Maintainer(s); subsequently, participating community members may select additional or substitute Maintainers, per `consensus agreements <https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers>`_.

.. _currentMaintainers:

**Current Maintainers of this Open Repository**

.. Initial Maintainers: Greg Back & Ivan Kirillov

*  `Greg Back <mailto:gback@mitre.org>`_; GitHub ID: `https://github.com/gtback <https://github.com/gtback>`_; WWW: `MITRE <https://www.mitre.org>`__
*  `Ivan Kirillov <mailto:ikirillov@mitre.org>`_; GitHub ID: `https://github.com/ikiril01 <https://github.com/ikiril01>`_; WWW: `MITRE <https://www.mitre.org>`__

.. _aboutOpenRepos:

`About OASIS Open Repositories`
===============================
*  `Open Repositories: Overview and Resources <https://www.oasis-open.org/resources/open-repositories/>`_
*  `Frequently Asked Questions <https://www.oasis-open.org/resources/open-repositories/faq>`_
*  `Open Source Licenses <https://www.oasis-open.org/resources/open-repositories/licenses>`_
*  `Contributor License Agreements (CLAs) <https://www.oasis-open.org/resources/open-repositories/cla>`_
*  `Maintainers' Guidelines and Agreement <https://www.oasis-open.org/resources/open-repositories/maintainers-guide>`__

.. _feedback:

`Feedback`
==========
Questions or comments about this Open Repository's activities should be composed as GitHub issues or comments. If use of an issue/comment is not possible or appropriate, questions may be directed by email to the Maintainer(s) `listed above <#currentMaintainers>`_. Please send general questions about Open Repository participation to OASIS Staff at `repository-admin@oasis-open.org <mailto:repository-admin@oasis-open.org>`_ and any specific CLA-related questions to `repository-cla@oasis-open.org <mailto:repository-cla@oasis-open.org>`_.
