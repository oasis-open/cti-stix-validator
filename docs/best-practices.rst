Checking Best Practices
=======================

The validator will always validate input against all of the mandatory
"MUST" requirements from the spec. By default it will issue warnings
if the input fails any of the "SHOULD" recommendations, but validation
will still pass. To turn these "best practice" warnings into errors
and cause validation to fail, use the :code:`--strict` option with the
command-line script, or create a ValidationOptions object with
:code:`strict=True` when using the library.

You cannot select which of the "MUST" requirement checks will be
performed; all of them will always be performed. However, you may
select which of the "SHOULD" checks to perform. Use the codes from the
table below to enable or disable these checks. For example, to disable
the checks for the report label and tool label vocabularies, use
:code:`--disable 218,222` or :code:`disabled="218,222"`. All the other
checks will still be performed. Conversely, to only check that custom
property names adhere to the recommended format but not run any of the
other "best practice" checks, use :code:`--enable 103` or
:code:`enabled="103"`.

Enabling supersedes disabling. Simultaneously enabling and disabling
the same check will result in the validator performing that check.

Some checks access Internet resources to determine valid values for
certain properties. For instance, the 'mime-type' check accesses the
IANA's list of registered MIME types. These web requests are cached to
conserve bandwidth, will expire after one week, and are stored in a
file called 'cache.sqlite' in the same directory the script is run
from. The cache can be refreshed manually with the :code:`--refresh-cache`
or :code:`refresh_cache=True`, or cleared with :code:`--clear-cache` or
:code:`clear_cache=True`. This caching can be disabled entirely with
:code:`--no-cache` or :code:`no_cache=True`.

**Recommended Best Practice Check Codes**

+--------+-----------------------------+----------------------------------------+
|**Code**|**Name**                     |**Ensures...**                          |
+--------+-----------------------------+----------------------------------------+
|   1    | format-checks               | all 1xx checks are run                 |
+--------+-----------------------------+----------------------------------------+
|  101   | custom-prefix               | names of custom object types,          |
|        |                             | properties, observable objects,        |
|        |                             | observable object properties, and      |
|        |                             | observable object extensions follow    |
|        |                             | the correct format                     |
+--------+-----------------------------+----------------------------------------+
|  102   | custom-prefix-lax           | same as 101 but more lenient; no       |
|        |                             | source identifier needed in prefix     |
+--------+-----------------------------+----------------------------------------+
|  111   | open-vocab-format           | values of open vocabularies follow the |
|        |                             | correct format                         |
+--------+-----------------------------+----------------------------------------+
|  121   | kill-chain-names            | kill-chain-phase name and phase follow |
|        |                             | the correct format                     |
+--------+-----------------------------+----------------------------------------+
|  141   | observable-object-keys      | observable object keys follow the      |
|        |                             | correct format                         |
+--------+-----------------------------+----------------------------------------+
|  142   | observable-dictionary-keys  | dictionaries in cyber observable       |
|        |                             | objects follow the correct format      |
+--------+-----------------------------+----------------------------------------+
|  149   | windows-process-priority-\  | windows-process-ext's 'priority'       |
|        | format                      | follows the correct format             |
+--------+-----------------------------+----------------------------------------+
|  150   | hash-length                 | keys in 'hashes'-type properties are   |
|        |                             | not too long                           |
+--------+-----------------------------+----------------------------------------+
|   2    | approved-values             | all 2xx checks are run                 |
+--------+-----------------------------+----------------------------------------+
|  201   | marking-definition-type     | marking definitions use a valid        |
|        |                             | definition_type                        |
+--------+-----------------------------+----------------------------------------+
|  202   | relationship-types          | relationships are among those defined  |
|        |                             | in the specification                   |
+--------+-----------------------------+----------------------------------------+
|  203   | duplicate-ids               | objects in a bundle with duplicate IDs |
|        |                             | have different `modified` timestamps   |
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
|  241   | hash-algo                   | certain property values are from the   |
|        |                             | hash-algo vocabulary                   |
+--------+-----------------------------+----------------------------------------+
|  242   | encryption-algo             | certain property values are from the   |
|        |                             | encryption-algo vocabulary             |
+--------+-----------------------------+----------------------------------------+
|  243   | windows-pebinary-type       | certain property values are from the   |
|        |                             | windows-pebinary-type vocabulary       |
+--------+-----------------------------+----------------------------------------+
|  244   | account-type                | certain property values are from the   |
|        |                             | account-type vocabulary                |
+--------+-----------------------------+----------------------------------------+
|  270   | all-external-sources        | all of the following external source   |
|        |                             | checks are run                         |
+--------+-----------------------------+----------------------------------------+
|  271   | mime-type                   | file.mime_type is a valid IANA MIME    |
|        |                             | type                                   |
+--------+-----------------------------+----------------------------------------+
|  272   | protocols                   | certain property values are valid IANA |
|        |                             | Service and Protocol names             |
+--------+-----------------------------+----------------------------------------+
|  273   | ipfix                       | certain property values are valid IANA |
|        |                             | IP Flow Information Export (IPFIX)     |
|        |                             | Entities                               |
+--------+-----------------------------+----------------------------------------+
|  274   | http-request-headers        | certain property values are valid HTTP |
|        |                             | request header names                   |
+--------+-----------------------------+----------------------------------------+
|  275   | socket-options              | certain property values are valid      |
|        |                             | socket options                         |
+--------+-----------------------------+----------------------------------------+
|  276   | pdf-doc-info                | certain property values are valid PDF  |
|        |                             | Document Information Dictionary keys   |
+--------+-----------------------------+----------------------------------------+
|  301   | network-traffic-ports       | network-traffic objects contain both   |
|        |                             | src_port and dst_port                  |
+--------+-----------------------------+----------------------------------------+
|  302   | extref-hashes               | external references SHOULD have hashes |
|        |                             | if they have a url                     |
+--------+-----------------------------+----------------------------------------+
