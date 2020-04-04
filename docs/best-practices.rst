Checking STIX Content
=====================

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

Mandatory Checks - STIX 2.1
---------------------------

+---------------------------------+----------------------------------------+----------------------------------------+
|**Name**                         |**Ensures...**                          |**Errors/Warnings**                     |
+---------------------------------+----------------------------------------+----------------------------------------+
| timestamp                       | timestamps contain sane months, days,  | '<property>': '<timestamp>' is not a   |
|                                 | hours, minutes, seconds                | valid timestamp: <message>             |
|                                 |                                        |                                        |
|                                 |                                        | '<object>': '<property>': '<timestamp>'|
|                                 |                                        | is not a valid timestamp: <message>    |
|                                 |                                        |                                        |
|                                 |                                        | '<object>': '<extension>':             |
|                                 |                                        | '<property>': '<timestamp>' is not a   |
|                                 |                                        | a valid timestamp: <message>           |
|                                 |                                        |                                        |
|                                 |                                        | '<object>': '<property>':              |
|                                 |                                        | '<embedded-property>' is not a valid   |
|                                 |                                        | timestamp: <message>                   |
+---------------------------------+----------------------------------------+----------------------------------------+
| timestamp_compare               | timestamp properties with a comparison | '<operand_1>' (<operand1_value>) must  |
|                                 | are valid                              | be <comparison_op> '<operand_2>'       |
|                                 |                                        | (<operand2_value)                      |
+---------------------------------+----------------------------------------+----------------------------------------+
| observable_timestamp_compare    | cyber observable timestamp properties  | In object '<identifier>',              |
|                                 | with a comparison requirement are      | '<operand_1>' (<operand1_value>) must  |
|                                 | valid                                  | be <comparison_op> '<operand_2>'       |
|                                 |                                        | (<operand2_value>)                     |
+---------------------------------+----------------------------------------+----------------------------------------+
| object_marking_circular_refs    | that marking definitions do not        | 'object_marking_refs' cannot contain   |
|                                 | contain circular references (i.e.,     | any references to this marking         |
|                                 | they do not reference themselves in    | definition object (no circular         |
|                                 | the 'object_marking_refs' property     | references)                            |
+---------------------------------+----------------------------------------+----------------------------------------+
| granular_markings_circular_refs | that marking definitions do not        | 'granular markings' cannot contain any |
|                                 | contain circular references (i.e.,     | references to this marking definition  |
|                                 | they do not reference themselves in    | object (no circular references)        |
|                                 | the 'granular_markings' property       |                                        |
+---------------------------------+----------------------------------------+----------------------------------------+
| marking_selector_syntax         | selectors in granular markings refer   | '<selector>' is not a valid selector   |
|                                 | to items which are actually present in | because '<index>' is not a valid index |
|                                 | the object                             |                                        |
|                                 |                                        | '<selector>' is not a valid selector   |
|                                 |                                        | because '<selector_segment>' is not a  |
|                                 |                                        | list.                                  |
|                                 |                                        |                                        |
|                                 |                                        | '<selector>' is not a valid selector   |
|                                 |                                        | because '<selector_segment>' is not a  |
|                                 |                                        | property.                              |
+---------------------------------+----------------------------------------+----------------------------------------+
| observable_object_references    | certain observable object properties   | '<property>' in observable object      |
|                                 | reference the correct type of object   | '<identifier>' can't resolve           |
|                                 |                                        | '<embed-property>' reference           |
|                                 |                                        | '<identifier>'                         |
|                                 |                                        |                                        |
|                                 |                                        | '<property>' in observable object      |
|                                 |                                        | '<identifier>' must refer to an object |
|                                 |                                        | of type '<type(s)>'                    |
+---------------------------------+----------------------------------------+----------------------------------------+
| artifact_mime_type              | the 'mime_type' property of artifact   | the 'mime_type' property of object     |
|                                 | objects comes from the Template column | '<identifier>' ('<mime_type>') must    |
|                                 | in the IANA media type registry        | be an IANA registered MIME Type of     |
|                                 |                                        | the form 'type/subtype'.               |
+---------------------------------+----------------------------------------+----------------------------------------+
| character_set                   | certain properties of cyber observable | The 'path_enc' property of object      |
|                                 | objects come from the IANA Character   | '<identifier>' ('<path_enc>') must be  |
|                                 | Set list.                              | an IANA registered character set.      |
|                                 |                                        |                                        |
|                                 |                                        | The 'name_enc' property of object      |
|                                 |                                        | '<identifier>' ('<name_enc>') must be  |
|                                 |                                        | IANA registered character set.         |
+---------------------------------+----------------------------------------+----------------------------------------+
| language                        | the 'lang' property of SDOs is a valid | '<lang>' is not a valid RFC 5646       |
|                                 | RFC 5646 language code                 | language code.                         |
+---------------------------------+----------------------------------------+----------------------------------------+
| software_language               | the 'language' property of software    | The 'languages' property of object     |
|                                 | objects is a valid ISO 639-2 language  | '<identifier>' contains an invalid     |
|                                 | code                                   | code ('<lang>').                       |
+---------------------------------+----------------------------------------+----------------------------------------+
| patterns                        | that the syntax of the pattern of an   | '<object>' is not a valid observable   |
|                                 | indicator is valid, and that objects   | type name                              |
|                                 | and properties referenced by the       |                                        |
|                                 | pattern are valid. This runs the       | Custom Observable Object type          |
|                                 | cti-pattern-validator                  | '<object>' should start with 'x-'      |
|                                 | (https://github.com/oasis-open/cti-    | followed by a source unique identifier |
|                                 | pattern-validator) to check the syntax | (like a domain name with dots replaced |
|                                 | of the pattern.                        | by hyphens), a hyphen and then the     |
|                                 |                                        | name                                   |
|                                 |                                        |                                        |
|                                 |                                        | Custom Observable Object type          |
|                                 |                                        | '<object>' should start with 'x-'      |
|                                 |                                        |                                        |
|                                 |                                        | '<property>' is not a valid observable |
|                                 |                                        | property name                          |
|                                 |                                        |                                        |
|                                 |                                        | Cyber Observable Object custom         |
|                                 |                                        | property '<property>' should start     |
|                                 |                                        | with 'x\_' followed by a source        |
|                                 |                                        | unique identifier (like a domain name  |
|                                 |                                        | with dots replaced by underscores), an |
|                                 |                                        | underscore and then the name           |
|                                 |                                        |                                        |
|                                 |                                        | Cyber Observable Object custom         |
|                                 |                                        | property '<property>' should start     |
|                                 |                                        | with 'x\_'                             |
+---------------------------------+----------------------------------------+----------------------------------------+
| language_contents               | keys in Language Content's 'contents'  | Invalid key '<key>' in 'contents'      |
|                                 | dictionary are valid language codes,   | property must be an RFC 5646 code      |
|                                 | and that the keys in the sub-          |                                        |
|                                 | dictionaries match the rules for       | '<subkey>' in '<key>' of the           |
|                                 | object property names                  | 'contents' property is invalid and     |
|                                 |                                        | must match a valid property name       |
+---------------------------------+----------------------------------------+----------------------------------------+
| uuid_version_check              | that an SCO with only optional ID      | If no Contributing Properties are      |
|                                 | Contributing Properties use a UUIDv4   | present a UUIDv4 must be used          |
+---------------------------------+----------------------------------------+----------------------------------------+
| process                         | that process objects use UUIDv4        | A process object must use UUIDv4 in    |
|                                 |                                        | its id                                 |
+---------------------------------+----------------------------------------+----------------------------------------+

Optional Checks - STIX 2.1
--------------------------

+--------+-----------------------------+----------------------------------------+----------------------------------------+
|**Code**|**Name**                     |**Ensures...**                          |**Errors/Warnings**                     |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|   1    | format-checks               | all 1xx checks are run. Specifically:  |                                        |
|        |                             |                                        |                                        |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  101   | custom-prefix               | names of custom object types,          | custom object type '<object>' should   |
|        |                             | properties, observable objects,        | start with 'x-' followed by a source   |
|        |                             | observable object properties, and      | unique identifier (like a domain name  |
|        |                             | observable object extensions follow    | with dots replaced by hyphens), a      |
|        |                             | the correct format                     | hyphen and then the name.              |
|        |                             |                                        |                                        |
|        |                             |                                        | custom property '<property>' should    |
|        |                             |                                        | have a type that starts with 'x\_'     |
|        |                             |                                        | followed by a source unique identifier |
|        |                             |                                        | (like a domain name with dots replaced |
|        |                             |                                        | by a hyphen), a hyphen and then the    |
|        |                             |                                        | name.                                  |
|        |                             |                                        |                                        |
|        |                             |                                        | Custom Observable Object type          |
|        |                             |                                        | '<observable_object>' should start     |
|        |                             |                                        | with 'x-' followed by a source unique  |
|        |                             |                                        | identifier (like a domain name with    |
|        |                             |                                        | dots replaced by hyphens), a hyphen    |
|        |                             |                                        | and then the name.                     |
|        |                             |                                        |                                        |
|        |                             |                                        | Custom Cyber Observable Object         |
|        |                             |                                        | extension type                         |
|        |                             |                                        | '<observable-object-extension>'        |
|        |                             |                                        | should start with 'x-'                 |
|        |                             |                                        | followed by a source unique identifier |
|        |                             |                                        | (like a domain with dots replaced by   |
|        |                             |                                        | hyphens), a hyphen and then the name.  |
|        |                             |                                        |                                        |
|        |                             |                                        | Cyber Observable Object custom         |
|        |                             |                                        | property '<observable_object_property>'|
|        |                             |                                        | should start with 'x\_' followed by a  |
|        |                             |                                        | source unique identifier (like a domain|
|        |                             |                                        | name with dots replaced by hyphens), a |
|        |                             |                                        | hyphen and then the name.              |
|        |                             |                                        |                                        |
|        |                             |                                        | Cyber Observable Object custom         |
|        |                             |                                        | property '<property>' in the           |
|        |                             |                                        | <extension> extension should start     |
|        |                             |                                        | with 'x\_' followed by a source unique |
|        |                             |                                        | (like a domain name with dots replaced |
|        |                             |                                        | by hyphens), a hyphen and then the     |
|        |                             |                                        | name.                                  |
|        |                             |                                        |                                        |
|        |                             |                                        | Cyber Observable Object custom         |
|        |                             |                                        | property '<property>' in the           |
|        |                             |                                        | <extension_property> of the            |
|        |                             |                                        | <extension> extension should start     |
|        |                             |                                        | with 'x\_' followed by a source        |
|        |                             |                                        | unique identifier (like a domain name  |
|        |                             |                                        | with dots replaced by hyphens), a      |
|        |                             |                                        | hyphen and then the name.              |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  102   | custom-prefix-lax           | same as 101 but more lenient; no       | custom object type '<object>' should   |
|        |                             | source identifier needed in prefix     | start with 'x-' in order to be         |
|        |                             |                                        | compatible with future versions of the |
|        |                             |                                        | STIX 2 specification.                  |
|        |                             |                                        |                                        |
|        |                             |                                        | custom property '<property>' should    |
|        |                             |                                        | have a type that starts with 'x\_' in  |
|        |                             |                                        | order to be compatible with future     |
|        |                             |                                        | versions of the STIX 2 specification.  |
|        |                             |                                        |                                        |
|        |                             |                                        | Custom Observable Object type          |
|        |                             |                                        | '<observable_object>' should start     |
|        |                             |                                        | with 'x-'.                             |
|        |                             |                                        |                                        |
|        |                             |                                        | Custom Observable Object extension     |
|        |                             |                                        | type '<observable-object_extension>'   |
|        |                             |                                        | should start with 'x-'.                |
|        |                             |                                        |                                        |
|        |                             |                                        | Cyber Observable Object custom         |
|        |                             |                                        | property '<property>' should start     |
|        |                             |                                        | with 'x\_'.                            |
|        |                             |                                        |                                        |
|        |                             |                                        | Cyber Observable Object custom         |
|        |                             |                                        | property '<embedded_property>' in the  |
|        |                             |                                        | <property> of the <object> object      |
|        |                             |                                        | should start with 'x\_'.               |
|        |                             |                                        |                                        |
|        |                             |                                        | Cyber Observable Object custom         |
|        |                             |                                        | property '<property>' in the           |
|        |                             |                                        | <extension> extension should start     |
|        |                             |                                        | with 'x\_'.                            |
|        |                             |                                        |                                        |
|        |                             |                                        | Cyber Observable Object custom         |
|        |                             |                                        | property '<property>' in the           |
|        |                             |                                        | <extension_property> property of the   |
|        |                             |                                        | <extension> extension should start     |
|        |                             |                                        | with 'x\_'.                            |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  103   | uuid-check                  | objects use the recommended versions   | Cyber Observable ID value <identifier> |
|        |                             | of UUID (v5 for SCOs, v4 for the rest) | is not a valid UUIDv5 ID.              |
|        |                             |                                        |                                        |
|        |                             |                                        | Given ID value <identifier> is not a   |
|        |                             |                                        | valid UUIDv4 ID.                       |
|        |                             |                                        |                                        |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  111   | open-vocab-format           | values of open vocabularies follow the | Open vocabulary value '<value>' should |
|        |                             | correct format                         | be all lowercase and use hyphens       |
|        |                             |                                        | instead of spaces or underscores as    |
|        |                             |                                        | word separators.                       |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  121   | kill-chain-names            | kill-chain-phase name and phase follow | kill_chain_name '<chain_name>' should  |
|        |                             | the correct format                     | be all lowercase and use hyphens       |
|        |                             |                                        | instead of spaces or underscores as    |
|        |                             |                                        | word separators.                       |
|        |                             |                                        |                                        |
|        |                             |                                        | phase_name '<phase_name>' should be    |
|        |                             |                                        | all lowercase and use hyphens instead  |
|        |                             |                                        | of spaces or underscores as word       |
|        |                             |                                        | separators                             |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  141   | observable-object-keys      | observable object keys follow the      | '<key_value>' is not a good key value. |
|        |                             | correct format                         | Observable Objects should use non-     |
|        |                             |                                        | negative integers for their keys.      |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  142   | observable-dictionary-keys  | dictionaries in cyber observable       | As a dictionary key, '<key_value>'     |
|        |                             | objects follow the correct format      | should be lowercase.                   |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  143   | malware-analysis-product    | malware analysis product names follow  | The 'product' property of object       |
|        |                             | the correct format                     | '<identifier>' should be all lowercase |
|        |                             |                                        | with words separated by dash.          |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  149   | windows-process-priority-\  | windows-process-ext's 'priority'       | The 'priority' property of object      |
|        | format                      | follows the correct format             | '<identifier>' should end in '_CLASS'. |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  150   | hash-length                 | keys in 'hashes'-type properties are   | Object '<identifier>' has a 'hashes'   |
|        |                             | not too long                           | dictionary with a hash of type         |
|        |                             |                                        | '<hash_type>', which is longer than    |
|        |                             |                                        | 30 characters.                         |
|        |                             |                                        |                                        |
|        |                             |                                        | Object '<identifier>' has an NTFS      |
|        |                             |                                        | extension with an alternate data stream|
|        |                             |                                        | that has a 'hashes' dictionary with a  |
|        |                             |                                        | hash of type '<hash_type>', which is   |
|        |                             |                                        | longer than 30 characters.             |
|        |                             |                                        |                                        |
|        |                             |                                        | Object '<identifier>' has a Windows    |
|        |                             |                                        | PE Binary File extension with a file   |
|        |                             |                                        | header hash of '<hash>', which is      |
|        |                             |                                        | longer than 30 characters.             |
|        |                             |                                        |                                        |
|        |                             |                                        | Object '<identifier>' has a Windows PE |
|        |                             |                                        | Binary File extension with an optional |
|        |                             |                                        | header that has a hash of              |
|        |                             |                                        | '<hash>', which is longer than         |
|        |                             |                                        | 30 characters.                         |
|        |                             |                                        |                                        |
|        |                             |                                        | Object '<identifier>' has a Windows PE |
|        |                             |                                        | Binary File extension with a section   |
|        |                             |                                        | that has a hash of '<hash>', which     |
|        |                             |                                        | is longer than 30 characters.          |
|        |                             |                                        |                                        |
|        |                             |                                        | Object '<identifier>' hash a 'hashes'  |
|        |                             |                                        | dictionary with a hash of type         |
|        |                             |                                        | '<hash_type>', which is longer than 30 |
|        |                             |                                        | characters.                            |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|   2    | approved-values             | all 2xx checks are run. Specifically:  |                                        |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  201   | marking-definition-type     | marking definitions use a valid        | Marking definition 'definition_type'   |
|        |                             | definition_type                        | should be one of:                      |
|        |                             |                                        | <marking-definition-type>.             |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  202   | relationship-types          | relationships are among those defined  | '<object>' is not a suggested          |
|        |                             | in the specification                   | relationship source object for the     |
|        |                             |                                        | '<relationship>' relationship.         |
|        |                             |                                        |                                        |
|        |                             |                                        | '<relationship>' is not a suggested    |
|        |                             |                                        | relationship type for '<object>'       |
|        |                             |                                        | objects.                               |
|        |                             |                                        |                                        |
|        |                             |                                        | '<object>' is not a suggested          |
|        |                             |                                        | relationship target object for         |
|        |                             |                                        | '<object>' objects with the            |
|        |                             |                                        | '<relationship>' relationship.         |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  203   | duplicate-ids               | objects in a bundle with duplicate IDs | Duplicate ID '<identifier>' has        |
|        |                             | have different `modified` timestamps   | identical 'modified' timestamp. If     |
|        |                             |                                        | they are different versions of the     |
|        |                             |                                        | same object, they should have different|
|        |                             |                                        | 'modified' properties,                 |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  210   | all-vocabs                  | all of the following open vocabulary   |'<property>' contains a value not in    |
|        |                             | checks are run                         | the <vocab_name>-ov vocabulary.        |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  211   | attack-motivation           | certain property values are from the   | '<property>' contains a value not      |
|        |                             | attack-motivation vocabulary           | in the attack-motivation-ov vocabulary |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  212   | attack-resource-level       | certain property values are from the   | '<property>' contains a value          |
|        |                             | attack-resource-level vocabulary       | not in the attack-resource-level-ov    |
|        |                             |                                        | vocabulary                             |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  213   | identity-class              | certain property values are from the   | '<property>' contains a value not in   |
|        |                             | identity-class vocabulary              | the identity-class-ov vocabulary       |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  214   | indicator-types             | certain property values are from the   | '<property>' contains a value not in   |
|        |                             | indicator-types vocabulary             | the indicator-types-ov vocabulary      |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  215   | industry-sector             | certain property values are from the   | '<property>' contains a value not      |
|        |                             | industry-sector vocabulary             | in the industry-sector-ov vocabulary   |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  216   | malware-types               | certain property values are from the   | '<property>' contains a value not in   |
|        |                             | malware-types vocabulary               | the malware-types-ov vocabulary        |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  218   | report-types                | certain property values are from the   | '<property>' contains a value not in   |
|        |                             | report-types vocabulary                | the report-types-ov vocabulary         |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  219   | threat-actor-types          | certain property values are from the   | '<property>' contains a value not      |
|        |                             | threat-actor-types vocabulary          | in the threat-actor-types-ov vocabulary|
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  220   | threat-actor-role           | certain property values are from the   | '<property>' contains a value not      |
|        |                             | threat_actor_role vocabulary           | in the threat-actor-role-ov vocabulary |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  221   | threat-actor-sophistication | certain property values are from the   | '<property>' contains a                |
|        |                             | threat_actor_sophistication vocabulary | value not in the                       |
|        |                             |                                        | threat-actor-sophistication-ov         |
|        |                             |                                        | vocabulary                             |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  222   | tool-types                  | certain property values are from the   | '<property>' contains a value not in   |
|        |                             | tool_types vocabulary                  | the tool-types-ov vocabulary           |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  223   | region                      | certain property values are from the   | '<property>' contains a value not in   |
|        |                             | region vocabulary                      | the region-ov vocabulary               |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  225   | grouping-context            | certain property values are from the   | '<property>' contains a value not      |
|        |                             | grouping-context vocabulary            | in the grouping-context-ov vocabulary  |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  226   | implementation-languages    | certain property values are from the   | '<property>' contains a                |
|        |                             | implementation-languages vocabulary    | value not in the                       |
|        |                             |                                        | implementation-languages-ov vocabulary |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  227   | infrastructure-types        | certain property values are from the   | '<property>' contains a value          |
|        |                             | infrastructure-types vocabulary        | not in the infrastructure-types-ov     |
|        |                             |                                        | vocabulary                             |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  228   | malware-capabilities        | certain property values are from the   | '<property>' contains a value          |
|        |                             | malware-capabilities vocabulary        | not in the malware-capabilities-ov     |
|        |                             |                                        | vocabulary                             |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  230   | processor-architecture      | certain property values are from the   | '<property>' contains a value not in   |
|        |                             | processor-architecture vocabulary      | the                                    |
|        |                             |                                        | processor-architecture-ov vocabulary   |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  231   | malware-result              | certain property values are from the   | '<property>' contains a value not in   |
|        |                             | malware-result vocabulary              | the malware-result-ov vocabulary       |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  241   | hash-algo                   | certain property values are from the   | Object '<identifier>' has a 'hashes'   |
|        |                             | hash-algo vocabulary                   | dictionary with a hash of type         |
|        |                             |                                        | '<hash_type>', which is not a value in |
|        |                             |                                        | the hash-algorithm-ov vocabulary nor   |
|        |                             |                                        | a custom value prepended with 'x\_'.   |
|        |                             |                                        |                                        |
|        |                             |                                        | Object '<identifier>' has an NTFS      |
|        |                             |                                        | extension with an alternate data       |
|        |                             |                                        | stream that has a 'hashes' dictionary  |
|        |                             |                                        | with a hash of type '<hash_type>',     |
|        |                             |                                        | which is not a value in the hash-      |
|        |                             |                                        | algorithm-ov vocabulary nor a custom   |
|        |                             |                                        | value prepended with 'x\_'.            |
|        |                             |                                        |                                        |
|        |                             |                                        | Object '<identifier>' has a Windows PE |
|        |                             |                                        | Binary File extension with a file      |
|        |                             |                                        | header hash of '<hash_type>', which is |
|        |                             |                                        | not a value in the hash-algorithm-     |
|        |                             |                                        | vocabulary nor a custom value prepended|
|        |                             |                                        | with 'x\_'.                            |
|        |                             |                                        |                                        |
|        |                             |                                        | Object '<identifier>' has a Windows PE |
|        |                             |                                        | Binary File extension with an optional |
|        |                             |                                        | header that has a hash of              |
|        |                             |                                        | '<hash_type>', which is not a value in |
|        |                             |                                        | the hash-algorithm-ov vocabulary nor a |
|        |                             |                                        | custom value prepended with 'x\_'.     |
|        |                             |                                        |                                        |
|        |                             |                                        | Object '<identifier>' has a Windows    |
|        |                             |                                        | PE Binary File extension with a        |
|        |                             |                                        | section that has a hash of             |
|        |                             |                                        | '<hash_type>', which is not a value    |
|        |                             |                                        | in the hash-algorithm-ov vocabulary    |
|        |                             |                                        | nor a custom value prepended with      |
|        |                             |                                        | 'x\_'.                                 |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  243   | windows-pebinary-type       | certain property values are from the   | Object '<identifier>' has a Windows PE |
|        |                             | windows-pebinary-type vocabulary       | Binary File extension with a 'pe_type' |
|        |                             |                                        | of '<pe_type>', which is not a value   |
|        |                             |                                        | in the windows-pebinary-type-ov        |
|        |                             |                                        | vocabulary.                            |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  244   | account-type                | certain property values are from the   | Object '<identifier>'is a User Account |
|        |                             | account-type vocabulary                | Object with an 'account_type' of       |
|        |                             |                                        | '<account_type>', which is not a value |
|        |                             |                                        | in the account-type-ov vocabulary.     |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  245   | indicator-pattern-types     | certain property values are from the   | '<property>' contains a value not in   |
|        |                             | pattern-type vocabulary                | the pattern-type-ov vocabulary         |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  270   | all-external-sources        | all of the following external source   |                                        |
|        |                             | checks are run                         |                                        |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  271   | mime-type                   | file.mime_type is a valid IANA MIME    | The 'mime_type' property of object     |
|        |                             | type                                   | '<identifier>' ('<mime_type>') should  |
|        |                             |                                        | be an IANA registered MIME Type of the |
|        |                             |                                        | form 'type/subtype'.                   |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  272   | protocols                   | certain property values are valid IANA | The 'protocols' property of object     |
|        |                             | Service and Protocol names             | '<identifier>' contains a value        |
|        |                             |                                        | ('<protocol>') not in IANA Service     |
|        |                             |                                        | Name and Transport Protocol Port       |
|        |                             |                                        | Number Registry.                       |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  273   | ipfix                       | certain property values are valid IANA | The 'ipfix' property of object         |
|        |                             | IP Flow Information Export (IPFIX)     | '<identifier>' contains a key          |
|        |                             | Entities                               | ('<ipfix>') not in IANA IP Flow        |
|        |                             |                                        | Information Export (IPFIX) Entities    |
|        |                             |                                        | Registry.                              |
|        |                             |                                        |                                        |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  274   | http-request-headers        | certain property values are valid HTTP | The 'request_header' property of object|
|        |                             | request header names                   | '<identifier>' contains an invalid HTTP|
|        |                             |                                        | header ('<http_request_header>').      |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  275   | socket-options              | certain property values are valid      | The 'options' property of object       |
|        |                             | socket options                         | '<identifier>' contains a key          |
|        |                             |                                        | ('<option>') that is not a valid       |
|        |                             |                                        | socket option (SO|ICMP|ICMP6|IP|IPV6|  |
|        |                             |                                        | MCAST|TCP|IRLMP)_*.                    |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  276   | pdf-doc-info                | certain property values are valid PDF  | The 'document_info_dict' property of   |
|        |                             | Document Information Dictionary keys   | object '<identifier>' contains a key   |
|        |                             |                                        | ('<key>') that is not a valid PDF      |
|        |                             |                                        | Document Information Dictionary key.   |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  277   | countries                   | certain property values are valid ISO  | Location 'country' should be a valid   |
|        |                             | 3166-1 ALPHA-2 codes                   | ISO 3166-1 ALPHA-2 Code.               |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  301   | network-traffic-ports       | network-traffic objects contain both   | The Network Traffic object             |
|        |                             | src_port and dst_port                  | '<identifier>' should contain both the |
|        |                             |                                        | 'src_port' and 'dst_port' properties.  |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  302   | extref-hashes               | external references SHOULD have hashes | External reference '<src>' has a URL   |
|        |                             | if they have a url                     | but no hash.                           |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  303   | indicator-properties        | Indicator objects have both name and   | Both the name and description          |
|        |                             | description properties                 | properties SHOULD be present.          |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
|  304   | deprecated-properties       | certain properties which have been     | Included property '<property>' is      |
|        |                             | deprecated are not being used          | deprecated within the indicated        |
|        |                             |                                        | spec version.                          |
+--------+-----------------------------+----------------------------------------+----------------------------------------+
