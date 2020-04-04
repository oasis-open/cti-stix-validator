"""STIX 2.1 WD04 open vocabularies and other lists
"""

import re

import requests

# Enumerations of the default values of STIX open vocabularies
ATTACK_MOTIVATION_OV = [
    "accidental",
    "coercion",
    "dominance",
    "ideology",
    "notoriety",
    "organizational-gain",
    "personal-gain",
    "personal-satisfaction",
    "revenge",
    "unpredictable",
]
ATTACK_RESOURCE_LEVEL_OV = [
    "individual",
    "club",
    "contest",
    "team",
    "organization",
    "government",
]
GROUPING_CONTEXT_OV = [
    "suspicious-activity",
    "malware-analysis",
    "unspecified",
]
IDENTITY_CLASS_OV = [
    "individual",
    "group",
    "system",
    "organization",
    "class",
    "unknown",
]
IMPLEMENTATION_LANGUAGES_OV = [
    "applescript",
    "bash",
    "c",
    "c++",
    "c#",
    "go",
    "java",
    "javascript",
    "lua",
    "objective-c",
    "perl",
    "php",
    "powershell",
    "python",
    "ruby",
    "scala",
    "swift",
    "typescript",
    "visual-basic",
    "x86-32",
    "x86-64",
]
INDICATOR_TYPE_OV = [
    "anomalous-activity",
    "anonymization",
    "benign",
    "compromised",
    "malicious-activity",
    "attribution",
    "unknown",
]
INDUSTRY_SECTOR_OV = [
    "agriculture",
    "aerospace",
    "automotive",
    "chemical",
    "commercial",
    "communications",
    "construction",
    "defense",
    "education",
    "energy",
    "entertainment",
    "financial-services",
    "government",
    "emergency-services",
    "government-local",
    "government-national",
    "government-public-services",
    "government-regional",
    "healthcare",
    "hospitality-leisure",
    "infrastructure",
    "dams",
    "nuclear",
    "water",
    "insurance",
    "manufacturing",
    "mining",
    "non-profit",
    "pharmaceuticals",
    "retail",
    "technology",
    "telecommunications",
    "transportation",
    "utilities",
]
INFRASTRUCTURE_TYPE_OV = [
    "amplification",
    "anonymization",
    "botnet",
    "command-and-control",
    "exfiltration",
    "hosting-malware",
    "hosting-target-lists",
    "phishing",
    "reconnaissance",
    "staging",
    "unknown",
]
MALWARE_RESULT_OV = [
    "malicious",
    "suspicious",
    "benign",
    "unknown",
]
MALWARE_TYPE_OV = [
    "adware",
    "backdoor",
    "bot",
    "bootkit",
    "ddos",
    "downloader",
    "dropper",
    "exploit-kit",
    "keylogger",
    "ransomware",
    "remote-access-trojan",
    "resource-exploitation",
    "rogue-security-software",
    "rootkit",
    "screen-capture",
    "spyware",
    "trojan",
    "unknown",
    "virus",
    "webshell",
    "wiper",
    "worm",
]
MALWARE_CAPABILITIES_OV = [
    "accesses-remote-machines",
    "anti-debugging",
    "anti-disassembly",
    "anti-emulation",
    "anti-memory-forensics",
    "anti-sandbox",
    "anti-vm",
    "captures-input-peripherals",
    "captures-output-peripherals",
    "captures-system-state-data",
    "cleans-traces-of-infection",
    "commits-fraud",
    "communicates-with-c2",
    "compromises-data-availability",
    "compromises-data-integrity",
    "compromises-system-availability",
    "controls-local-machine",
    "degrades-security-software",
    "degrades-system-updates",
    "determines-c2-server",
    "emails-spam",
    "escalates-privileges",
    "evades-av",
    "exfiltrates-data",
    "fingerprints-host",
    "hides-artifacts",
    "hides-executing-code",
    "infects-files",
    "infects-remote-machines",
    "installs-other-components",
    "persists-after-system-reboot",
    "prevents-artifact-access",
    "prevents-artifact-deletion",
    "probes-network-environment",
    "self-modifies",
    "steals-authentication-credentials",
    "violates-system-operational-integrity",
]
INDICATOR_PATTERN_OV = [
    "stix",
    "pcre",
    "sigma",
    "snort",
    "suricata",
    "yara",
]
PROCESSOR_ARCHITECTURE_OV = [
    "alpha",
    "arm",
    "ia-64",
    "mips",
    "powerpc",
    "sparc",
    "x86",
    "x86-64",
]
REGION_OV = [
    "africa",
    "eastern-africa",
    "middle-africa",
    "northern-africa",
    "southern-africa",
    "western-africa",
    "americas",
    "latin-america-caribbean",
    "south-america",
    "caribbean",
    "central-america",
    "northern-america",
    "asia",
    "central-asia",
    "eastern-asia",
    "southern-asia",
    "south-eastern-asia",
    "western-asia",
    "europe",
    "eastern-europe",
    "northern-europe",
    "southern-europe",
    "western-europe",
    "oceania",
    "australia-new-zealand",
    "melanesia",
    "micronesia",
    "polynesia",
    "antarctica",
]
REPORT_TYPE_OV = [
    "threat-report",
    "attack-pattern",
    "campaign",
    "identity",
    "indicator",
    "intrusion-set",
    "malware",
    "observed-data",
    "threat-actor",
    "tool",
    "vulnerability",
]
THREAT_ACTOR_TYPE_OV = [
    "activist",
    "competitor",
    "crime-syndicate",
    "criminal",
    "hacker",
    "insider-accidental",
    "insider-disgruntled",
    "nation-state",
    "sensationalist",
    "spy",
    "terrorist",
    "unknown",
]
THREAT_ACTOR_ROLE_OV = [
    "agent",
    "director",
    "independent",
    "infrastructure-architect",
    "infrastructure-operator",
    "malware-author",
    "sponsor",
]
THREAT_ACTOR_SOPHISTICATION_OV = [
    "none",
    "minimal",
    "intermediate",
    "advanced",
    "expert",
    "innovator",
    "strategic",
]
TOOL_TYPE_OV = [
    "denial-of-service",
    "exploitation",
    "information-gathering",
    "network-capture",
    "credential-exploitation",
    "remote-access",
    "vulnerability-scanning",
    "unknown",
]
HASH_ALGO_OV = [
    "MD5",
    "SHA-1",
    "SHA-256",
    "SHA-512",
    "SHA3-256",
    "SHA3-512",
    "SSDEEP",
    "TLSH",
]
WINDOWS_PEBINARY_TYPE_OV = [
    "exe",
    "dll",
    "sys",
]
ACCOUNT_TYPE_OV = [
    "unix",
    "windows-local",
    "windows-domain",
    "ldap",
    "tacacs",
    "radius",
    "nis",
    "openid",
    "facebook",
    "skype",
    "twitter",
    "kavi",
]


# Dictionaries mapping object types to properties that use a given vocabulary
ACCOUNT_TYPE_USES = {
    "user-account": ["account_type"],
}
ATTACK_MOTIVATION_USES = {
    "intrusion-set": [
        "primary_motivation",
        "secondary_motivations",
    ],
    "threat-actor": [
        "primary_motivation",
        "secondary_motivations",
        "personal_motivations",
    ]
}
ATTACK_RESOURCE_LEVEL_USES = {
    "intrusion-set": ["resource_level"],
    "threat-actor": ["resource_level"],
}
GROUPING_CONTEXT_USES = {
    "grouping": ["context"],
}
HASH_ALGO_USES = {
    "artifact": ["hashes"],
    "file": ["hashes"],
    "ntfs-ext": ["hashes"],
    "sections": ["hashes"],
    "x509-certificate": ["hashes"],
    "windows-pebinary-ext": ["file_header_hashes"],
}
IDENTITY_CLASS_USES = {
    "identity": ["identity_class"],
}
IMPLEMENTATION_LANGUAGES_USES = {
    "malware": ["implementation_languages"],
}
INDICATOR_TYPE_USES = {
    "indicator": ["indicator_types"],
}
INDICATOR_PATTERN_USES = {
    "indicator": ["pattern_type"],
}
INFRASTRUCTURE_TYPE_USES = {
    "infrastructure": ["infrastructure_types"],
}
INDUSTRY_SECTOR_USES = {
    "identity": ["sectors"],
}
MALWARE_CAPABILITIES_USES = {
    "malware": ["capabilities"],
}
MALWARE_RESULT_USES = {
    "malware-analysis": ["result"],
}
REGION_USES = {
    "location": ["region"],
}
MALWARE_TYPE_USES = {
    "malware": ["malware_types"],
}
PROCESSOR_ARCHITECTURE_USES = {
    "malware": ["architecture_execution_envs"],
}
REPORT_TYPE_USES = {
    "report": ["report_types"],
}
THREAT_ACTOR_TYPE_USES = {
    "threat-actor": ["threat_actor_types"],
}
THREAT_ACTOR_ROLE_USES = {
    "threat-actor": ["roles"],
}
THREAT_ACTOR_SOPHISTICATION_USES = {
    "threat-actor": ["sophistication"],
}
TOOL_TYPE_USES = {
    "tool": ["tool_types"],
}


# List of default STIX object types
TYPES = [
    "attack-pattern",
    "campaign",
    "course-of-action",
    "grouping",
    "identity",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "malware-analysis",
    "note",
    "observed-data",
    "opinion",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
    "bundle",
    "relationship",
    "sighting",
    "language-content",
    "marking-definition",
]

OBSERVABLE_TYPES = [
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
]

# List of default marking definition types
MARKING_DEFINITION_TYPES = [
    "statement",
    "tlp",
]

# List of object types which have a `kill-chain-phases` property
KILL_CHAIN_PHASE_USES = [
    "attack-pattern",
    "indicator",
    "infrastructure",
    "malware",
    "tool",
]


# Mapping of official STIX objects to their official properties
PROPERTIES = {
    "attack-pattern": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'kill_chain_phases',
        'aliases',
    ],
    "campaign": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'aliases',
        'first_seen',
        'last_seen',
        'objective',
    ],
    "course-of-action": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'action'
    ],
    "grouping": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'context',
        'object_refs',
    ],
    "identity": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'roles',
        'identity_class',
        'sectors',
        'contact_information',
    ],
    "indicator": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        "pattern_type",
        "pattern_version",
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'indicator_types',
        'pattern',
        'valid_from',
        'valid_until',
        'kill_chain_phases',
    ],
    "infrastructure": [
        'type',
        "aliases",
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'infrastructure_types',
        'kill_chain_phases',
        'first_seen',
        'last_seen',
    ],
    "intrusion-set": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'aliases',
        'first_seen',
        'last_seen',
        'goals',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
    ],
    "location": [
        'type',
        'name',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'description',
        'latittude',
        'longitude',
        'precision',
        'region',
        'country',
        'administrative_area',
        'city',
        'street_address',
        'postal_code',
    ],
    "malware": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'malware_types',
        'is_family',
        'aliases',
        'kill_chain_phases',
        'first_seen',
        'last_seen',
        'operating_system_refs',
        'architecture_execution_envs',
        'implementation_languages',
        'capabilities',
        'sample_refs',
    ],
    "malware-analysis": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'product',
        'version',
        'host_vm_ref',
        'operating_system_ref',
        'installed_software_ref',
        'configuration_version',
        'modules',
        'analysis_engine_version',
        'analysis_definition_version',
        'submitted',
        'analysis_started',
        'analysis_ended',
        'result_name',
        'result',
        'analysis_sco_refs',
        'sample_ref',
    ],
    "note": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'abstract',
        'content',
        'authors',
        'object_refs',
    ],
    "observed-data": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'first_observed',
        'last_observed',
        'number_observed',
        'objects',
        'object_refs',
    ],
    "opinion": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'explanation',
        'authors',
        'object_refs',
        'opinion',
    ],
    "report": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'report_types',
        'published',
        'object_refs',
    ],
    "threat-actor": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'first_seen',
        'last_seen',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'threat_actor_types',
        'aliases',
        'roles',
        'goals',
        'sophistication',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
        'personal_motivations',
    ],
    "tool": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'tool_types',
        'aliases',
        'kill_chain_phases',
        'tool_version'
    ],
    "vulnerability": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
    ],
    "bundle": [
        'type',
        'id',
        'objects',
    ],
    "relationship": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'relationship_type',
        'description',
        'source_ref',
        'target_ref',
        'start_time',
        'stop_time',
    ],
    "sighting": [
        'type',
        'spec_version',
        'id',
        'description',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'first_seen',
        'last_seen',
        'count',
        'sighting_of_ref',
        'observed_data_refs',
        'where_sighted_refs',
        'summary',
    ],
    "language-content": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'confidence',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'object_ref',
        'object_modified',
        'contents',
    ],
    "marking-definition": [
        'type',
        'spec_version',
        'id',
        'created_by_ref',
        'created',
        'lang',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'definition_type',
        'definition',
    ]
}
# Mappings of official Cyber Observable Objects to their official properties
OBSERVABLE_PROPERTIES = {
    'artifact': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'mime_type',
        'payload_bin',
        'url',
        'hashes',
        'encryption_algorithm',
        'decryption_key',
    ],
    'autonomous-system': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'number',
        'name',
        'rir',
    ],
    'directory': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'path',
        'path_enc',
        'ctime',
        'mtime',
        'atime',
        'contains_refs',
    ],
    'domain-name': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'value',
        'resolves_to_refs',
    ],
    'email-addr': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'value',
        'display_name',
        'belongs_to_ref',
    ],
    'email-message': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'is_multipart',
        'date',
        'content_type',
        'from_ref',
        'sender_ref',
        'to_refs',
        'cc_refs',
        'bcc_refs',
        'subject',
        'received_lines',
        'additional_header_fields',
        'message_id',
        'body',
        'body_multipart',
        'raw_email_ref',
    ],
    'file': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'hashes',
        'size',
        'name',
        'name_enc',
        'magic_number_hex',
        'mime_type',
        'ctime',
        'mtime',
        'atime',
        'parent_directory_ref',
        'contains_refs',
        'content_ref',
    ],
    'ipv4-addr': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'value',
        'resolves_to_refs',
        'belongs_to_refs',
    ],
    'ipv6-addr': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'value',
        'resolves_to_refs',
        'belongs_to_refs',
    ],
    'mac-addr': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'value',
    ],
    'mutex': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'name',
    ],
    'network-traffic': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'start',
        'end',
        'is_active',
        'src_ref',
        'dst_ref',
        'src_port',
        'dst_port',
        'protocols',
        'src_byte_count',
        'dst_byte_count',
        'src_packets',
        'dst_packets',
        'ipfix',
        'src_payload_ref',
        'dst_payload_ref',
        'encapsulates_refs',
        'encapsulated_by_ref',
    ],
    'process': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'is_hidden',
        'pid',
        'created',
        'cwd',
        'command_line',
        'environment_variables',
        'opened_connection_refs',
        'creator_user_ref',
        'image_ref',
        'parent_ref',
        'child_refs',
    ],
    'software': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'name',
        'cpe',
        'swid',
        'languages',
        'vendor',
        'version',
    ],
    'url': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'value',
    ],
    'user-account': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'user_id',
        'credential',
        'account_login',
        'account_type',
        'display_name',
        'is_service_account',
        'is_privileged',
        'can_escalate_privs',
        'is_disabled',
        'account_created',
        'account_expires',
        'credential_last_changed',
        'account_first_login',
        'account_last_login',
    ],
    'windows-registry-key': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'key',
        'values',
        'modified_time',
        'creator_user_ref',
        'number_of_subkeys',
    ],
    'x509-certificate': [
        'type',
        'id',
        'spec_version',
        'object_marking_refs',
        'granular_markings',
        'defanged',
        'extensions',
        'is_self_signed',
        'hashes',
        'version',
        'serial_number',
        'signature_algorithm',
        'issuer',
        'validity_not_before',
        'validity_not_after',
        'subject',
        'subject_public_key_algorithm',
        'subject_public_key_modulus',
        'subject_public_key_exponent',
        'x509_v3_extensions',
    ]
}
OBSERVABLE_EXTENSION_PROPERTIES = {
    'archive-ext': [
        'contains_refs',
        'comment',
    ],
    'ntfs-ext': [
        'sid',
        'alternate_data_streams',
    ],
    'pdf-ext': [
        'version',
        'is_optimized',
        'document_info_dict',
        'pdfid0',
        'pdfid1',
    ],
    'raster-image-ext': [
        'image_height',
        'image_width',
        'bits_per_pixel',
        'exif_tags',
    ],
    'windows-pebinary-ext': [
        'pe_type',
        'imphash',
        'machine_hex',
        'number_of_sections',
        'time_date_stamp',
        'pointer_to_symbol_table_hex',
        'number_of_symbols',
        'size_of_optional_header',
        'characteristics_hex',
        'file_header_hashes',
        'optional_header',
        'sections',
    ],
    'http-request-ext': [
        'request_method',
        'request_value',
        'request_version',
        'request_header',
        'message_body_length',
        'message_body_data_ref',
    ],
    'icmp-ext': [
        'icmp_type_hex',
        'icmp_code_hex',
    ],
    'socket-ext': [
        'address_family',
        'is_blocking',
        'is_listening',
        'options',
        'socket_type',
        'socket_descriptor',
        'socket_handle',
    ],
    'tcp-ext': [
        'src_flags_hex',
        'dst_flags_hex',
    ],
    'windows-process-ext': [
        'aslr_enabled',
        'dep_enabled',
        'priority',
        'owner_sid',
        'window_title',
        'startup_info',
        'integrity_level',
    ],
    'windows-service-ext': [
        'service_name',
        'descriptions',
        'display_name',
        'group_name',
        'start_type',
        'service_dll_refs',
        'service_type',
        'service_status',
    ],
    'unix-account-ext': [
        'gid',
        'groups',
        'home_dir',
        'shell',
    ]
}
# Mappings of properties of embedded cyber observable types
OBSERVABLE_EMBEDDED_PROPERTIES = {
    'email-message': {
        'body_multipart': [
            'body',
            'body_raw_ref',
            'content_type',
            'content_disposition',
        ]
    },
    'windows-registry-key': {
        'values': [
            'name',
            'data',
            'data_type',
        ]
    },
    'x509-certificate': {
        'x509_v3_extensions': [
            'basic_constraints',
            'name_constraints',
            'policy_constraints',
            'key_usage',
            'extended_key_usage',
            'subject_key_identifier',
            'authority_key_identifier',
            'subject_alternative_name',
            'issuer_alternative_name',
            'subject_directory_attributes',
            'crl_distribution_points',
            'inhibit_any_policy',
            'private_key_usage_period_not_before',
            'private_key_usage_period_not_after',
            'certificate_policies',
            'policy_mappings',
        ]
    }
}
OBSERVABLE_EXTENSION_EMBEDDED_PROPERTIES = {
    'ntfs-ext': {
        'alternate_data_streams': [
            'name',
            'hashes',
            'size',
        ]
    },
    'windows-pebinary-ext': {
        'optional_header': [
            'magic_hex',
            'major_linker_version',
            'minor_linker_version',
            'size_of_code',
            'size_of_initialized_data',
            'size_of_uninitialized_data',
            'address_of_entry_point',
            'base_of_code',
            'base_of_data',
            'image_base',
            'section_alignment',
            'file_alignment',
            'major_os_version',
            'minor_os_version',
            'major_image_version',
            'minor_image_version',
            'major_subsystem_version',
            'minor_subsystem_version',
            'win32_version_value_hex',
            'size_of_image',
            'size_of_headers',
            'checksum_hex',
            'subsystem_hex',
            'dll_characteristics_hex',
            'size_of_stack_reserve',
            'size_of_stack_commit',
            'size_of_heap_reserve',
            'size_of_heap_commit',
            'loader_flags_hex',
            'number_of_rva_and_sizes',
            'hashes',
        ],
        'sections': [
            'name',
            'size',
            'entropy',
            'hashes',
        ]
    }
}

# Official cyber observable object extensions, per object type
OBSERVABLE_EXTENSIONS = {
    'file': [
        'archive-ext',
        'ntfs-ext',
        'pdf-ext',
        'raster-image-ext',
        'windows-pebinary-ext',
    ],
    'network-traffic': [
        'http-request-ext',
        'icmp-ext',
        'socket-ext',
        'tcp-ext',
    ],
    'process': [
        'windows-process-ext',
        'windows-service-ext',
    ],
    'user-account': [
        'unix-account-ext',
    ]
}

# Maping of Observable Object properties that reference other Objects
OBSERVABLE_PROP_REFS = {
    'directory': {
        'contains_refs': [
            'file',
            'directory',
        ]
    },
    'domain-name': {
        'resolves_to_refs': [
            'ipv4-addr',
            'ipv6-addr',
            'domain-name',
        ]
    },
    'email-addr': {
        'belongs_to_ref': [
            'user-account',
        ]
    },
    'email-message': {
        'from_ref': [
            'email-addr',
        ],
        'sender_ref': [
            'email-addr',
        ],
        'to_refs': [
            'email-addr',
        ],
        'cc_refs': [
            'email-addr',
        ],
        'bcc_refs': [
            'email-addr',
        ],
        'raw_email_ref': [
            'artifact',
        ],
        'body_multipart': {
            'body_raw_ref': [
                'artifact',
                'file',
            ]
        }
    },
    'file': {
        'parent_directory_ref': [
            'directory',
        ],
        'content_ref': [
            'artifact',
        ],
        'extensions': {
            'archive-ext': {
                'contains_refs': [
                    'file',
                ]
            }
        }
    },
    'ipv4-addr': {
        'resolves_to_refs': [
            'mac-addr',
        ],
        'belongs_to_refs': [
            'autonomous-system',
        ]
    },
    'ipv6-addr': {
        'resolves_to_refs': [
            'mac-addr',
        ],
        'belongs_to_refs': [
            'autonomous-system',
        ]
    },
    'network-traffic': {
        'src_ref': [
            'ipv4-addr',
            'ipv6-addr',
            'mac-addr',
            'domain-name',
        ],
        'dst_ref': [
            'ipv4-addr',
            'ipv6-addr',
            'mac-addr',
            'domain-name',
        ],
        'src_payload_ref': [
            'artifact',
        ],
        'dst_payload_ref': [
            'artifact',
        ],
        'encapsulates_refs': [
            'network-traffic',
        ],
        'encapsulated_by_ref': [
            'network-traffic',
        ],
        'extensions': {
            'http-request-ext': {
                'message_body_data_ref': [
                    'artifact',
                ]
            }
        }
    },
    'process': {
        'opened_connection_refs': [
            'network-traffic',
        ],
        'creator_user_ref': [
            'user-account',
        ],
        'image_ref': [
            'file',
        ],
        'parent_ref': [
            'process',
        ],
        'child_refs': [
            'process',
        ],
        'extensions': {
            'windows-service-ext': {
                'service_dll_refs': [
                    'file',
                ]
            }
        }
    },
    'windows-registry-key': {
        'creator_user_ref': [
            'user-account',
        ]
    }
}

# Cyber Observable Object properties of the dictionary type whose keys do not
# fall under the requirement to be lowercase.
OBSERVABLE_DICT_KEY_EXCEPTIONS = [
    'hashes',
    'file_header_hashes',
    'request_header',
    'additional_header_fields',
    'document_info_dict',
    'exif_tags',
    'ipfix',
    'options',
    'environment_variables',
    'key',
    'startup_info',
]

# Reserved properties and objects
RESERVED_PROPERTIES = [
    'severity',
    'usernames',
    'phone_numbers',
]
RESERVED_OBJECTS = [
    'incident',
    'action',
]
OBSERVABLE_RESERVED_OBJECTS = [
    'action',
]


NON_SDOS = [
    'bundle',
    'language-content',
    'marking-definition',
    'sighting',
    'relationship',
]

# List of relationship types common to all object types
COMMON_RELATIONSHIPS = [
    'derived-from',
    'duplicate-of',
    'related-to',
]

# Mapping of official STIX objects to their official relationships
RELATIONSHIPS = {
    'attack-pattern': {
        'delivers': 'malware',
        'targets': [
            'location',
            'vulnerability',
            'identity',
        ],
        'uses': [
            'malware',
            'tool',
        ]
    },
    'campaign': {
        'attributed-to': [
            'intrusion-set',
            'threat-actor',
        ],
        'compromises': 'infrastructure',
        'originates-from': 'location',
        'targets': [
            'location',
            'identity',
            'vulnerability',
        ],
        'uses': [
            'attack-pattern',
            'infrastructure',
            'malware',
            'tool',
        ]
    },
    'course-of-action': {
        'investigates': 'indicator',
        'mitigates': [
            'attack-pattern',
            'indicator',
            'malware',
            'tool',
            'vulnerability',
        ],
        'remediates': [
            'malware',
            'vulnerability',
        ]
    },
    'domain-name': {
        'resolves-to': [
            'domain-name',
            'ipv4-addr',
            'ipv6-addr',
        ]
    },
    'identity': {
        'located-at': 'location',
    },
    'indicator': {
        'indicates': [
            'attack-pattern',
            'campaign',
            'infrastructure',
            'intrusion-set',
            'malware',
            'threat-actor',
            'tool',
        ],
        'based-on': 'observed-data'
    },
    'infrastructure': {
        'communicates-with': [
            'infrastructure',
            'ipv4-addr',
            'ipv6-addr',
            'domain-name',
            'url',
        ],
        'consists-of': [
            'infrastructure',
            'observed-data',
            'artifact',
            'autonomous-system',
            'directory',
            'domain-name',
            'email-addr',
            'email-message',
            'file',
            'ipv4-addr',
            'ipv6-addr',
            'mac-addr',
            'mutex',
            'network-traffic',
            'process',
            'software',
            'url',
            'user-account',
            'windows-registry-key',
            'x509-certificate',
        ],
        'controls': [
            'infrastructure',
            'malware',
        ],
        'delivers': 'malware',
        'has': 'vulnerability',
        'hosts': [
            'tool',
            'malware',
        ],
        'located-at': 'location',
        'uses': 'infrastructure',
    },
    'intrusion-set': {
        'attributed-to': 'threat-actor',
        'compromises': 'infrastructure',
        'hosts': 'infrastructure',
        'originates-from': 'location',
        'owns': 'infrastructure',
        'targets': [
            'identity',
            'location',
            'vulnerability',
        ],
        'uses': [
            'attack-pattern',
            'infrastructure',
            'malware',
            'tool',
        ],
    },
    'ipv4-addr': {
        'resolves-to': 'mac-addr',
        'belongs-to': 'autonomous-system',
    },
    'ipv6-addr': {
        'resolves-to': 'mac-addr',
        'belongs-to': 'autonomous-system',
    },
    'malware': {
        'authored-by': [
            'threat-actor',
            'intrusion-set',
        ],
        'beacons-to': 'infrastructure',
        'exfiltrates-to': 'infrastructure',
        'communicates-with': [
            'ipv4-addr',
            'ipv6-addr',
            'domain-name',
            'url',
        ],
        'controls': 'malware',
        'downloads': [
            'malware',
            'file',
            'tool',
        ],
        'drops': [
            'malware',
            'file',
            'tool',
        ],
        'exploits': 'vulnerability',
        'originates-from': 'location',
        'targets': [
            'identity',
            'infrastructure',
            'location',
        ],
        'uses': [
            'attack-pattern',
            'infrastructure',
            'malware',
            'tool',
        ],
        'variant-of': 'malware',
    },
    'malware-analysis': {
        'characterizes': 'malware',
        'analysis-of': 'malware',
        'static-analysis-of': 'malware',
        'dynamic-analysis-of': 'malware',
    },
    'threat-actor': {
        'attributed-to': 'identity',
        'compromises': 'infrastructure',
        'hosts': 'infrastructure',
        'owns': 'infrastructure',
        'impersonates': 'identity',
        'located-at': 'location',
        'targets': [
            'identity',
            'location',
            'vulnerability',
        ],
        'uses': [
            'attack-pattern',
            'infrastructure',
            'malware',
            'tool',
        ],
    },
    'tool': {
        'delivers': 'malware',
        'drops': 'malware',
        'uses': 'infrastructure',
        'has': 'vulnerability',
        'targets': [
            'identity',
            'infrastructure',
            'location',
            'vulnerability',
        ]
    },
    'vulnerability': {
        "impacts": [
            'infrastructure',
            'tools',
        ]
    },
}


# Mapping of official STIX objects to their timestamp properties
# Common timestamp properties ('created', 'modified') are already included
TIMESTAMP_PROPERTIES = {
    'campaign': [
        'first_seen',
        'last_seen',
    ],
    'indicator': [
        'valid_from',
        'valid_until',
    ],
    'infrastructure': [
        'first_seen',
        'last_seen',
    ],
    'intrusion-set': [
        'first_seen',
        'last_seen',
    ],
    'language-content': [
        'object_modified'
    ],
    'malware': [
        'first_seen',
        'last_seen',
    ],
    'malware-analysis': [
        'submitted',
        'analysis_started',
        'analysis_ended',
    ],
    'observed-data': [
        'first_observed',
        'last_observed',
    ],
    'report': [
        'published',
    ],
    'relationship': [
        'start_time',
        'stop_time',
    ],
    'sighting': [
        'first_seen',
        'last_seen',
    ],
    'threat-actor': [
        'first_seen',
        'last_seen'
    ],
}


# Mapping of official STIX Cyber Observable objects to their timestamp
# properties
TIMESTAMP_OBSERVABLE_PROPERTIES = {
    'directory': [
        'ctime',
        'mtime',
        'atime',
    ],
    'email-message': [
        'date',
    ],
    'file': [
        'ctime',
        'mtime',
        'atime',
    ],
    'network-traffic': [
        'start',
        'end',
    ],
    'process': [
        'created',
    ],
    'user-account': [
        'account_created',
        'account_expires',
        'credential_last_changed',
        'account_first_login',
        'account_last_login',
    ],
    'windows-registry-key': [
        'modified_time',
    ],
    'x509-certificate': [
        'validity_not_before',
        'validity_not_after',
    ],
}

# Mapping of STIX Cyber Observable object to their timestamp-typed
# embedded properties
TIMESTAMP_EMBEDDED_PROPERTIES = {
    'file': {
        'extensions': [
            'time_date_stamp',
        ],
    },
    'x509-certificate': {
        'x509_v3_extensions': [
            'private_key_usage_period_not_before',
            'private_key_usage_period_not_after',
        ],
    },
}

# Mapping of STIX Object timestamp properties with a comparison requirement
# E.g. MUST be greater than or equal tovalues
# created/modified are already checked
TIMESTAMP_COMPARE = {
    "campaign": [
        ('last_seen', 'ge', 'first_seen'),
    ],
    "indicator": [
        ('valid_until', 'gt', 'valid_from'),
    ],
    "infrastructure": [
        ('last_seen', 'ge', 'first_seen'),
    ],
    "intrusion-set": [
        ('last_seen', 'ge', 'first_seen'),
    ],
    "malware": [
        ('last_seen', 'ge', 'first_seen'),
    ],
    "observed-data": [
        ('last_observed', 'ge', 'first_observed'),
    ],
    "relationship": [
        ('stop_time', 'gt', 'start_time'),
    ],
    "sighting": [
        ('last_seen', 'gt', 'first_seen'),
    ],
    'threat-actor': [
        ('last_seen', 'ge', 'first_seen')
    ]
}

# Mapping of STIX Object timestamp properties with a comparison requirement
TIMESTAMP_COMPARE_OBSERVABLE = {
    "network-traffic": [
        ('end', 'gt', 'start'),
    ],
}

# Mapping of official STIX objects to their open-vocab properties
VOCAB_PROPERTIES = {
    "artifact": [
        'hashes'
    ],
    "file": [
        "hashes",
    ],
    "grouping-of-action": [
        'context',
    ],
    "identity": [
        'identity_class',
        'sectors',
    ],
    "indicator": [
        'indicator_types',
    ],
    "infrastructure": [
        'infrastructure_types',
    ],
    "intrusion-set": [
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
    ],
    "location": [
        'region',
    ],
    "malware": [
        'malware_types',
        'architecture_execution_envs',
        'implementation_languages',
        'capabilities',
    ],
    "malware-analysis": [
        'result',
    ],
    "ntfs-ext": [
        'hashes',
    ],
    "report": [
        'report_types',
    ],
    "sections": [
        "hashes",
    ],
    "threat-actor": [
        'threat_actor_types',
        'roles',
        'sophistication',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
        'personal_motivations',
    ],
    "tool": [
        'tool_types',
    ],
    "marking-definition": [
        'definition_type',
    ],
    "windows-pebinary-ext": [
        "file_header_hashes",
    ],
    "x509-certificate": [
        "hashes",
    ]
}

DEPRECATED_PROPERTIES = {
    'observed-data': ['objects'],
}


# Mapping of check code numbers to names
CHECK_CODES = {
    '1': 'format-checks',
    '101': 'custom-prefix',
    '102': 'custom-prefix-lax',
    '103': 'uuid-check',
    '111': 'open-vocab-format',
    '121': 'kill-chain-names',
    '141': 'observable-object-keys',
    '142': 'observable-dictionary-keys',
    '143': 'malware-analysis-product',
    '149': 'windows-process-priority-format',
    '150': 'hash-length',
    '2': 'approved-values',
    '201': 'marking-definition-type',
    '202': 'relationship-types',
    '203': 'duplicate-ids',
    '210': 'all-vocabs',
    '211': 'attack-motivation',
    '212': 'attack-resource-level',
    '213': 'identity-class',
    '214': 'indicator-types',
    '215': 'industry-sector',
    '216': 'malware-types',
    '218': 'report-types',
    '219': 'threat-actor-types',
    '220': 'threat-actor-role',
    '221': 'threat-actor-sophistication',
    '222': 'tool-types',
    '223': 'region',
    '225': 'grouping-context',
    '226': 'implementation-languages',
    '227': 'infrastructure-types',
    '228': 'malware-capabilities',
    '230': 'processor-architecture',
    '231': 'malware-result',
    '241': 'hash-algo',
    '243': 'windows-pebinary-type',
    '244': 'account-type',
    '245': 'indicator-pattern-types',
    '270': 'all-external-sources',
    '271': 'mime-type',
    '272': 'protocols',
    '273': 'ipfix',
    '274': 'http-request-headers',
    '275': 'socket-options',
    '276': 'pdf-doc-info',
    '277': 'countries',
    '301': 'network-traffic-ports',
    '302': 'extref-hashes',
    '303': 'indicator-properties',
    '304': 'deprecated-properties',
}


def media_types():
    """Return a list of the IANA Media (MIME) Types, or an empty list if the
    IANA website is unreachable.
    Store it as a function attribute so that we only build the list once.
    """
    if not hasattr(media_types, 'typelist'):
        tlist = []
        categories = [
            'application',
            'audio',
            'font',
            'image',
            'message',
            'model',
            'multipart',
            'text',
            'video'
        ]
        for cat in categories:
            try:
                data = requests.get('http://www.iana.org/assignments/'
                                    'media-types/%s.csv' % cat)
            except requests.exceptions.RequestException:
                return []

            types = []
            for line in data.iter_lines():
                if line:
                    line = line.decode("utf-8")
                    if line.count(',') > 0:
                        reg_template = line.split(',')[1]
                        if reg_template:
                            types.append(reg_template)
                        else:
                            types.append(cat + '/' + line.split(',')[0])

            tlist.extend(types)
        media_types.typelist = tlist
    return media_types.typelist


def char_sets():
    """Return a list of the IANA Character Sets, or an empty list if the
    IANA website is unreachable.
    Store it as a function attribute so that we only build the list once.
    """
    if not hasattr(char_sets, 'setlist'):
        clist = []
        try:
            data = requests.get('http://www.iana.org/assignments/character-'
                                'sets/character-sets-1.csv')
        except requests.exceptions.RequestException:
            return []

        for line in data.iter_lines():
            if line:
                line = line.decode("utf-8")
                if line.count(',') > 0:
                    vals = line.split(',')
                    if vals[0]:
                        clist.append(vals[0])
                    else:
                        clist.append(vals[1])

        char_sets.setlist = clist
    return char_sets.setlist


def protocols():
    """Return a list of values from the IANA Service Name and Transport
    Protocol Port Number Registry, or an empty list if the IANA website is
    unreachable.
    Store it as a function attribute so that we only build the list once.
    """
    if not hasattr(protocols, 'protlist'):
        plist = []
        try:
            data = requests.get('http://www.iana.org/assignments/service-names'
                                '-port-numbers/service-names-port-numbers.csv')
        except requests.exceptions.RequestException:
            return []

        for line in data.iter_lines():
            if line:
                line = line.decode("utf-8")
                if line.count(',') > 0:
                    vals = line.split(',')
                    if vals[0]:
                        plist.append(vals[0])
                    if len(vals) > 2 and vals[2] and vals[2] not in plist:
                        plist.append(vals[2])

        plist.append('ipv4')
        plist.append('ipv6')
        plist.append('ssl')
        plist.append('tls')
        plist.append('dns')
        protocols.protlist = plist
    return protocols.protlist


def ipfix():
    """Return a list of values from the list of IANA IP Flow Information Export
    (IPFIX) Entities, or an empty list if the IANA website is unreachable.
    Store it as a function attribute so that we only build the list once.
    """
    if not hasattr(ipfix, 'ipflist'):
        ilist = []
        try:
            data = requests.get('http://www.iana.org/assignments/ipfix/ipfix-'
                                'information-elements.csv')
        except requests.exceptions.RequestException:
            return []

        for line in data.iter_lines():
            if line:
                line = line.decode("utf-8")
                if re.match(r'^\d+(,[a-zA-Z0-9]+){2},', line):
                    vals = line.split(',')
                    if vals[1]:
                        ilist.append(vals[1])

        ipfix.ipflist = ilist
    return ipfix.ipflist


# If you have a Socket Option not present in this list
# for SO|ICMP|ICMP6|IP|IPV6|MCAST|TCP|IRLMP please open an issue/PR
# in https://github.com/oasis-open/cti-stix-validator/ to include it.
# Include a reference (link) to where its defined.
SOCKET_OPTIONS = [
    'ICMP6_FILTER',
    'IP_ADD_MEMBERSHIP',
    'IP_ADD_SOURCE_MEMBERSHIP',
    'IP_BIND_ADDRESS_NO_PORT',
    'IP_BLOCK_SOURCE',
    'IP_DONTFRAGMENT',
    'IP_DROP_MEMBERSHIP',
    'IP_DROP_SOURCE_MEMBERSHIP',
    'IP_FREEBIND',
    'IP_HDRINCL',
    'IP_MSFILTER',
    'IP_MTU',
    'IP_MTU_DISCOVER',
    'IP_MULTICAST_ALL',
    'IP_MULTICAST_IF',
    'IP_MULTICAST_LOOP',
    'IP_MULTICAST_TTL',
    'IP_NODEFRAG',
    'IP_OPTIONS',
    'IP_ORIGINAL_ARRIVAL_IF',
    'IP_PKTINFO',
    'IP_RECEIVE_BROADCAST',
    'IP_RECVDSTADDR',
    'IP_RECVERR',
    'IP_RECVIF',
    'IP_RECVOPTS',
    'IP_RECVORIGDSTADDR',
    'IP_RECVTOS',
    'IP_RECVTTL',
    'IP_RETOPTS',
    'IP_ROUTER_ALERT',
    'IP_TOS',
    'IP_TRANSPARENT',
    'IP_TTL',
    'IP_UNBLOCK_SOURCE',
    'IP_UNICAST_IF',
    'IP_WFP_REDIRECT_CONTEXT',
    'IP_WFP_REDIRECT_RECORDS',
    'IPV6_ADD_MEMBERSHIP',
    'IPV6_CHECKSUM',
    'IPV6_DONTFRAG',
    'IPV6_DROP_MEMBERSHIP',
    'IPV6_DSTOPTS',
    'IPV6_HDRINCL',
    'IPV6_HOPLIMIT',
    'IPV6_HOPOPTS',
    'IPV6_JOIN_GROUP',
    'IPV6_LEAVE_GROUP',
    'IPV6_MTU',
    'IPV6_MTU_DISCOVER',
    'IPV6_MULTICAST_HOPS',
    'IPV6_MULTICAST_IF',
    'IPV6_MULTICAST_LOOP',
    'IPV6_NEXTHOP',
    'IPV6_PATHMTU',
    'IPV6_PKTINFO',
    'IPV6_PROTECTION_LEVEL',
    'IPV6_RECVDSTOPTS',
    'IPV6_RECVHOPLIMIT',
    'IPV6_RECVHOPOPTS',
    'IPV6_RECVIF',
    'IPV6_RECVPATHMTU',
    'IPV6_RECVPKTINFO',
    'IPV6_RECVRTHDR',
    'IPV6_RECVTCLASS',
    'IPV6_RTHDR',
    'IPV6_TCLASS',
    'IPV6_UNICAST_HOPS',
    'IPV6_UNICAST_IF',
    'IPV6_UNICAT_HOPS',
    'IPV6_USE_MIN_MTU',
    'IPV6_V6ONLY',
    'IRLMP_9WIRE_MODE',
    'IRLMP_DISCOVERY_MODE',
    'IRLMP_ENUMDEVICES',
    'IRLMP_EXCLUSIVE_MODE',
    'IRLMP_IAS_QUERY',
    'IRLMP_IAS_SET',
    'IRLMP_IRLPT_MODE',
    'IRLMP_PARAMETERS',
    'IRLMP_SEND_PDU_LEN',
    'IRLMP_SHARP_MODE',
    'IRLMP_TINYTP_MODE',
    'MCAST_BLOCK_SOURCE',
    'MCAST_JOIN_GROUP',
    'MCAST_JOIN_SOURCE_GROUP',
    'MCAST_LEAVE_GROUP',
    'MCAST_LEAVE_SOURCE_GROUP',
    'MCAST_UNBLOCK_SOURCE',
    'SO_ACCEPTCONN',
    'SO_ATTACH_BPF',
    'SO_ATTACH_FILTER',
    'SO_ATTACH_REUSEPORT_CBPF',
    'SO_BINDTODEVICE',
    'SO_BROADCAST',
    'SO_BSDCOMPAT',
    'SO_BSP_STATE',
    'SO_BUSY_POLL',
    'SO_CONDITIONAL_ACCEPT',
    'SO_CONFIRM_NAME',
    'SO_CONNDATA',
    'SO_CONNDATALEN',
    'SO_CONNECT_TIME',
    'SO_CONNOPT',
    'SO_CONNOPTLEN',
    'SO_DEBUG',
    'SO_DEREGISTER_NAME',
    'SO_DETACH_FILTER',
    'SO_DISCDATA',
    'SO_DISCDATALEN',
    'SO_DISCOPT',
    'SO_DISCOPTLEN',
    'SO_DOMAIN',
    'SO_DONTLINGER',
    'SO_DONTROUTE',
    'SO_ERROR',
    'SO_EXCLUSIVEADDRUSE',
    'SO_GETLOCALZONES',
    'SO_GETMYZONE',
    'SO_GETNETINFO',
    'SO_GETZONELIST',
    'SO_GROUP_ID',
    'SO_GROUP_PRIORITY',
    'SO_INCOMING_CPU',
    'SO_KEEPALIVE',
    'SO_LINGER',
    'SO_LOOKUP_MYZONE',
    'SO_LOOKUP_NAME',
    'SO_LOOKUP_NETDEF_ON_ADAPTER',
    'SO_LOOKUP_ZONES',
    'SO_LOOKUP_ZONES_ON_ADAPTER',
    'SO_MARK',
    'SO_MAX_MSG_SIZE',
    'SO_MAXDG',
    'SO_MAXPATHDG',
    'SO_OOBINLINE',
    'SO_OPENTYPE',
    'SO_PAP_GET_SERVER_STATUS',
    'SO_PAP_PRIME_READ',
    'SO_PAP_SET_SERVER_STATUS',
    'SO_PASSCRED',
    'SO_PASSSEC',
    'SO_PAUSE_ACCEPT',
    'SO_PEEK_OFF',
    'SO_PEERCRED',
    'SO_PORT_SCALABILITY',
    'SO_PRIORITY',
    'SO_PROTOCOL',
    'SO_PROTOCOL_INFO',
    'SO_PROTOCOL_INFOA',
    'SO_PROTOCOL_INFOW',
    'SO_RANDOMIZE_PORT',
    'SO_RCVBUF',
    'SO_RCVBUFFORCE',
    'SO_RCVLOWAT',
    'SO_RCVTIMEO',
    'SO_REGISTER_NAME',
    'SO_REMOVE_NAME',
    'SO_REUSE_MULTICASTPORT',
    'SO_REUSE_UNICASTPORT',
    'SO_REUSEADDR',
    'SO_REUSEPORT',
    'SO_RXQ_OVFL',
    'SO_SNDBUF',
    'SO_SNDBUFFORCE',
    'SO_SNDLOWAT',
    'SO_SNDTIMEO',
    'SO_TIMESTAMP',
    'SO_TYPE',
    'SO_UPDATE_ACCEPT_CONTEXT',
    'SO_UPDATE_CONNECT_CONTEXT',
    'SO_USELOOPBACK',
    'TCP_BSDURGENT',
    'TCP_CONGESTION',
    'TCP_CORK',
    'TCP_DEFER_ACCEPT',
    'TCP_EXPEDITED_1122',
    'TCP_FASTOPEN',
    'TCP_INFO',
    'TCP_KEEPCNT',
    'TCP_KEEPIDLE',
    'TCP_KEEPINTVL',
    'TCP_LINGER2',
    'TCP_MAXRT',
    'TCP_MAXSEG',
    'TCP_NODELAY',
    'TCP_QUICKACK',
    'TCP_SYNCNT',
    'TCP_TIMESTAMPS',
    'TCP_USER_TIMEOUT',
    'TCP_WINDOW_CLAMP',
]

PDF_DID = [
    'Title',
    'Author',
    'Subject',
    'Keywords',
    'Creator',
    'Producer',
    'CreationDate',
    'ModDate',
    'Trapped'
]

LANG_CODES = [
    'af', 'af-ZA', 'ar', 'ar-AE', 'ar-BH', 'ar-DZ', 'ar-EG', 'ar-IQ', 'ar-JO',
    'ar-KW', 'ar-LB', 'ar-LY', 'ar-MA', 'ar-OM', 'ar-QA', 'ar-SA', 'ar-SY',
    'ar-TN', 'ar-YE', 'az', 'az-AZ', 'az-Cyrl-AZ', 'be', 'be-BY', 'bg', 'bg-BG',
    'bs-BA', 'ca', 'ca-ES', 'cs', 'cs-CZ', 'cy', 'cy-GB', 'da', 'da-DK', 'de',
    'de-AT', 'de-CH', 'de-DE', 'de-LI', 'de-LU', 'dv', 'dv-MV', 'el', 'el-GR',
    'en', 'en-AU', 'en-BZ', 'en-CA', 'en-CB', 'en-GB', 'en-IE', 'en-JM',
    'en-NZ', 'en-PH', 'en-TT', 'en-US', 'en-ZA', 'en-ZW', 'eo', 'es', 'es-AR',
    'es-BO', 'es-CL', 'es-CO', 'es-CR', 'es-DO', 'es-EC', 'es-ES', 'es-GT',
    'es-HN', 'es-MX', 'es-NI', 'es-PA', 'es-PE', 'es-PR', 'es-PY', 'es-SV',
    'es-UY', 'es-VE', 'et', 'et-EE', 'eu', 'eu-ES', 'fa', 'fa-IR', 'fi',
    'fi-FI', 'fo', 'fo-FO', 'fr', 'fr-BE', 'fr-CA', 'fr-CH', 'fr-FR', 'fr-LU',
    'fr-MC', 'gl', 'gl-ES', 'gu', 'gu-IN', 'he', 'he-IL', 'hi', 'hi-IN', 'hr',
    'hr-BA', 'hr-HR', 'hu', 'hu-HU', 'hy', 'hy-AM', 'id', 'id-ID', 'is',
    'is-IS', 'it', 'it-CH', 'it-IT', 'ja', 'ja-JP', 'ka', 'ka-GE', 'kk',
    'kk-KZ', 'kn', 'kn-IN', 'ko', 'ko-KR', 'kok', 'kok-IN', 'ky', 'ky-KG',
    'lt', 'lt-LT', 'lv', 'lv-LV', 'mi', 'mi-NZ', 'mk', 'mk-MK', 'mn', 'mn-MN',
    'mr', 'mr-IN', 'ms', 'ms-BN', 'ms-MY', 'mt', 'mt-MT', 'nb', 'nb-NO', 'nl',
    'nl-BE', 'nl-NL', 'nn-NO', 'ns', 'ns-ZA', 'pa', 'pa-IN', 'pl', 'pl-PL',
    'ps', 'ps-AR', 'pt', 'pt-BR', 'pt-PT', 'qu', 'qu-BO', 'qu-EC', 'qu-PE',
    'ro', 'ro-RO', 'ru', 'ru-RU', 'sa', 'sa-IN', 'se', 'se-FI', 'se-NO',
    'se-SE', 'sk', 'sk-SK', 'sl', 'sl-SI', 'sq', 'sq-AL', 'sr-BA', 'sr-Cyrl-BA',
    'sr-SP', 'sr-Cyrl-SP', 'sv', 'sv-FI', 'sv-SE', 'sw', 'sw-KE', 'syr',
    'syr-SY', 'ta', 'ta-IN', 'te', 'te-IN', 'th', 'th-TH', 'tl', 'tl-PH', 'tn',
    'tn-ZA', 'tr', 'tr-TR', 'tt', 'tt-RU', 'ts', 'uk', 'uk-UA', 'ur', 'ur-PK',
    'uz', 'uz-UZ', 'uz-Cyrl-UZ', 'vi', 'vi-VN', 'xh', 'xh-ZA', 'zh', 'zh-CN',
    'zh-HK', 'zh-MO', 'zh-SG', 'zh-TW', 'zu', 'zu-ZA',
]

SOFTWARE_LANG_CODES = [
    'aar', 'abk', 'ace', 'ach', 'ada', 'ady', 'afa', 'afh', 'afr', 'ain',
    'aka', 'akk', 'alb', 'sqi', 'ale', 'alg', 'alt', 'amh', 'ang', 'anp',
    'apa', 'ara', 'arc', 'arg', 'arm', 'hye', 'arn', 'arp', 'art', 'arw',
    'asm', 'ast', 'ath', 'aus', 'ava', 'ave', 'awa', 'aym', 'aze', 'bad',
    'bai', 'bak', 'bal', 'bam', 'ban', 'baq', 'eus', 'bas', 'bat', 'bej',
    'bel', 'bem', 'ben', 'ber', 'bho', 'bih', 'bik', 'bin', 'bis', 'bla',
    'bnt', 'tib', 'bod', 'bos', 'bra', 'bre', 'btk', 'bua', 'bug', 'bul',
    'bur', 'mya', 'byn', 'cad', 'cai', 'car', 'cat', 'cau', 'ceb', 'cel',
    'cze', 'ces', 'cha', 'chb', 'che', 'chg', 'chi', 'zho', 'chk', 'chm',
    'chn', 'cho', 'chp', 'chr', 'chu', 'chv', 'chy', 'cmc', 'cop', 'cor',
    'cos', 'cpe', 'cpf', 'cpp', 'cre', 'crh', 'crp', 'csb', 'cus', 'wel',
    'cym', 'cze', 'ces', 'dak', 'dan', 'dar', 'day', 'del', 'den', 'ger',
    'deu', 'dgr', 'din', 'div', 'doi', 'dra', 'dsb', 'dua', 'dum', 'dut',
    'nld', 'dyu', 'dzo', 'efi', 'egy', 'eka', 'gre', 'ell', 'elx', 'eng',
    'enm', 'epo', 'est', 'baq', 'eus', 'ewe', 'ewo', 'fan', 'fao', 'per',
    'fas', 'fat', 'fij', 'fil', 'fin', 'fiu', 'fon', 'fre', 'fra', 'frm',
    'fro', 'frr', 'frs', 'fry', 'ful', 'fur', 'gaa', 'gay', 'gba', 'gem',
    'geo', 'kat', 'ger', 'deu', 'gez', 'gil', 'gla', 'gle', 'glg', 'glv',
    'gmh', 'goh', 'gon', 'gor', 'got', 'grb', 'grc', 'gre', 'ell', 'grn',
    'gsw', 'guj', 'gwi', 'hai', 'hat', 'hau', 'haw', 'heb', 'her', 'hil',
    'him', 'hin', 'hit', 'hmn', 'hmo', 'hrv', 'hsb', 'hun', 'hup', 'arm',
    'hye', 'iba', 'ibo', 'ice', 'isl', 'ido', 'iii', 'ijo', 'iku', 'ile',
    'ilo', 'ina', 'inc', 'ind', 'ine', 'inh', 'ipk', 'ira', 'iro', 'ice',
    'isl', 'ita', 'jav', 'jbo', 'jpn', 'jpr', 'jrb', 'kaa', 'kab', 'kac',
    'kal', 'kam', 'kan', 'kar', 'kas', 'geo', 'kat', 'kau', 'kaw', 'kaz',
    'kbd', 'kha', 'khi', 'khm', 'kho', 'kik', 'kin', 'kir', 'kmb', 'kok',
    'kom', 'kon', 'kor', 'kos', 'kpe', 'krc', 'krl', 'kro', 'kru', 'kua',
    'kum', 'kur', 'kut', 'lad', 'lah', 'lam', 'lao', 'lat', 'lav', 'lez',
    'lim', 'lin', 'lit', 'lol', 'loz', 'ltz', 'lua', 'lub', 'lug', 'lui',
    'lun', 'luo', 'lus', 'mac', 'mkd', 'mad', 'mag', 'mah', 'mai', 'mak',
    'mal', 'man', 'mao', 'mri', 'map', 'mar', 'mas', 'may', 'msa', 'mdf',
    'mdr', 'men', 'mga', 'mic', 'min', 'mis', 'mac', 'mkd', 'mkh', 'mlg',
    'mlt', 'mnc', 'mni', 'mno', 'moh', 'mon', 'mos', 'mao', 'mri', 'may',
    'msa', 'mul', 'mun', 'mus', 'mwl', 'mwr', 'bur', 'mya', 'myn', 'myv',
    'nah', 'nai', 'nap', 'nau', 'nav', 'nbl', 'nde', 'ndo', 'nds', 'nep',
    'new', 'nia', 'nic', 'niu', 'dut', 'nld', 'nno', 'nob', 'nog', 'non',
    'nor', 'nqo', 'nso', 'nub', 'nwc', 'nya', 'nym', 'nyn', 'nyo', 'nzi',
    'oci', 'oji', 'ori', 'orm', 'osa', 'oss', 'ota', 'oto', 'paa', 'pag',
    'pal', 'pam', 'pan', 'pap', 'pau', 'peo', 'per', 'fas', 'phi', 'phn',
    'pli', 'pol', 'pon', 'por', 'pra', 'pro', 'pus', 'qaa-qtz', 'que', 'raj',
    'rap', 'rar', 'roa', 'roh', 'rom', 'rum', 'ron', 'run', 'rup', 'rus',
    'sad', 'sag', 'sah', 'sai', 'sal', 'sam', 'san', 'sas', 'sat', 'scn',
    'sco', 'sel', 'sem', 'sga', 'sgn', 'shn', 'sid', 'sin', 'sio', 'sit',
    'sla', 'slo', 'slk', 'slv', 'sma', 'sme', 'smi', 'smj', 'smn', 'smo',
    'sms', 'sna', 'snd', 'snk', 'sog', 'som', 'son', 'sot', 'spa', 'alb',
    'sqi', 'srd', 'srn', 'srp', 'srr', 'ssa', 'ssw', 'suk', 'sun', 'sus',
    'sux', 'swa', 'swe', 'syc', 'syr', 'tah', 'tai', 'tam', 'tat', 'tel',
    'tem', 'ter', 'tet', 'tgk', 'tgl', 'tha', 'tib', 'bod', 'tig', 'tir',
    'tiv', 'tkl', 'tlh', 'tli', 'tmh', 'tog', 'ton', 'tpi', 'tsi', 'tsn',
    'tso', 'tuk', 'tum', 'tup', 'tur', 'tut', 'tvl', 'twi', 'tyv', 'udm',
    'uga', 'uig', 'ukr', 'umb', 'und', 'urd', 'uzb', 'vai', 'ven', 'vie',
    'vol', 'vot', 'wak', 'wal', 'war', 'was', 'wel', 'cym', 'wen', 'wln',
    'wol', 'xal', 'xho', 'yao', 'yap', 'yid', 'yor', 'ypk', 'zap', 'zbl',
    'zen', 'zgh', 'zha', 'chi', 'zho', 'znd', 'zul', 'zun', 'zxx', 'zza'
]

COUNTRY_CODES = [
    'AC', 'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AN', 'AO', 'AP', 'AQ',
    'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF',
    'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BR', 'BS', 'BT',
    'BU', 'BV', 'BW', 'BX', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH',
    'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CP', 'CR', 'CS', 'CT', 'CU', 'CV',
    'CW', 'CX', 'CY', 'CZ', 'DD', 'DE', 'DG', 'DJ', 'DK', 'DM', 'DO', 'DY',
    'DZ', 'EA', 'EC', 'EE', 'EF', 'EG', 'EH', 'EM', 'EP', 'ER', 'ES', 'ET',
    'EU', 'EV', 'EW', 'EZ', 'FI', 'FJ', 'FK', 'FL', 'FM', 'FO', 'FQ', 'FR',
    'FX', 'GA', 'GB', 'GC', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GL', 'GM',
    'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM', 'HN',
    'HR', 'HT', 'HU', 'HV', 'IB', 'IC', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO',
    'IQ', 'IR', 'IS', 'IT', 'JA', 'JE', 'JM', 'JO', 'JP', 'JT', 'KE', 'KG',
    'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC',
    'LF', 'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD',
    'ME', 'MF', 'MG', 'MH', 'MI', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ',
    'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE',
    'NF', 'NG', 'NH', 'NI', 'NL', 'NO', 'NP', 'NQ', 'NR', 'NT', 'NU', 'NZ',
    'OA', 'OM', 'PA', 'PC', 'PE', 'PF', 'PG', 'PH', 'PI', 'PK', 'PL', 'PM',
    'PN', 'PR', 'PS', 'PT', 'PU', 'PW', 'PY', 'PZ', 'QA', 'RA', 'RB', 'RC',
    'RE', 'RH', 'RI', 'RL', 'RM', 'RN', 'RO', 'RP', 'RS', 'RU', 'RW', 'SA',
    'SB', 'SC', 'SD', 'SE', 'SF', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM',
    'SN', 'SO', 'SR', 'SS', 'ST', 'SU', 'SV', 'SX', 'SY', 'SZ', 'TA', 'TC',
    'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TP', 'TR',
    'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UK', 'UM', 'UN', 'US', 'UY', 'UZ',
    'VA', 'VC', 'VD', 'VE', 'VG', 'VI', 'VN', 'VU', 'WF', 'WG', 'WK', 'WL',
    'WO', 'WS', 'WV', 'YD', 'YE', 'YT', 'YU', 'YV', 'ZA', 'ZM', 'ZR', 'ZW',
]

HTTP_REQUEST_HEADERS = [
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Datetime",
    "Authorization",
    "Cache-Control",
    "Connection",
    "Cookie",
    "Content-Length",
    "Content-MD5",
    "Content-Type",
    "Date",
    "Expect",
    "Forwarded",
    "From",
    "Host",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Max-Forwards",
    "Origin",
    "Pragma",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "TE",
    "User-Agent",
    "Upgrade",
    "Via",
    "Warning",
    "X-Requested-With",
    "DNT",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "Front-End-Https",
    "X-Http-Method-Override",
    "X-ATT-DeviceId",
    "X-Wap-Profile",
    "Proxy-Connection",
    "X-UIDH",
    "X-Csrf-Token",
    "X-Request-ID",
    "X-Correlation-ID"
]
