"""STIX 2.0 open vocabularies and other lists
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
    "unpredictable"
]
ATTACK_RESOURCE_LEVEL_OV = [
    "individual",
    "club",
    "contest",
    "team",
    "organization",
    "government"
]
IDENTITY_CLASS_OV = [
    "individual",
    "group",
    "organization",
    "class",
    "unknown"
]
INDICATOR_LABEL_OV = [
    "anomalous-activity",
    "anonymization",
    "benign",
    "compromised",
    "malicious-activity",
    "attribution"
]
INDUSTRY_SECTOR_OV = [
    "agriculture",
    "aerospace",
    "automotive",
    "communications",
    "construction",
    "defence",
    "education",
    "energy",
    "entertainment",
    "financial-services",
    "government-national",
    "government-regional",
    "government-local",
    "government-public-services",
    "healthcare",
    "hospitality-leisure",
    "infrastructure",
    "insurance",
    "manufacturing",
    "mining",
    "non-profit",
    "pharmaceuticals",
    "retail",
    "technology",
    "telecommunications",
    "transportation",
    "utilities"
]
MALWARE_LABEL_OV = [
    "adware",
    "backdoor",
    "bot",
    "ddos",
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
    "virus",
    "worm"
]
REPORT_LABEL_OV = [
    "threat-report",
    "attack-pattern",
    "campaign",
    "identity",
    "indicator",
    "malware",
    "observed-data",
    "threat-actor",
    "tool",
    "vulnerability"
]
THREAT_ACTOR_LABEL_OV = [
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
    "terrorist"
]
THREAT_ACTOR_ROLE_OV = [
    "agent",
    "director",
    "independent",
    "infrastructure-architect",
    "infrastructure-operator",
    "malware-author",
    "sponsor"
]
THREAT_ACTOR_SOPHISTICATION_OV = [
    "none",
    "minimal",
    "intermediate",
    "advanced",
    "expert",
    "innovator",
    "strategic"
]
TOOL_LABEL_OV = [
    "denial-of-service",
    "exploitation",
    "information-gathering",
    "network-capture",
    "credential-exploitation",
    "remote-access",
    "vulnerability-scanning"
]
HASH_ALGO_OV = [
    "MD5",
    "MD6",
    "RIPEMD-160",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "ssdeep",
    "WHIRLPOOL"
]
ENCRYPTION_ALGO_OV = [
    "AES128-ECB",
    "AES128-CBC",
    "AES128-CFB",
    "AES128-COFB",
    "AES128-CTR",
    "AES128-XTS",
    "AES128-GCM",
    "Salsa20",
    "Salsa12",
    "Salsa8",
    "ChaCha20-Poly1305",
    "ChaCha20",
    "DES-CBC",
    "3DES-CBC",
    "DES-EBC",
    "3DES-EBC",
    "CAST128-CBC",
    "CAST256-CBC",
    "RSA",
    "DSA"
]
WINDOWS_PEBINARY_TYPE_OV = [
    "exe",
    "dll",
    "sys"
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
    "twitter"
]


# Dictionaries mapping object types to properties that use a given vocabulary
ATTACK_MOTIVATION_USES = {
    "intrusion-set": [
        "primary_motivation",
        "secondary_motivations"
    ],
    "threat-actor": [
        "primary_motivation",
        "secondary_motivations",
        "personal_motivations"
    ]
}
ATTACK_RESOURCE_LEVEL_USES = {
    "intrusion-set": ["resource_level"],
    "threat-actor": ["resource_level"]
}
IDENTITY_CLASS_USES = {
    "identity": ["identity_class"]
}
INDICATOR_LABEL_USES = {
    "indicator": ["labels"]
}
INDUSTRY_SECTOR_USES = {
    "identity": ["sectors"]
}
MALWARE_LABEL_USES = {
    "malware": ["labels"]
}
REPORT_LABEL_USES = {
    "report": ["labels"]
}
THREAT_ACTOR_LABEL_USES = {
    "threat-actor": ["labels"]
}
THREAT_ACTOR_ROLE_USES = {
    "threat-actor": ["roles"]
}
THREAT_ACTOR_SOPHISTICATION_USES = {
    "threat-actor": ["sophistication"]
}
TOOL_LABEL_USES = {
    "tool": ["labels"]
}


# List of default STIX object types
TYPES = [
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
    "indicator",
    "intrusion-set",
    "malware",
    "observed-data",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
    "bundle",
    "relationship",
    "sighting",
    "marking-definition"
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
    "x509-certificate"
]

# List of default marking definition types
MARKING_DEFINITION_TYPES = [
    "statement",
    "tlp"
]

# List of object types which have a `kill-chain-phases` property
KILL_CHAIN_PHASE_USES = [
    "attack-pattern",
    "indicator",
    "malware",
    "tool"
]


# Mapping of official STIX objects to their official properties
PROPERTIES = {
    "attack-pattern": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'kill_chain_phases'
    ],
    "campaign": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'aliases',
        'first_seen',
        'last_seen',
        'objective'
    ],
    "course-of-action": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'action'
    ],
    "identity": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'identity_class',
        'sectors',
        'contact_information'
    ],
    "indicator": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'pattern',
        'valid_from',
        'valid_until',
        'kill_chain_phases'
    ],
    "intrusion-set": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
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
        'secondary_motivations'
    ],
    "malware": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'kill_chain_phases'
    ],
    "observed-data": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'first_observed',
        'last_observed',
        'number_observed',
        'objects'
    ],
    "report": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'published',
        'object_refs'
    ],
    "threat-actor": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'aliases',
        'roles',
        'goals',
        'sophistication',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
        'personal_motivations'
    ],
    "tool": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'kill_chain_phases',
        'tool_version'
    ],
    "vulnerability": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description'
    ],
    "bundle": [
        'type',
        'id',
        'spec_version',
        'objects'
    ],
    "relationship": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'relationship_type',
        'description',
        'source_ref',
        'target_ref'
    ],
    "sighting": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'first_seen',
        'last_seen',
        'count',
        'sighting_of_ref',
        'observed_data_refs',
        'where_sighted_refs',
        'summary'
    ],
    "marking-definition": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'definition_type',
        'definition'
    ]
}
# Mappings of official Cyber Observable Objects to their official properties
OBSERVABLE_PROPERTIES = {
    'artifact': [
        'type',
        'extensions',
        'mime_type',
        'payload_bin',
        'url',
        'hashes'
    ],
    'autonomous-system': [
        'type',
        'extensions',
        'number',
        'name',
        'rir'
    ],
    'directory': [
        'type',
        'extensions',
        'path',
        'path_enc',
        'created',
        'modified',
        'accessed',
        'contains_refs'
    ],
    'domain-name': [
        'type',
        'extensions',
        'value',
        'resolves_to_refs'
    ],
    'email-addr': [
        'type',
        'extensions',
        'value',
        'display_name',
        'belongs_to_ref'
    ],
    'email-message': [
        'type',
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
        'body',
        'body_multipart',
        'raw_email_ref'
    ],
    'file': [
        'type',
        'extensions',
        'hashes',
        'size',
        'name',
        'name_enc',
        'magic_number_hex',
        'mime_type',
        'created',
        'modified',
        'accessed',
        'parent_directory_ref',
        'is_encrypted',
        'encryption_algorithm',
        'decryption_key',
        'contains_refs',
        'content_ref'
    ],
    'ipv4-addr': [
        'type',
        'extensions',
        'value',
        'resolves_to_refs',
        'belongs_to_refs'
    ],
    'ipv6-addr': [
        'type',
        'extensions',
        'value',
        'resolves_to_refs',
        'belongs_to_refs'
    ],
    'mac-addr': [
        'type',
        'extensions',
        'value'
    ],
    'mutex': [
        'type',
        'extensions',
        'name'
    ],
    'network-traffic': [
        'type',
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
        'encapsulated_by_ref'
    ],
    'process': [
        'type',
        'extensions',
        'is_hidden',
        'pid',
        'name',
        'created',
        'cwd',
        'arguments',
        'command_line',
        'environment_variables',
        'opened_connection_refs',
        'creator_user_ref',
        'binary_ref',
        'parent_ref',
        'child_refs'
    ],
    'software': [
        'type',
        'extensions',
        'name',
        'cpe',
        'languages',
        'vendor',
        'version'
    ],
    'url': [
        'type',
        'extensions',
        'value'
    ],
    'user-account': [
        'type',
        'extensions',
        'user_id',
        'account_login',
        'account_type',
        'display_name',
        'is_service_account',
        'is_privileged',
        'can_escalate_privs',
        'is_disabled',
        'account_created',
        'account_expires',
        'password_last_changed',
        'account_first_login',
        'account_last_login'
    ],
    'windows-registry-key': [
        'type',
        'extensions',
        'key',
        'values',
        'modified',
        'creator_user_ref',
        'number_of_subkeys'
    ],
    'x509-certificate': [
        'type',
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
        'subject_public_key_modulus',
        'subject_public_key_exponent',
        'x509_v3_extensions'
    ]
}
OBSERVABLE_EXTENSION_PROPERTIES = {
    'archive-ext': [
        'contains_refs',
        'version',
        'comment'
    ],
    'ntfs-ext': [
        'sid',
        'alternate_data_streams'
    ],
    'pdf-ext': [
        'version',
        'is_optimized',
        'document_info_dict',
        'pdfid0',
        'pdfid1'
    ],
    'raster-image-ext': [
        'image_height',
        'image_width',
        'bits_per_pixel',
        'image_compression_algorithm',
        'exif_tags'
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
        'sections'
    ],
    'http-request-ext': [
        'request_method',
        'request_value',
        'request_version',
        'request_header',
        'message_body_length',
        'message_body_data_ref'
    ],
    'icmp-ext': [
        'icmp_type_hex',
        'icmp_code_hex'
    ],
    'socket-ext': [
        'address_family',
        'is_blocking',
        'is_listening',
        'protocol_family',
        'options',
        'socket_type',
        'socket_descriptor',
        'socket_handle'
    ],
    'tcp-ext': [
        'src_flags_hex',
        'dst_flags_hex'
    ],
    'windows-process-ext': [
        'aslr_enabled',
        'dep_enabled',
        'priority',
        'owner_sid',
        'window_title',
        'startup_info'
    ],
    'windows-service-ext': [
        'service_name',
        'descriptions',
        'display_name',
        'group_name',
        'start_type',
        'service_dll_refs',
        'service_type',
        'service_status'
    ],
    'unix-account-ext': [
        'gid',
        'groups',
        'home_dir',
        'shell'
    ]
}
# Mappings of properties of embedded cyber observable types
OBSERVABLE_EMBEDDED_PROPERTIES = {
    'email-message': {
        'body_multipart': [
            'body',
            'body_raw_ref',
            'content_type',
            'content_disposition'
        ]
    },
    'windows-registry-key': {
        'values': [
            'name',
            'data',
            'data_type'
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
            'policy_mappings'
        ]
    }
}
OBSERVABLE_EXTENSION_EMBEDDED_PROPERTIES = {
    'ntfs-ext': {
        'alternate_data_streams': [
            'name',
            'hashes',
            'size'
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
            'hashes'
        ],
        'sections': [
            'name',
            'size',
            'entropy',
            'hashes'
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
        'windows-pebinary-ext'
    ],
    'network-traffic': [
        'http-request-ext',
        'icmp-ext',
        'socket-ext',
        'tcp-ext'
    ],
    'process': [
        'windows-process-ext',
        'windows-service-ext',
    ],
    'user-account': [
        'unix-account-ext'
    ]
}

# Maping of Observable Object properties that reference other Objects
OBSERVABLE_PROP_REFS = {
    'directory': {
        'contains_refs': [
            'file',
            'directory'
        ]
    },
    'domain-name': {
        'resolves_to_refs': [
            'ipv4-addr',
            'ipv6-addr',
            'domain-name'
        ]
    },
    'email-addr': {
        'belongs_to_ref': [
            'user-account'
        ]
    },
    'email-message': {
        'from_ref': [
            'email-addr'
        ],
        'sender_ref': [
            'email-addr'
        ],
        'to_refs': [
            'email-addr'
        ],
        'cc_refs': [
            'email-addr'
        ],
        'bcc_refs': [
            'email-addr'
        ],
        'raw_email_ref': [
            'artifact'
        ],
        'body_multipart': {
            'body_raw_ref': [
                'artifact',
                'file'
            ]
        }
    },
    'file': {
        'parent_directory_ref': [
            'directory'
        ],
        'content_ref': [
            'artifact'
        ],
        'extensions': {
            'archive-ext': {
                'contains_refs': [
                    'file'
                ]
            }
        }
    },
    'ipv4-addr': {
        'resolves_to_refs': [
            'mac-addr'
        ],
        'belongs_to_refs': [
            'autonomous-system'
        ]
    },
    'ipv6-addr': {
        'resolves_to_refs': [
            'mac-addr'
        ],
        'belongs_to_refs': [
            'autonomous-system'
        ]
    },
    'network-traffic': {
        'src_ref': [
            'ipv4-addr',
            'ipv6-addr',
            'mac-addr',
            'domain-name'
        ],
        'dst_ref': [
            'ipv4-addr',
            'ipv6-addr',
            'mac-addr',
            'domain-name'
        ],
        'src_payload_ref': [
            'artifact'
        ],
        'dst_payload_ref': [
            'artifact'
        ],
        'encapsulates_refs': [
            'network-traffic'
        ],
        'encapsulated_by_ref': [
            'network-traffic'
        ],
        'extensions': {
            'http-request-ext': {
                'message_body_data_ref': [
                    'artifact'
                ]
            }
        }
    },
    'process': {
        'opened_connection_refs': [
            'network-traffic'
        ],
        'creator_user_ref': [
            'user-account'
        ],
        'binary_ref': [
            'file'
        ],
        'parent_ref': [
            'process'
        ],
        'child_refs': [
            'process'
        ],
        'extensions': {
            'windows-service-ext': {
                'service_dll_refs': [
                    'file'
                ]
            }
        }
    },
    'windows-registry-key': {
        'creator_user_ref': [
            'user-account'
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
    'startup_info'
]

# Reserved properties and objects
RESERVED_PROPERTIES = [
    'confidence',
    'severity',
    'action',
    'usernames',
    'phone_numbers',
    'addresses',
    'first_seen_precision',
    'last_seen_precision',
    'valid_from_precision',
    'valid_until_precision'
]
RESERVED_OBJECTS = [
    'incident',
    'infrastructure'
]
OBSERVABLE_RESERVED_OBJECTS = [
    'action'
]


NON_SDOS = [
    'bundle',
    'marking-definition',
    'sighting',
    'relationship'
]

# List of relationship types common to all object types
COMMON_RELATIONSHIPS = [
    'derived-from',
    'duplicate-of',
    'related-to'
]

# Mapping of official STIX objects to their official relationships
RELATIONSHIPS = {
    'attack-pattern': {
        'targets': [
            'vulnerability',
            'identity'
        ],
        'uses': [
            'malware',
            'tool'
        ]
    },
    'campaign': {
        'attributed-to': [
            'intrusion-set',
            'threat-actor'
        ],
        'targets': [
            'identity',
            'vulnerability'
        ],
        'uses': [
            'attack-pattern',
            'malware',
            'tool'
        ]
    },
    'course-of-action': {
        'mitigates': [
            'attack-pattern',
            'malware',
            'tool',
            'vulnerability'
        ]
    },
    'indicator': {
        'indicates': [
            'attack-pattern',
            'campaign',
            'intrusion-set',
            'malware',
            'threat-actor',
            'tool'
        ],
    },
    'intrusion-set': {
        'attributed-to': 'threat-actor',
        'targets': [
            'identity',
            'vulnerability',
        ],
        'uses': [
            'attack-pattern',
            'malware',
            'tool'
        ],
    },
    'malware': {
        'targets': [
            'identity',
            'vulnerability'
        ],
        'uses': 'tool',
        'variant-of': 'malware'
    },
    'threat-actor': {
        'attributed-to': 'identity',
        'impersonates': 'identity',
        'targets': [
            'identity',
            'vulnerability'
        ],
        'uses': [
            'attack-pattern',
            'malware',
            'tool'
        ]
    },
    'tool': {
        'targets': [
            'identity',
            'vulnerability'
        ]
    }
}


# Mapping of official STIX objects to their timestamp properties
TIMESTAMP_PROPERTIES = {
    'campaign': [
        'first_seen',
        'last_seen',
    ],
    'indicator': [
        'valid_from',
        'valid_until',
    ],
    'intrusion-set': [
        'first_seen',
        'last_seen',
    ],
    'observed-data': [
        'first_observed',
        'last_observed',
    ],
    'report': [
        'published',
    ],
    'sighting': [
        'first_seen',
        'last_seen',
    ],
}


# Mapping of official STIX Cyber Observable objects to their timestamp properties
TIMESTAMP_OBSERVABLE_PROPERTIES = {
    'directory': [
        'created',
        'modified',
        'accessed',
    ],
    'email-message': [
        'date',
    ],
    'file': [
        'created',
        'modified',
        'accessed',
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
        'password_last_changed',
        'account_first_login',
        'account_last_login',
    ],
    'windows-registry-key': [
        'modified',
    ],
    'x509-certificate': [
        'validity_not_before',
        'validity_not_after',
    ],
}

# Mapping of STIX Cyber Observable object to their timestamp-typed embedded properties
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

# Mapping of official STIX objects to their open-vocab properties
VOCAB_PROPERTIES = {
    "identity": [
        'identity_class',
        'sectors'
    ],
    "indicator": [
        'labels'
    ],
    "intrusion-set": [
        'resource_level',
        'primary_motivation',
        'secondary_motivations'
    ],
    "malware": [
        'labels'
    ],
    "report": [
        'labels'
    ],
    "threat-actor": [
        'labels',
        'roles',
        'sophistication',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
        'personal_motivations'
    ],
    "tool": [
        'labels'
    ],
    "marking-definition": [
        'definition_type'
    ]
}

# Mapping of check code numbers to names
CHECK_CODES = {
    '1': 'format-checks',
    '101': 'custom-prefix',
    '102': 'custom-prefix-lax',
    '111': 'open-vocab-format',
    '121': 'kill-chain-names',
    '141': 'observable-object-keys',
    '142': 'observable-dictionary-keys',
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
    '214': 'indicator-label',
    '215': 'industry-sector',
    '216': 'malware-label',
    '218': 'report-label',
    '219': 'threat-actor-label',
    '220': 'threat-actor-role',
    '221': 'threat-actor-sophistication',
    '222': 'tool-label',
    '241': 'hash-algo',
    '242': 'encryption-algo',
    '243': 'windows-pebinary-type',
    '244': 'account-type',
    '270': 'all-external-sources',
    '271': 'mime-type',
    '272': 'protocols',
    '273': 'ipfix',
    '274': 'http-request-headers',
    '275': 'socket-options',
    '276': 'pdf-doc-info',
    '301': 'network-traffic-ports',
    '302': 'extref-hashes',
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


SOCKET_OPTIONS = [
    'SO_ACCEPTCONN',
    'SO_BINDTODEVICE',
    'SO_BROADCAST',
    'SO_BSDCOMPAT',
    'SO_DEBUG',
    'SO_DOMAIN',
    'SO_ERROR',
    'SO_DONTROUTE',
    'SO_KEEPALIVE',
    'SO_LINGER',
    'SO_MARK',
    'SO_OOBINLINE',
    'SO_PASSCRED',
    'SO_PEERCRED',
    'SO_PRIORITY',
    'SO_PROTOCOL',
    'SO_RCVBUF',
    'SO_RCVBUFFORCE',
    'SO_RCVLOWAT',
    'SO_SNDLOWAT',
    'SO_RCVTIMEO',
    'SO_SNDTIMEO',
    'SO_REUSEADDR',
    'SO_SNDBUF',
    'SO_SNDBUFFORCE',
    'SO_TIMESTAMP',
    'SO_TYPE'
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
