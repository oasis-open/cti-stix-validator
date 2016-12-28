"""STIX 2.0 open vocabularies and other lists
"""


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
    "windows local",
    "windows domain",
    "ldap",
    "tacacs",
    "radius",
    "nis",
    "openid",
    "facebook",
    "skype",
    "twitter",
    "kavi"
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
    "email-address",
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
        'description',
        'extensions',
        'mime_type',
        'payload_bin',
        'url',
        'hashes'
    ],
    'autonomous-system': [
        'type',
        'description',
        'extensions',
        'number',
        'name',
        'rir'
    ],
    'directory': [
        'type',
        'description',
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
        'description',
        'extensions',
        'value',
        'resolves_to_refs'
    ],
    'email-address': [
        'type',
        'description',
        'extensions',
        'value',
        'display_name',
        'belongs_to_ref'
    ],
    'email-message': [
        'type',
        'description',
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
        'description',
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
        'description',
        'extensions',
        'value',
        'resolves_to_refs',
        'belongs_to_refs'
    ],
    'ipv6-addr': [
        'type',
        'description',
        'extensions',
        'value',
        'resolves_to_refs',
        'belongs_to_refs'
    ],
    'mac-addr': [
        'type',
        'description',
        'extensions',
        'value'
    ],
    'mutex': [
        'type',
        'description',
        'extensions',
        'name'
    ],
    'network-traffic': [
        'type',
        'description',
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
        'description',
        'extensions',
        'is_hidden',
        'pid',
        'name',
        'created',
        'cwd',
        'arguments',
        'environment_variables',
        'opened_connection_refs',
        'creator_user_ref',
        'binary_ref',
        'parent_ref',
        'child_refs'
    ],
    'software': [
        'type',
        'description',
        'extensions',
        'name',
        'cpe',
        'language',
        'vendor',
        'version'
    ],
    'url': [
        'type',
        'description',
        'extensions',
        'value'
    ],
    'user-account': [
        'type',
        'description',
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
        'description',
        'extensions',
        'key',
        'values',
        'modified',
        'creator_user_ref',
        'number_of_subkeys'
    ],
    'x509-certificate': [
        'type',
        'description',
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
        'start_command_line',
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
OBSERVABLE_EMBEDED_PROPERTIES = {
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
OBSERVABLE_EXTENSION_EMBEDED_PROPERTIES = {
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
    'email-address': {
        'belongs_to_ref': [
            'user-account'
        ]
    },
    'email-message': {
        'from_ref': [
            'email-address'
        ],
        'sender_ref': [
            'email-address'
        ],
        'to_refs': [
            'email-address'
        ],
        'cc_refs': [
            'email-address'
        ],
        'bcc_refs': [
            'email-address'
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
            'ntwork-traffic'
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
    'key'
]

# Reserved properties and objects
RESERVED_PROPERTIES = [
    'confidence',
    'severity',
    'action',
    'usernames',
    'phone_numbers',
    'addresses'
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
        'goals',
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
