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
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
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
        'version',
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
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'aliases',
        'first_seen',
        'first_seen_precision',
        'objective'
    ],
    "course-of-action": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
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
        'version',
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
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'pattern',
        'valid_from',
        'valid_from_precision',
        'valid_until',
        'valid_until_precision',
        'kill_chain_phases'
    ],
    "intrusion-set": [
        'type',
        'id',
        'created_by_ref',
        'created',
        'modified',
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'name',
        'description',
        'aliases',
        'first_seen',
        'first_seen_precision',
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
        'version',
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
        'version',
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
        'version',
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
        'version',
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
        'version',
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
        'version',
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
        'version',
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
        'version',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings',
        'first_seen',
        'first_seen_precision',
        'last_seen',
        'last_seen_precision',
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


DENIED_RELATIONSHIPS = [
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
