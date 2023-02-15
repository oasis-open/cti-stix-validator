extensions = [
    'sphinx-prompt',
]

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = 'stix2-validator'
copyright = '2018-2022, OASIS Open'
author = 'OASIS Open'

version = '3.1.3'
release = '3.1.3'

language = None
exclude_patterns = ['_build', '_templates', 'Thumbs.db', '.DS_Store']
pygments_style = 'sphinx'
todo_include_todos = False

html_theme = 'alabaster'
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
        'relations.html',
        'searchbox.html',
    ]
}

latex_elements = {}
latex_documents = [
    (master_doc, 'stix2-validator.tex', 'stix2-validator Documentation',
     author, 'manual'),
]

man_pages = [
    (master_doc, project, 'stix2-validator Documentation', [author], 1),
]
