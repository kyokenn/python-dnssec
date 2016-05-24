from setuptools import setup


setup(**{
    'name': 'python-dnssec',
    'version': '0.0.1',
    'author': 'Okami',
    'author_email': 'okami@fuzetsu.info',
    'description': (
        'python-dnssec is a set of scripts and modules from the original'
        'DNSSEC-Tools project rewritten in python.'),
    'license': 'GPLv3',
    'keywords': 'dnssec rollerd pyrollerd rollctl pyrollctl',
    'url': 'https://pypi.python.org/pypi/python-dnssec',
    'packages': [
        'dnssec',
        'dnssec.api',
        'dnssec.parsers',
        'dnssec.rollerd',
    ],
    'scripts': ['rollerd'],
    'long_description': '',
    'classifiers': [
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
    ],
    'install_requires': [
        'dnspython3 >= 1.12.0',
    ],
})
