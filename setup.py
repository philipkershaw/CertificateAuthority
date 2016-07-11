#!/usr/bin/env python
"""Distribution Utilities setup program for Certificate Authority Package

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "24/10/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = """BSD - See LICENSE file in top-level directory"""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages


setup(
    name =            	'ContrailCA',
    version =         	'0.4.0',
    description =     	'Certificate Authority',
    long_description = 	'''\
Provides a simple implementation of a Certificate Authority.  It uses the 
PyOpenSSL for bindings to OpenSSL but also includes the ability to callout 
direct to an openssl command for more fine-grained control over the certificate 
issuing process if required.

The code has been developed for the Contrail Project, http://contrail-project.eu/

Prerequisites
=============
This has been developed and tested for Python 2.7 and 3.5.

Installation
============
Installation can be performed using pip.

Configuration
=============
Examples are contained in ``contrail.security.ca.test``.
''',
    author =          	'Philip Kershaw',
    author_email =    	'Philip.Kershaw@stfc.ac.uk',
    maintainer =        'Philip Kershaw',
    maintainer_email =  'Philip.Kershaw@stfc.ac.uk',
    url =             	'https://github.com/cedadev/CertificateAuthority',
    platforms =         ['POSIX', 'Linux', 'Windows'],
    install_requires =  ['PyOpenSSL'],
    
    # Required for Subject Alt Names unit test only
    extras_require = {'subjectAltName_support': 'pyasn1'},
    license =           __license__,
    test_suite =        'contrail.security.onlineca.client.test',
    packages =          find_packages(),
    package_data =      {
        'contrail.security.ca.test': [
            'README', 'LICENSE', '*.cfg', '*.crt', '*.key',
            'ca_config/serial', 'ca_config/index.txt', 
            'ca_config/newcerts/README', 'ca_config/*.crt', 'ca_config/*.key', 
            'ca_config/test-ca.cfg'
            ]
    },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    entry_points={
        'console_scripts': ['gen_ca_cert = contrail.security.ca.utils:main',
                            ],
        },
    zip_safe = False
)
