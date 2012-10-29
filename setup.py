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
    version =         	'0.1.0',
    description =     	'Certificate Authority',
    long_description = 	'''\
Provides a simple implementation of a Certificate Authority.  It uses the 
PyOpenSSL for bindings to OpenSSL but also includes the ability to callout 
direct to an openssl command for more fine-grained control over the certificate 
issuing process if required.

The code has been developed for the Contrail Project, http://contrail-project.eu/

Prerequisites
=============
This has been developed and tested for Python 2.7.

Installation
============
Installation can be performed using easy_install or pip.

Configuration
=============
Examples are contained in ``contrail.security.ca.test``.
''',
    author =          	'Philip Kershaw',
    author_email =    	'Philip.Kershaw@stfc.ac.uk',
    maintainer =        'Philip Kershaw',
    maintainer_email =  'Philip.Kershaw@stfc.ac.uk',
#    url =             	'',
    platforms =         ['POSIX', 'Linux', 'Windows'],
    install_requires =  ['ndg_httpsclient'],
    
    # Required for Subject Alt Names unit test only
    extras_require = {'subjectAltName_support': 'pyasn1'},
    license =           __license__,
    test_suite =        'contrail.security.onlineca.client.test',
    packages =          find_packages(),
    package_data =      {
        'contrail.security.ca.test': [
            'README', '*.cfg', '*.crt', '*.key',
            'ca_config/serial', 'ca_config/index.txt', 
            'ca_config/newcerts/README', 'ca_config/*.crt', 'ca_config/*.key', 
            'ca_config/test-ca.cfg'
            ]
    },
    classifiers = [
        'Development Status :: 4 - Beta',
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
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe = False
)
