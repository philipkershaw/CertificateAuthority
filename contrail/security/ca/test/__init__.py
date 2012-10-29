"""Module for Certificate Authority default implementation unit tests
"""
__author__ = "P J Kershaw"
__date__ = "20/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import unittest
from os import path
from os import urandom
import base64

from contrail.security.ca.cert_req import CertReqUtils

THIS_DIR = path.abspath(path.dirname(__file__))


class CertificateAuthorityBaseTestCase(unittest.TestCase):
    """Certificate authority unit test base class"""
    CA_CERT_FILEPATH = path.join(THIS_DIR, 'ca_config', 'myca.crt')
    CA_KEY_FILEPATH = path.join(THIS_DIR, 'ca_config', 'myca.key')
    CA_KEY_FILE_PASSWD = 'ndgtestca'
    CERT_AUTHORITY_CLASS = None
    MIN_KEY_NBITS = 1024
    
    @classmethod
    def create_cert_req(cls, dn=None):
        key_pair = CertReqUtils.create_key_pair()
        
        if dn is None:
            dn = {'CN': 'localhost', 'O': 'NDG', 'OU': 'Security'}
            
        cert_req = CertReqUtils.create_cert_req(dn, key_pair)
        
        return key_pair, cert_req
    
    @classmethod
    def _create_ca_and_cert_req(cls):
        key_pair, cert_req = cls.create_cert_req()
        ca = cls.CERT_AUTHORITY_CLASS.from_files(cls.CA_CERT_FILEPATH, 
                                                 cls.CA_KEY_FILEPATH, 
                                                 cls.CA_KEY_FILE_PASSWD)
        ca.min_key_nbits = cls.MIN_KEY_NBITS
        
        return key_pair, cert_req, ca
