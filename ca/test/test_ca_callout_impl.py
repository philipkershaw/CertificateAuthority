"""Module for Certificate Authority OpenSSL callout implementation unit tests

This requires the openssl executable installed and on the system path of the 
host
"""
__author__ = "P J Kershaw"
__date__ = "19/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
logging.basicConfig(level=logging.DEBUG)
import unittest
from os import path

from OpenSSL import crypto

from ca.callout_impl import CertificateAuthorityWithCallout
from ca.test import CertificateAuthorityBaseTestCase, THIS_DIR


class CertificateAuthorityWithCalloutTestCase(CertificateAuthorityBaseTestCase):
    """Test certificate authority class"""
    CERT_AUTHORITY_CLASS = CertificateAuthorityWithCallout
    CFG_FILEPATH = path.join(THIS_DIR, 'callout_ca.cfg')

    def test01_create_from_keywords(self):
        cert_issue_cmd = (
            'openssl ca -key file.key -cert file.crt -config '
            './test-ca/test-ca.cfg -days 365 -in $in_csr -out $out_cert '
            '-batch'
        )

        ca = CertificateAuthorityWithCallout.from_keywords(
                                                min_key_nbits=4096,
                                                cert_issue_cmd=cert_issue_cmd)
        self.assert_(ca, 'null ca object')
        
        self.assertEqual(ca.min_key_nbits, 4096, 
                         'Error setting serial_num_counter')
        
        self.assertRaises(TypeError, 
                          CertificateAuthorityWithCallout.from_keywords,
                          min_key_nbits=None)
        
    def test02_create_from_files(self):
        ca = CertificateAuthorityWithCallout.from_files(
                            self.__class__.CA_CERT_FILEPATH, 
                            self.__class__.CA_KEY_FILEPATH, 
                            key_file_passwd=self.__class__.CA_KEY_FILE_PASSWD)
        self.assert_(ca, 'null ca object')
        self.assertIsInstance(ca.cert, crypto.X509, 
                              'ca.cert is not an X509 instance')
        self.assertIsInstance(ca.key, crypto.PKey, 
                              'ca.key is not an PKey instance')
        
    def test03_create_from_config(self):
        ca = CertificateAuthorityWithCallout.from_config(
                                                self.__class__.CFG_FILEPATH)
        self.assert_(ca, 'null ca object')
        self.assertIsInstance(ca.cert, crypto.X509, 
                              'ca.cert is not an X509 instance')
        self.assertIsInstance(ca.key, crypto.PKey, 
                              'ca.key is not an PKey instance')
        self.assert_(ca.cert_issue_cmd, 'Missing openssl issuing command')
    
    def test04_issue_certificate(self):
        cert_req = self.__class__.create_cert_req()[-1]
        ca = CertificateAuthorityWithCallout.from_config(
                                                self.__class__.CFG_FILEPATH)
        cert = ca.issue_certificate(cert_req)
        self.assert_(cert, 'Null output certificate')


if __name__ == "__main__":
    unittest.main()