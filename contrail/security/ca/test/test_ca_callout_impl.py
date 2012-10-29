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
log = logging.getLogger(__name__)
import unittest
import uuid
from os import path, environ

from OpenSSL import crypto

from contrail.security.ca.callout_impl import CertificateAuthorityWithCallout
from contrail.security.ca.test import CertificateAuthorityBaseTestCase, THIS_DIR

# Configure environment for openssl config file - see ./ca_config/ca_config.cfg
environ['CONTRAIL_CA_TEST_DIR'] = THIS_DIR


class CertificateAuthorityWithCalloutTestCase(CertificateAuthorityBaseTestCase):
    """Test certificate authority class"""
    CERT_AUTHORITY_CLASS = CertificateAuthorityWithCallout
    CFG_FILEPATH = path.join(THIS_DIR, 'callout_ca.cfg')

    def test01_create_from_keywords(self):
        test_ca_cfg_filepath = path.join(THIS_DIR, 'ca_config', 'ca_config.cfg')
        cert_issue_cmd = (
            'openssl ca -key file.key -cert file.crt -config '
            '%s -days 365 -in $in_csr -out $out_cert '
            '-batch'
        ) % test_ca_cfg_filepath

        ca = CertificateAuthorityWithCallout.from_keywords(
                            min_key_nbits=4096,
                            cert_filepath=self.__class__.CA_CERT_FILEPATH, 
                            key_filepath=self.__class__.CA_KEY_FILEPATH, 
                            key_passwd=self.__class__.CA_KEY_FILE_PASSWD,
                            cert_issue_cmd=cert_issue_cmd)
        self.assert_(ca, 'null ca object')
        
        self.assertEqual(ca.min_key_nbits, 4096, 
                         'Error setting serial_num_counter')
        
        self.assertRaises(TypeError, 
                          CertificateAuthorityWithCallout.from_keywords,
                          cert_filepath=self.__class__.CA_CERT_FILEPATH, 
                          key_filepath=self.__class__.CA_KEY_FILEPATH, 
                          key_passwd=self.__class__.CA_KEY_FILE_PASSWD,
                          cert_issue_cmd=cert_issue_cmd,
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
        # Use random dn to avoid error overwriting existing entry in the db
        dn = {'CN': str(uuid.uuid4()), 'O': 'NDG', 'OU': 'Security'}
        cert_req = self.__class__.create_cert_req(dn)[-1]
        ca = CertificateAuthorityWithCallout.from_config(
                                                self.__class__.CFG_FILEPATH)
        cert = ca.issue_certificate(cert_req)
        self.assert_(cert, 'Null output certificate')
        log.debug('Issued new certificate: %r', cert.get_subject())


if __name__ == "__main__":
    unittest.main()