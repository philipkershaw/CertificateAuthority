"""Module for Certificate Authority default implementation unit tests
"""
__author__ = "P J Kershaw"
__date__ = "19/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import warnings
import logging
logging.basicConfig(level=logging.DEBUG)

from os import path
import unittest

from OpenSSL import crypto

PYASN1_SUPPORT = True
try:
    from pyasn1.codec.der.decoder import decode
    
except ImportError:
    warnings.warn('Skipping certificate extensions test, pyasn1 is not '
                  'installed.  To test extensions support, install '
                  'pyasn1 and retry')
    PYASN1_SUPPORT = False
    
from contrail.security.ca.impl import CertificateAuthority

if PYASN1_SUPPORT:
    from contrail.security.ca.subj_alt_name import GeneralNames
    
from contrail.security.ca.test import CertificateAuthorityBaseTestCase, THIS_DIR


class CertificateAuthorityTestCase(CertificateAuthorityBaseTestCase):
    """Test certificate authority class"""
    CERT_AUTHORITY_CLASS = CertificateAuthority
    CFG_FILEPATH = path.join(THIS_DIR, 'ca.cfg')
    
    def test01_issue_fqdn_cert_with_subj_alt_names(self):
        key_pair, cert_req, ca = self._create_ca_and_cert_req()
        
        not_before_nsecs = 0
        not_after_nsecs =  60*60*24*365*5
        
        cert = ca.issue_certificate(
                      cert_req, 
                      not_before_time_nsecs=not_before_nsecs, 
                      not_after_time_nsecs=not_after_nsecs, 
                      subject_alt_name='DNS:localhost, DNS:localhost.domain')
    
        
        s_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
        open(path.join(THIS_DIR, 'my.key'), 'w').write(s_key)
        s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        open(path.join(THIS_DIR, 'my.crt'), 'w').write(s_cert)

    if PYASN1_SUPPORT:
        def test02_check_ext(self):
                
            # Check for subject alternative names
            cert = crypto.load_certificate(
                                    crypto.FILETYPE_PEM, 
                                    open(path.join(THIS_DIR, 'my.crt')).read())
            
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                ext_name = ext.get_short_name()
                if ext_name == 'subjectAltName':
                    ext_dat = ext.get_data()
                    print ext_dat
                    dec = decode(ext_dat, asn1Spec=GeneralNames())
                    print dec
                    print dec[0].prettyPrint()
                    for i in range(len(dec[0])):
                        dns_name = str(
                                dec[0].getComponentByPosition(i).getComponent())
                        print dns_name

    def test03_create_from_keywords(self):
        ca = CertificateAuthority.from_keywords(
                            cert_filepath=self.__class__.CA_CERT_FILEPATH, 
                            key_filepath=self.__class__.CA_KEY_FILEPATH, 
                            key_passwd=self.__class__.CA_KEY_FILE_PASSWD,
                            serial_num_counter=11)
        self.assert_(ca, 'null ca object')
        self.assertEqual(ca.serial_num_counter, 11, 
                         'Error setting serial_num_counter')
        
    def test04_create_from_files(self):
        ca = CertificateAuthority.from_files(self.__class__.CA_CERT_FILEPATH, 
                            self.__class__.CA_KEY_FILEPATH, 
                            key_file_passwd=self.__class__.CA_KEY_FILE_PASSWD)
        self.assert_(ca, 'null ca object')
        self.assertIsInstance(ca.cert, crypto.X509, 
                              'ca.cert is not an X509 instance')
        self.assertIsInstance(ca.key, crypto.PKey, 
                              'ca.key is not an PKey instance')
        
    def test05_create_from_config(self):
        ca = CertificateAuthority.from_config(self.__class__.CFG_FILEPATH)
        self.assert_(ca, 'null ca object')
        self.assertIsInstance(ca.cert, crypto.X509, 
                              'ca.cert is not an X509 instance')
        self.assertIsInstance(ca.key, crypto.PKey, 
                              'ca.key is not an PKey instance')
        
    def test06_issue_cert_with_custom_ext(self):
        key_pair, cert_req, ca = self.__class__._create_ca_and_cert_req()
        
        not_before_nsecs = 0
        not_after_nsecs =  60*60*24*365*5

        cert = ca.issue_certificate(
                      cert_req, 
                      not_before_time_nsecs=not_before_nsecs, 
                      not_after_time_nsecs=not_after_nsecs, 
                      extensions=[('nsComment', 'my_cust_val', False)])

        s_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
        open(path.join(THIS_DIR, 'my1.key'), 'w').write(s_key)
        s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        open(path.join(THIS_DIR, 'my1.crt'), 'w').write(s_cert)
        
        
if __name__ == "__main__":
    unittest.main()