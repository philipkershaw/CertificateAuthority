'''
Created on Jun 1, 2016

@author: philipkershaw
'''
import os
import unittest

from OpenSSL import crypto
import six

from contrail.security.ca.utils.cli import CertificateAuthorityCLI
from contrail.security.ca.cert_req import CertReqUtils
from contrail.security.ca.test import THIS_DIR

if six.PY2:
    # Workaround for FileNotFoundError.  IOError is more generic but the
    # match is sufficient for the purposes of these tests
    file_not_found_excep = OSError
else:
    # Compatibility wrapper to allow dual Python 2/3 support
    file_not_found_excep = FileNotFoundError
     
        
class CertificateAuthorityCLITestCase(unittest.TestCase):
    'Test Certificate Authority command line interface'
    CSR_FILEPATH = os.path.join(THIS_DIR, 'certreq.csr')
    NEWCERT1_FILEPATH = os.path.join(THIS_DIR, 'newcert1.crt')
    NEWCERT2_FILEPATH = os.path.join(THIS_DIR, 'newcert2.crt')
    
    CA_CERT_FILEPATH = os.path.join(THIS_DIR, 'ca.crt')
    CA_KEY_FILEPATH = os.path.join(THIS_DIR, 'ca.key')
    
    def tearDown(self):
        self.__class__._delete_csr_file()
        self.__class__._delete_ca_files()
        super(CertificateAuthorityCLITestCase, self).tearDown()
        
    @classmethod
    def _create_csr_file(cls):
        key_pair = CertReqUtils.create_key_pair()
        req = CertReqUtils.create_cert_req([('O', 'Org'), ('OU', 'Org unit'),
                                            ('CN', 'Common name')],
                                           key_pair)
        s_req = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        with open(cls.CSR_FILEPATH, 'wb') as req_file:
            req_file.write(s_req)
       
    @classmethod
    def _delete_csr_file(cls):
        try:
            os.unlink(cls.CSR_FILEPATH)
        except file_not_found_excep:
            pass
    
    @classmethod
    def _create_ca_files(cls):         
        CertificateAuthorityCLI().main(
            'gen_ca', '-c', cls.CA_CERT_FILEPATH, '-k', 
            cls.CA_KEY_FILEPATH, '-s',
            'O=CA Org,OU=CA Org unit,CN=Root Certificate Authority'
        )
        
    def test01_create_ca_cert_and_key(self):
        self.__class__._create_ca_files()
        
    @classmethod
    def _delete_ca_files(cls):
        try:
            os.unlink(cls.CA_CERT_FILEPATH)
        except file_not_found_excep:
            pass
        
        try:
            os.unlink(cls.CA_KEY_FILEPATH)
        except file_not_found_excep:
            pass
        
    def _check_cert(self, cert_filepath):
        with open(cert_filepath, 'rb') as cert_file:
            s_cert = cert_file.read()
            
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, s_cert)
        self.assertIsNotNone(cert.get_issuer())
        
        return cert

    def test02_issue_cert(self):
        self.__class__._create_ca_files()
        self.__class__._create_csr_file()

        try:
            CertificateAuthorityCLI().main(
                'issue_cert', 
                '-C', self.__class__.CA_CERT_FILEPATH, 
                '-K', self.__class__.CA_KEY_FILEPATH, 
                '-o', self.__class__.NEWCERT1_FILEPATH, 
                '-q', self.__class__.CSR_FILEPATH
            )
            
            self._check_cert(self.__class__.NEWCERT1_FILEPATH)
        finally:
            try:
                os.unlink(self.__class__.NEWCERT1_FILEPATH)
            except file_not_found_excep:
                pass

    def test02_issue_cert_with_subject_alt_names(self):
        # Check issuing cert with subject alternative name
        self.__class__._create_ca_files()
        self.__class__._create_csr_file()
        
        try:
            CertificateAuthorityCLI().main(
                'issue_cert', 
                '-C', self.__class__.CA_CERT_FILEPATH, 
                '-K', self.__class__.CA_KEY_FILEPATH, 
                '-o', self.__class__.NEWCERT2_FILEPATH, 
                '-q', self.__class__.CSR_FILEPATH, 
                '-S', 'DNS:localhost'
            )
            
            cert = self._check_cert(self.__class__.NEWCERT2_FILEPATH)
            ext_found = False
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                if 'localhost' in str(ext.get_data()):
                    ext_found = True
                    break

            self.assertTrue(ext_found, 'Subject alt Name extension not found')    
        finally:
            try:
                os.unlink(self.__class__.NEWCERT2_FILEPATH)
            except file_not_found_excep:
                pass
            

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()