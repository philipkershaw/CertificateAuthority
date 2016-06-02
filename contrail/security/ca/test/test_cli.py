'''
Created on Jun 1, 2016

@author: philipkershaw
'''
import unittest

from OpenSSL import crypto

from contrail.security.ca.utils.cli import CertificateAuthorityCLI
from contrail.security.ca.cert_req import CertReqUtils

class CertificateAuthorityCLITestCase(unittest.TestCase):

    def test01_create_ca_cert_and_key(self):
        CertificateAuthorityCLI().main(
            'gen_ca', '-c', './ca.crt', '-k', './ca.key', '-s',
            'O=CA Org,OU=CA Org unit,CN=Root Certificate Authority'
        )

    def test02_issue_cert(self):
        key_pair = CertReqUtils.create_key_pair()
        req = CertReqUtils.create_cert_req([('O', 'Org'), ('OU', 'Org unit'),
                                            ('CN', 'Common name')],
                                           key_pair)
        s_req = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        with open('./certreq.csr', 'wb') as req_file:
            req_file.write(s_req)
            
        CertificateAuthorityCLI().main(
            'issue_cert', '-C', './ca.crt', '-K', './ca.key', 
            '-o', 'newcert.crt', '-q', 'certreq.csr'
        )

    def test02_issue_cert_with_subject_alt_names(self):
        key_pair = CertReqUtils.create_key_pair()
        req = CertReqUtils.create_cert_req([('O', 'Org'), ('OU', 'Org unit'),
                                            ('CN', 'Common name')],
                                           key_pair)
        s_req = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        with open('./certreq.csr', 'wb') as req_file:
            req_file.write(s_req)
            
        CertificateAuthorityCLI().main(
            'issue_cert', '-C', './ca.crt', '-K', './ca.key', 
            '-o', 'new-cert-with-subj-alt-name.crt', '-q', 'certreq.csr', 
            '-S', 'localhost'
        )

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()