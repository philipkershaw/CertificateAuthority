'''
Created on Feb 1, 2012

@author: philipkershaw
'''
import logging
logging.basicConfig(level=logging.DEBUG)

from os import path
import unittest

from OpenSSL import crypto
from pyasn1.codec.der.decoder import decode

from ca import CertificateAuthority, Utils
from ca.subj_alt_name import GeneralNames


this_dir = path.abspath(path.dirname(__file__))


class CertificateAuthorityTestCase(unittest.TestCase):
    """Test certificate authority class"""
    ca_cert_filepath = path.join(this_dir, 'myca.crt')
    ca_key_filepath = path.join(this_dir, 'myca.key')
    ca_key_file_passwd = 'ndgtestca'
    cfg_filepath = path.join(this_dir, 'ca.cfg')

    def _create_ca_and_cert_req(self):
        key_pair = Utils.create_key_pair()
        
        dn = {'CN': 'localhost', 'O': 'NDG', 'OU': 'Security'}
        cert_req = Utils.create_cert_req(dn, key_pair)
        
        ca = CertificateAuthority.from_files(self.__class__.ca_cert_filepath, 
                                             self.__class__.ca_key_filepath, 
                                             self.__class__.ca_key_file_passwd)
        
        return key_pair, cert_req, ca
      
    def test01_issue_fqdn_cert_with_subj_alt_names(self):
        key_pair, cert_req, ca = self._create_ca_and_cert_req()
        
        not_before_ndays = 0
        not_after_ndays =  60*60*24*365*5
        
        cert = ca.issue_certificate(cert_req, 
                      (not_before_ndays, not_after_ndays), 
                      subject_alt_name='DNS:localhost, DNS:localhost.domain')
    
        
        s_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
        open(path.join(this_dir, 'my.key'), 'w').write(s_key)
        s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        open(path.join(this_dir, 'my.crt'), 'w').write(s_cert)

    def test02_check_ext(self):
        # Check for subject alternative names
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                    open(path.join(this_dir, 'my.crt')).read())
        
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
        ca = CertificateAuthority.from_keywords(serial_num_counter=11)
        self.assert_(ca, 'null ca object')
        self.assertEqual(ca.serial_num_counter, 11, 
                         'Error setting serial_num_counter')
        
    def test04_create_from_files(self):
        ca = CertificateAuthority.from_files(self.__class__.ca_cert_filepath, 
                            self.__class__.ca_key_filepath, 
                            key_file_passwd=self.__class__.ca_key_file_passwd)
        self.assert_(ca, 'null ca object')
        self.assertIsInstance(ca.cert, crypto.X509, 
                              'ca.cert is not an X509 instance')
        self.assertIsInstance(ca.key, crypto.PKey, 
                              'ca.key is not an PKey instance')
        
    def test05_create_from_config(self):
        ca = CertificateAuthority.from_config(self.__class__.cfg_filepath)
        self.assert_(ca, 'null ca object')
        self.assertIsInstance(ca.cert, crypto.X509, 
                              'ca.cert is not an X509 instance')
        self.assertIsInstance(ca.key, crypto.PKey, 
                              'ca.key is not an PKey instance')
        
    def test06_issue_cert_with_custom_ext(self):
        key_pair, cert_req, ca = self._create_ca_and_cert_req()
        
        not_before_ndays = 0
        not_after_ndays =  60*60*24*365*5

        cert = ca.issue_certificate(cert_req, 
                      (not_before_ndays, not_after_ndays), 
                      extensions=[('nsComment', 'my_cust_val', False)])

        s_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
        open(path.join(this_dir, 'my1.key'), 'w').write(s_key)
        s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        open(path.join(this_dir, 'my1.crt'), 'w').write(s_cert)
        
        
if __name__ == "__main__":
    unittest.main()