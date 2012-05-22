'''
Created on Feb 1, 2012

@author: philipkershaw
'''
import unittest

from OpenSSL import crypto
from pyasn1.type import univ
from pyasn1.codec.der.decoder import decode

from subj_alt_name import GeneralNames


class CertificateAuthorityTestCase(unittest.TestCase):
    PRIKEY_NBITS = 1024
    MESSAGE_DIGEST_TYPE = "md5"

    @staticmethod
    def _create_key_pair(nBitsForKey=PRIKEY_NBITS):
        """Generate key pair and return as PEM encoded string
        @type nBitsForKey: int
        @param nBitsForKey: number of bits for private key generation - 
        default is 2048
        @rtype: OpenSSL.crypto.PKey
        @return: public/private key pair
        """
        key_pair = crypto.PKey()
        key_pair.generate_key(crypto.TYPE_RSA, nBitsForKey)
        
        return key_pair
            
    @staticmethod
    def _create_cert_req(dn, key_pair, messageDigest=MESSAGE_DIGEST_TYPE):
        """Create a certificate request.
        
        @type key_pair: string/None
        @param key_pair: public/private key pair
        @type messageDigest: basestring
        @param messageDigest: message digest type - default is MD5
        @param name: The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          SP    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          email - E-mail address
        @type name: dict
        @rtype: base string
        @return certificate request PEM text and private key PEM text
        """
        
        # Check all required certificate request DN parameters are set                
        # Create certificate request
        cert_req = crypto.X509Req()
        subj = cert_req.get_subject()
    
        for k, v in dn.items():
            setattr(subj, k, v)
        
        # Create public key object
        cert_req.set_pubkey(key_pair)
        
        # Add the public key to the request
        cert_req.sign(key_pair, messageDigest)
        
        return cert_req
    
    @staticmethod
    def _create_certificate(req, (issuerCert, issuerKey), serial, 
                            (notBefore, notAfter), digest="md5"):
        """
        Generate a certificate given a certificate request.
    
        Arguments: req        - Certificate reqeust to use
                   issuerCert - The certificate of the issuer
                   issuerKey  - The private key of the issuer
                   serial     - Serial number for the certificate
                   notBefore  - Timestamp (relative to now) when the certificate
                                starts being valid
                   notAfter   - Timestamp (relative to now) when the certificate
                                stops being valid
                   digest     - Digest method to use for signing, default is md5
        Returns:   The signed certificate in an X509 object
        """
        cert = crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.set_version(2) # equivalent to version 3
        ext1 = crypto.X509Extension('basicConstraints', True, 'CA:false')
        ext2 = crypto.X509Extension('subjectAltName', False, 
                                    'DNS:localhost, DNS:localhost.domain')
        cert.add_extensions((ext1, ext2))
        cert.sign(issuerKey, digest)
        
        return cert 
          
    def test01(self):
        key_pair = self.__class__._create_key_pair()
        
        dn = {'CN': 'localhost', 'O': 'NDG', 'OU': 'Security'}
        cert_req = self.__class__._create_cert_req(dn, key_pair)

        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, 
                                        open('./cakey.pem').read(),
                                        'ndgtestca')
        
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                          open('./cacert.pem').read())
        
        serial = 10
        not_before = 0
        not_after =  60*60*24*365*5
        cert = self.__class__._create_certificate(cert_req, 
                                                  (ca_cert, ca_key), 
                                                  serial, 
                                                  (not_before, not_after))
        
        s_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
        open('./my.key', 'w').write(s_key)
        s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        open('./my.crt', 'w').write(s_cert)

    def test02_check_ext(self):
        # Check for subject alternative names
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                          open('./my.crt').read())
        
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
                    dns_name = str(dec[0].getComponentByPosition(i).getComponent())
                    print dns_name


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()