"""Certificate Authority package certificate request helper module
"""
__author__ = "P J Kershaw"
__date__ = "19/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from OpenSSL import crypto

from contrail.security.ca.base import AbstractCertificateAuthority


class CertReqUtils(object):
    """Utility class containing helper functions for use with Certificate
    Authority"""
    PRIKEY_NBITS_DEFAULT = AbstractCertificateAuthority.MIN_KEY_NBITS_DEFAULT
    DIGEST_TYPE_DEFAULT = AbstractCertificateAuthority.DIGEST_TYPE_DEFAULT
        
    @staticmethod
    def create_key_pair(nbits_for_key=PRIKEY_NBITS_DEFAULT):
        """Generate key pair and return as PEM encoded string
        @type nbits_for_key: int
        @param nbits_for_key: number of bits for private key generation - 
        default is 2048
        @rtype: OpenSSL.crypto.PKey
        @return: public/private key pair
        """
        key_pair = crypto.PKey()
        key_pair.generate_key(crypto.TYPE_RSA, nbits_for_key)
        
        return key_pair
            
    @staticmethod
    def create_cert_req(dn, 
                        key_pair, 
                        message_digest=DIGEST_TYPE_DEFAULT):
        """Create a certificate request.
        
        @param dn: The distinguished name of the subject of the request, 
        possible arguments are:
          C     - Country name
          SP    - State or province name
          L     - Locality name
          O     - Organization name
          OU    - Organizational unit name
          CN    - Common name
          email - E-mail address
        @type dn: dict or a list of two element tuples corresponding to field
        name and field value
        @type key_pair: string/None
        @param key_pair: public/private key pair
        @type message_digest: basestring
        @param message_digest: message digest type - default is MD5
        @return certificate request PEM text and private key PEM text
        @rtype: base string
        """
        
        # Check all required certificate request DN parameters are set                
        # Create certificate request
        cert_req = crypto.X509Req()
        subj = cert_req.get_subject()
    
        if isinstance(dn, dict):
            dn_items = dn.items()
        else:
            dn_items = dn
            
        for k, v in dn_items:
            setattr(subj, k, v)
        
        # Create public key object
        cert_req.set_pubkey(key_pair)
        
        # Add the public key to the request
        cert_req.sign(key_pair, message_digest)
        
        return cert_req
