
from OpenSSL import crypto

class Utils(object):
    """Utility class containing helper functions for use with Certificate
    Authority"""
    prikey_nbits = 1024
    message_digest_type = "md5"
        
    @staticmethod
    def create_key_pair(nbits_for_key=prikey_nbits):
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
    def create_cert_req(dn, key_pair, message_digest=message_digest_type):
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
        @type dn: dict
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
    
        for k, v in dn.items():
            setattr(subj, k, v)
        
        # Create public key object
        cert_req.set_pubkey(key_pair)
        
        # Add the public key to the request
        cert_req.sign(key_pair, message_digest)
        
        return cert_req


class CertificateAuthority(object):
    """Provide basic functionality for a Certificate Authority"""
    certificate_version2 = 1
    certificate_version3 = 2
    
    def __init__(self):
        """Create certificate authority instance"""
        self.__cert = None
        self.__key = None
        self.__serial_num = 0L

    @property
    def cert(self):
        return self.__cert

    @cert.setter
    def cert(self, value):
        if not isinstance(value, crypto.X509):
            raise TypeError('Expecting OpenSSL.crypto.X509 type for "cert" '
                            'got %r type' % type(value))

        self.__cert = value
        
    @property
    def key(self):
        """CA private key"""
        return self.__key

    @key.setter
    def key(self, value):
        if not isinstance(value, crypto.PKey):
            raise TypeError('Expecting OpenSSL.crypto.PKey type for "key" '
                            'got %r type' % type(value))
        self.__key = value
        
    @property
    def serial_num(self):
        """Certificate serial number"""
        return self.__serial_num

    @serial_num.setter
    def serial_num(self, value):
        if not isinstance(value, (long, int)):
            raise TypeError('Expecting int or long type for "serial_num" '
                            'got %r type' % type(value))
        self.__serial_num = long(value)

    @classmethod
    def from_files(cls, cert_filepath, key_filepath, key_file_passwd=None):
        """Construct new instance certificate and private key files
        "return: new certificate authority instance
        """
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, 
                                        open(key_filepath).read(),
                                        key_file_passwd)
        
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                          open(cert_filepath).read())
        
        ca = CertificateAuthority()
        ca.cert = cert
        ca.key = key
        return ca
    
    def issue_certificate(self, 
                          req, 
                          (not_before_ndays, not_after_ndays), 
                          digest=Utils.message_digest_type,
                          certificate_version=certificate_version3,
                          ca_true=False,
                          subject_alt_name=False):
        """
        Generate a certificate given a certificate request.
    
        @param req: Certificate request to use
        @param not_before_ndays: Timestamp (relative to now) when the 
        certificate starts being valid
        @type not_before_ndays: int or long
        @param not_after_ndays: Timestamp (relative to now) when the certificate
        stops being valid
        @type not_after_ndays: int or long
        @param digest: Digest method to use for signing, default is md5
        @param ca_true: set to True to set CA:true in the basic constraints 
        extension
        @type ca_true: bool
        @return: The signed certificate in an X.509 object
        """
        cert = crypto.X509()
        cert.set_serial_number(self.serial_num)
        
        cert.gmtime_adj_notBefore(not_before_ndays)
        cert.gmtime_adj_notAfter(not_after_ndays)
        
        cert.set_issuer(self.cert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        
        cert.set_version(certificate_version)
        
        # Certificate extensions
        if ca_true:
            basic_constraints = 'CA:true'
        else:
            basic_constraints = 'CA:false'
            
        # Add basic contraints as first element of extensions tuple
        extensions = (crypto.X509Extension('basicConstraints', 
                                           True, 
                                           basic_constraints),)
            
        # Check for a subject alt names extension, if present add as is.
        if isinstance(subject_alt_name, basestring):
            extensions += (crypto.X509Extension('subjectAltName', 
                                                False, 
                                                subject_alt_name),)
            
        cert.add_extensions(extensions)
        
        cert.sign(self.key, digest)
        
        # Serial number is a counter
        self.serial_num += 1
        
        return cert 
