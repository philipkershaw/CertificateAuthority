"""ca package contains Certificate Authority classes
"""
__author__ = "P J Kershaw"
__date__ = "10/08/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
from ConfigParser import ConfigParser, SafeConfigParser
from os import path
import logging
log = logging.getLogger(__name__)

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


class CertificateAuthorityCSRError(Exception):
    """Error with input certificate signing request"""
    
    
class CertificateAuthority(object):
    """Provide basic functionality for a Certificate Authority"""
    certificate_version2 = 1
    certificate_version3 = 2
    
    __slots__ = ('__cert', '__key', '__serial_num', '__min_key_nbits')
    
    def __init__(self):
        """Create certificate authority instance"""
        self.__cert = None
        self.__key = None
        self.__serial_num = 0L
        self.__min_key_nbits = 1024


    @classmethod
    def from_config(cls, cfg, **kw):
        '''Alternative constructor makes object from config file settings
        @type cfg: basestring / ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @rtype: ndg.saml.saml2.binding.soap.client.SOAPBinding or derived type
        @return: new instance of this class
        '''
        obj = cls()
        obj.parse_config(cfg, **kw)
        
        return obj

    def parse_config(self, cfg, prefix='', section='DEFAULT'):
        '''Read config file settings
        @type cfg: basestring /ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @type prefix: basestring
        @param prefix: prefix for option names e.g. "attributeQuery."
        @type section: baestring
        @param section: configuration file section from which to extract
        parameters.
        '''  
        if isinstance(cfg, basestring):
            config_file_path = path.expandvars(cfg)
            here_dir = path.dirname(config_file_path)
            _cfg = SafeConfigParser(defaults=dict(here=here_dir))
            _cfg.optionxform = str

            _cfg.read(config_file_path)
            
        elif isinstance(cfg, ConfigParser):
            _cfg = cfg   
        else:
            raise AttributeError('Expecting basestring or ConfigParser type '
                                 'for "cfg" attribute; got %r type' % type(cfg))
        
        # Get items for this section as a dictionary so that parseKeywords can
        # used to update the object
        kw = dict(_cfg.items(section))
        
        # ... but first get file path settings which aren't included as 
        # instance variables
        cert_filepath_opt = prefix + self.__class__.cert_filepath_optname
        prikey_filepath_opt = prefix + self.__class__.prikey_filepath_optname
        prikey_file_passwd_opt = prefix + self.__class__.prikey_passwd_optname
        
        cert_filepath = kw.get(cert_filepath_opt)
        prikey_file_passwd = kw.get(prikey_file_passwd_opt)
        prikey_filepath = kw.get(prikey_filepath_opt)
        
        if 'prefix' not in kw and prefix:
            kw['prefix'] = prefix
            
        self.parse_keywords(**kw)
        
    def parse_keywords(self, prefix='', **kw):
        """Update object from input keywords
        
        @type prefix: basestring
        @param prefix: if a prefix is given, only update self from kw items 
        where keyword starts with this prefix
        @type kw: dict
        @param kw: items corresponding to class instance variables to 
        update.  Keyword names must match their equivalent class instance 
        variable names.  However, they may prefixed with <prefix>
        """
        prefixLen = len(prefix)
        for optName, val in kw.items():
            if prefix:
                # Filter attributes based on prefix
                if optName.startswith(prefix):
                    setattr(self, optName[prefixLen:], val)
            else:
                # No prefix set - attempt to set all attributes   
                setattr(self, optName, val)
                
    @classmethod
    def from_keywords(cls, prefix='', **kw):
        """Create a new instance initialising instance variables from the 
        keyword inputs
        @type prefix: basestring
        @param prefix: if a prefix is given, only update self from kw items 
        where keyword starts with this prefix
        @type kw: dict
        @param kw: items corresponding to class instance variables to 
        update.  Keyword names must match their equivalent class instance 
        variable names.  However, they may prefixed with <prefix>
        @return: new instance of this class
        @rtype: ndg.saml.saml2.binding.soap.client.SOAPBinding or derived type
        """
        obj = cls()
        obj.parse_keywords(prefix=prefix, **kw)
        
        return obj

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
    def serial_num_counter(self):
        """Certificate serial number"""
        return self.__serial_num

    @serial_num_counter.setter
    def serial_num_counter(self, value):
        if not isinstance(value, (long, int)):
            raise TypeError('Expecting int or long type for "serial_num_counter" '
                            'got %r type' % type(value))
        self.__serial_num = long(value)
        
    @property
    def min_key_nbits(self):
        """Minimum number of bits required for key in certificate request"""
        return self.__min_key_nbits

    @min_key_nbits.setter
    def min_key_nbits(self, value):
        if not isinstance(value, (long, int)):
            raise TypeError('Expecting int or long type for "min_key_nbits" '
                            'got %r type' % type(value))
        self.__min_key_nbits = long(value)
        
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
                          subject_alt_name=False,
                          extensions=None):
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
        
        # Check number of bits in key
        pkey = req.get_pubkey()
        pkey_nbits = pkey.bits()
        if pkey_nbits < self.min_key_nbits:
            raise CertificateAuthorityCSRError('Certificate signing request '
                                               'must use a key with at least '
                                               '%d bits, input request has a '
                                               'key with %d bits' % pkey_nbits)
            
        cert = crypto.X509()
        cert.set_serial_number(self.serial_num_counter)
        
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
            
        # Add basic constraints as first element of extensions list
        basic_constraints_ext = crypto.X509Extension('basicConstraints', 
                                                     True, 
                                                     basic_constraints)
        x509_extensions = [basic_constraints_ext]
            
        # Check for a subject alt names extension, if present add as is.
        if isinstance(subject_alt_name, basestring):
            subject_alt_name_ext = crypto.X509Extension('subjectAltName', 
                                                        False, 
                                                        subject_alt_name)
            x509_extensions.append(subject_alt_name_ext)
            
        if extensions:
            x509_extensions += self._add_certificate_ext(cert, extensions)
            
        cert.add_extensions(x509_extensions)
        
        cert.sign(self.key, digest)
        
        # Serial number is a counter
        self.serial_num_counter += 1
        
        if log.isEnabledFor(logging.INFO):
            dn = ''.join(["/%s=%s" % (k, v) 
                          for k,v in cert.get_subject().get_components()])
            
            log.info('Issuing certificate with subject %s', dn)
        
        return cert 
    
    def _add_certificate_ext(self, cert, extensions):
        """Add certificate extension - derived classes can override to customise
        behaviour
        """

        x509_extensions = []
        for ext_name, ext_val, ext_crit in extensions:
            x509_cust_ext = crypto.X509Extension(ext_name, ext_crit, str(ext_val))
            x509_extensions.append(x509_cust_ext)
            
        return x509_extensions

