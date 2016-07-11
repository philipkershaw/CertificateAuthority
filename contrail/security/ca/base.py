"""Module for Certificate Authority abstract base class
"""
__author__ = "P J Kershaw"
__date__ = "20/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import six

from six.moves.configparser import ConfigParser

# six doesn't seem to handle SafeConfigParser deprecation correctly:
if six.PY2:   
    from six.moves.configparser import SafeConfigParser as SafeConfigParser_
else:
    from six.moves.configparser import ConfigParser as SafeConfigParser_
    
from os import path
from abc import ABCMeta, abstractmethod
import logging
log = logging.getLogger(__name__)

from OpenSSL import crypto


class CertificateAuthorityError(Exception):
    """Base class for exceptions for CertificateAuthority class"""
        
    
class CertificateAuthorityConfigError(CertificateAuthorityError):
    """Error reading options from config file"""
    
    
class CertificateIssuingError(CertificateAuthorityError):
    """Error issuing a certificate"""
    
    
class AbstractCertificateAuthority(object):
    """Provide basic functionality for a Certificate Authority"""
    DEFAULT_NOT_BEFORE_TIME = 0
    DEFAULT_NOT_AFTER_TIME = 60*60*24*365*3 # 3 years
    
    CACERT_DEFAULT_NOT_BEFORE_TIME = 0
    CACERT_DEFAULT_NOT_AFTER_TIME = 60*60*24*365*5 # 5 years

    MIN_KEY_NBITS_DEFAULT = 2048
    DIGEST_TYPE_DEFAULT = "sha256"

    CERTIFICATE_VERSION2 = 1
    CERTIFICATE_VERSION3 = 2

    SERIAL_NUM_DEFAULT = six.integer_types[-1](0)

    CERT_FILEPATH_OPTNAME = "cert_filepath"
    PRIKEY_FILEPATH_OPTNAME = "key_filepath"
    PRIKEY_PASSWD_OPTNAME = "key_passwd"
    
    __metaclass__ = ABCMeta
    __slots__ = (
        '__cert', 
        '__key', 
        '__serial_num_counter', 
        '__min_key_nbits',
        '__serial_filepath'
    )
    
    def __init__(self):
        """Create certificate authority instance"""
        self.__cert = None
        self.__key = None
        self.__serial_num_counter = self.__class__.SERIAL_NUM_DEFAULT
        self.__min_key_nbits = self.__class__.MIN_KEY_NBITS_DEFAULT
        self.__serial_filepath = None
    
    @abstractmethod
    def issue_certificate(self, cert_req):
        """
        Generate a certificate given a certificate request.
    
        @param cert_req: Certificate request to use
        """
        
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
        if isinstance(cfg, six.string_types):
            config_file_path = path.expandvars(cfg)
            here_dir = path.dirname(config_file_path)
            _cfg = SafeConfigParser_(defaults={'here':here_dir})
            _cfg.optionxform = str

            _cfg.read(config_file_path)
            
        elif isinstance(cfg, ConfigParser):
            _cfg = cfg   
        else:
            raise AttributeError('Expecting basestring or ConfigParser type '
                                 'for "cfg" attribute; got %r type' % type(cfg))
                        
        # Get items for this section as a dictionary so that parse_keywords can
        # used to update the object
        kw = dict([(opt_name, val) for opt_name, val in _cfg.items(section)
                   if opt_name != 'here'])
        
        # ... but first get file path settings which aren't included as 
        # instance variables
        cert_filepath_opt = prefix + self.__class__.CERT_FILEPATH_OPTNAME
        prikey_filepath_opt = prefix + self.__class__.PRIKEY_FILEPATH_OPTNAME
        prikey_file_passwd_opt = prefix + self.__class__.PRIKEY_PASSWD_OPTNAME
        
        try:
            cert_filepath = kw.pop(cert_filepath_opt)
            prikey_filepath = kw.pop(prikey_filepath_opt)
            
        except KeyError as e:
            raise CertificateAuthorityConfigError('Missing option from config '
                                                  '%s' % str(e))

        # Password does not need to be set and can default to None
        prikey_file_passwd = kw.pop(prikey_file_passwd_opt, None)
            
        # Set 'cert' and 'key' attributes from equivalent files
        self.parse_files(cert_filepath, prikey_filepath, 
                         key_file_passwd=prikey_file_passwd)
        
        # Take prefix setting from config if set otherwise default to input
        # setting made to this method
        if 'prefix' not in kw and prefix:
            kw['prefix'] = prefix
        
        # Prune cert and key settings as these cannot be intelligently read from
        # a config file.
        for key in ('cert', 'key'):
            if key in kw:
                del key
                    
        self.parse_keywords(**kw)
        
        if self.serial_filepath is not None:
            self.init_serial_file()
        
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
        prefix_len = len(prefix)
        for opt_name, val in kw.items():
            if prefix:
                # Filter attributes based on prefix
                if opt_name.startswith(prefix):
                    setattr(self, opt_name[prefix_len:], val)
            else:
                # No prefix set - attempt to set all attributes   
                setattr(self, opt_name, val)
                
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
        @rtype: ca.base.AbstractCertificateAuthority derived type
        """
        obj = cls()
        
        # ... but first get file path settings which aren't included as 
        # instance variables
        cert_filepath_opt = prefix + cls.CERT_FILEPATH_OPTNAME
        prikey_filepath_opt = prefix + cls.PRIKEY_FILEPATH_OPTNAME
        prikey_file_passwd_opt = prefix + cls.PRIKEY_PASSWD_OPTNAME
        
        cert_filepath = kw.pop(cert_filepath_opt, None)
        if cert_filepath is None and 'cert' not in kw:
            raise CertificateAuthorityConfigError(
                    "No 'cert' or %r option set" % cls.CERT_FILEPATH_OPTNAME)
   
        prikey_filepath = kw.pop(prikey_filepath_opt, None)
        if prikey_filepath is None and 'key' not in kw:
            raise CertificateAuthorityConfigError(
                    "No 'key' or %r option set" % cls.PRIKEY_FILEPATH_OPTNAME)
            
        # Password does not need to be set and can default to None
        prikey_file_passwd = kw.pop(prikey_file_passwd_opt, None)
            
        # Set 'cert' and 'key' attributes from equivalent files
        if cert_filepath and prikey_filepath:
            obj.parse_files(cert_filepath, prikey_filepath, 
                            key_file_passwd=prikey_file_passwd)

        obj.parse_keywords(prefix=prefix, **kw)
        
        return obj
        
    def parse_files(self, cert_filepath, key_filepath, key_file_passwd=None):
        """Read certificate and private key files setting instance variables
        """
        with open(key_filepath) as key_file:
            key_file_txt = key_file.read()
            
        args = crypto.FILETYPE_PEM, key_file_txt
        if key_file_passwd:
            # Force coercion to byte string for both Python 2 and 3
            args += (six.b(str(key_file_passwd)), )
            
        self.key = crypto.load_privatekey(*args)
        
        with open(cert_filepath) as cert_file:
            cert_file_txt = cert_file.read()
            
        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                            cert_file_txt)

        
    @classmethod
    def from_files(cls, cert_filepath, key_filepath, key_file_passwd=None):
        """Construct new instance certificate and private key files
        @return: new certificate authority instance
        """
        ca = cls()
        ca.parse_files(cert_filepath, key_filepath, 
                       key_file_passwd=key_file_passwd)
        
        return ca
    
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
        return self.__serial_num_counter

    @serial_num_counter.setter
    def serial_num_counter(self, value):
        if not isinstance(value, six.integer_types):
            raise TypeError('Expecting int or long type for '
                            '"serial_num_counter" got %r type' % type(value))
        self.__serial_num_counter = six.integer_types[-1](value)
        
    @property
    def serial_filepath(self):
        return self.__serial_filepath
    
    @serial_filepath.setter
    def serial_filepath(self, value):
        if not isinstance(value, six.string_types):
            raise TypeError('Expecting string type for "serial_filepath" '
                            'got %r type' % type(value))
        self.__serial_filepath = value
        
    @property
    def min_key_nbits(self):
        """Minimum number of bits required for key in certificate request"""
        return self.__min_key_nbits

    @min_key_nbits.setter
    def min_key_nbits(self, value):
        if not isinstance(value, six.integer_types + six.string_types):
            raise TypeError('Expecting int or long type for "min_key_nbits" '
                            'got %r type' % type(value))
            
        self.__min_key_nbits = six.integer_types[-1](value)
          
    def _read_serial_file(self):
        '''Read serial number from serial file'''
        serial_file = open(self.serial_filepath, 'r')
        
        try:
            self.serial_num_counter = six.integer_types[-1](serial_file.read())
        finally:
            serial_file.close()
                    
    def _write_serial_file(self):
        '''Write serial number to serial file'''
        serial_file = open(self.serial_filepath, 'w')
        
        try:
            serial_file.write("%2l" % self.serial_num_counter)
        finally:
            serial_file.close()
            
    def init_serial_file(self):
        '''Initialise serial file if doesn't already exist'''
        if not path.exists(self.serial_filepath):
            self._write_serial_file()
