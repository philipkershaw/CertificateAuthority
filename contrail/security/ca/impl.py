"""Certificate Authority default implementation
"""
__author__ = "P J Kershaw"
__date__ = "19/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)
    
from OpenSSL import crypto

from contrail.security.ca.cert_req import CertReqUtils
from contrail.security.ca.base import (AbstractCertificateAuthority, 
                                       CertificateAuthorityError)


class CertificateAuthorityCSRError(CertificateAuthorityError):
    """Error with input certificate signing request"""


class CertificateAuthority(AbstractCertificateAuthority):
    '''Certificate Authority implementation entirely based on PyOpenSSL bindings
    '''
    DEFAULT_NOT_BEFORE_TIME = 0
    DEFAULT_NOT_AFTER_TIME = 60*60*24*365*3 # 3 years
    
    __slots__ = (
        '__not_before_time_nsecs',
        '__not_after_time_nsecs',
        '__digest',
        '__certificate_version',
        '__ca_true',
        '__subject_alt_name'
    )
    def __init__(self):
        super(CertificateAuthority, self).__init__()
        
        self.__not_before_time_nsecs = self.__class__.DEFAULT_NOT_BEFORE_TIME 
        self.__not_after_time_nsecs = self.__class__.DEFAULT_NOT_AFTER_TIME 
        self.__digest = CertReqUtils.MESSAGE_DIGEST_TYPE_DEFAULT
        self.__certificate_version = self.__class__.CERTIFICATE_VERSION3
        self.__ca_true = False
        self.__subject_alt_name = False
        
    @property
    def not_before_time_nsecs(self):
        """Default not before time in seconds for certs issued"""
        return self.__not_before_time_nsecs

    @not_before_time_nsecs.setter
    def not_before_time_nsecs(self, value):
        if not isinstance(value, (long, int, basestring)):
            raise TypeError('Expecting int, long or string type for '
                            '"not_before_time_nsecs" got %r type' % type(value))
        self.__not_before_time_nsecs = long(value)
        
    @property
    def not_after_time_nsecs(self):
        """Default not after time in seconds for certs issued"""
        return self.__not_after_time_nsecs

    @not_after_time_nsecs.setter
    def not_after_time_nsecs(self, value):
        if not isinstance(value, (long, int, basestring)):
            raise TypeError('Expecting int, long or string type for '
                            '"not_after_time_nsecs" got %r type' % type(value))
        self.__not_after_time_nsecs = long(value)
  
    @property
    def digest(self):
        return self.__digest
    
    @digest.setter
    def digest(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "digest" '
                            'got %r type' % type(value))
        self.__digest = value
  
    @property
    def certificate_version(self):
        return self.__certificate_version
    
    @certificate_version.setter
    def certificate_version(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "certificate_version" '
                            'got %r type' % type(value))
        self.__certificate_version = value
                        
    @property
    def ca_true(self):
        """Set to true to issue *CA* certificates by default"""
        return self.__ca_true

    @ca_true.setter
    def ca_true(self, value):
        if isinstance(value, basestring):
            self.__ca_true = value.lower() in ('1', 'true')
            
        elif isinstance(value, (long, int)):
            self.__ca_true = long(value)
        else:
            raise TypeError('Expecting int or long type for '
                            '"ca_true" got %r type' % type(value))
        
    @property
    def subject_alt_name(self):
        """Set to true to set subject alt name in certificates by default"""
        return self.__subject_alt_name

    @subject_alt_name.setter
    def subject_alt_name(self, value):
        if isinstance(value, basestring):
            self.__subject_alt_name = value.lower() in ('1', 'true')
            
        elif isinstance(value, (long, int)):
            self.__subject_alt_name = long(value)
        else:
            raise TypeError('Expecting int or long type for '
                            '"ca_true" got %r type' % type(value))        
                
    def issue_certificate(
        self, 
        cert_req,
        subject_name=None, 
        digest=CertReqUtils.MESSAGE_DIGEST_TYPE_DEFAULT,
        certificate_version=AbstractCertificateAuthority.CERTIFICATE_VERSION3,
        ca_true=False,
        subject_alt_name=False,
        extensions=None):
        """
        Generate a certificate given a certificate request.
    
        @param cert_req: Certificate request to use
        @param not_before_time_nsecs: Timestamp (relative to now) when the 
        certificate starts being valid
        @param subject_name: set alternate subject name to one specified in the
        certificate request
        @type subject_name: OpenSSL.crypto.X509Name
        @param digest: Digest method to use for signing, default is md5
        @param ca_true: set to True to set CA:true in the basic constraints 
        extension
        @type ca_true: bool
        @return: The signed certificate in an X.509 object
        """
        
        # Check number of bits in key
        pkey = cert_req.get_pubkey()
        pkey_nbits = pkey.bits()
        if pkey_nbits < self.min_key_nbits:
            raise CertificateAuthorityCSRError('Certificate signing request '
                                               'must use a key with at least '
                                               '%d bits, input request has a '
                                               'key with %d bits' % 
                                               (self.min_key_nbits, pkey_nbits))
        
        cert = crypto.X509()
        
        # Update serial number from value stored in file if available
        if self.serial_filepath:
            self._read_serial_file()
        
        cert.set_serial_number(self.serial_num_counter)
        
        cert.gmtime_adj_notBefore(self.not_before_time_nsecs)
        cert.gmtime_adj_notAfter(self.not_after_time_nsecs)

        cert.set_issuer(self.cert.get_subject())
        
        if subject_name is None:
            subject_name = cert_req.get_subject()
            
        cert.set_subject(subject_name)
        cert.set_pubkey(cert_req.get_pubkey())
        
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
        
        if self.serial_filepath is not None:
            self._write_serial_file()
            
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
            x509_cust_ext = crypto.X509Extension(ext_name, 
                                                 ext_crit, 
                                                 str(ext_val))
            x509_extensions.append(x509_cust_ext)
            
        return x509_extensions
