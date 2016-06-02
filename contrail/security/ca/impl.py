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

import six
    
from OpenSSL import crypto

from contrail.security.ca.base import AbstractCertificateAuthority as AbstractCA
from contrail.security.ca.base import  CertificateAuthorityError

if six.PY2:
    _unicode_for_py3 = lambda string_: string_
else:
    _unicode_for_py3 = lambda string_: string_.decode()
    
    
class CertificateAuthorityCSRError(CertificateAuthorityError):
    """Error with input certificate signing request"""


class CertificateAuthority(AbstractCA):
    '''Certificate Authority implementation entirely based on PyOpenSSL bindings
    '''
    
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
        self.__digest = self.__class__.DIGEST_TYPE_DEFAULT
        self.__certificate_version = self.__class__.CERTIFICATE_VERSION3
        self.__ca_true = False
        self.__subject_alt_name = False
        
    @property
    def not_before_time_nsecs(self):
        """Default not before time in seconds for certs issued"""
        return self.__not_before_time_nsecs

    @not_before_time_nsecs.setter
    def not_before_time_nsecs(self, value):
        if not isinstance(value, six.string_types + six.integer_types):
            raise TypeError('Expecting int, long or string type for '
                            '"not_before_time_nsecs" got %r type' % type(value))
        
        # Nb. PyOpenSSL expects integer value for 
        # OpenSSL.crypto.X509.gmtime_adj_notAfter
        self.__not_before_time_nsecs = int(value)
        
    @property
    def not_after_time_nsecs(self):
        """Default not after time in seconds for certs issued"""
        return self.__not_after_time_nsecs

    @not_after_time_nsecs.setter
    def not_after_time_nsecs(self, value):
        if not isinstance(value, six.integer_types + six.string_types):
            raise TypeError('Expecting int, long or string type for '
                            '"not_after_time_nsecs" got %r type' % type(value))
            
        self.__not_after_time_nsecs = int(value)
  
    @property
    def digest(self):
        return self.__digest
    
    @digest.setter
    def digest(self, value):
        if not isinstance(value, six.string_types):
            raise TypeError('Expecting string type for "digest" '
                            'got %r type' % type(value))
        self.__digest = value
  
    @property
    def certificate_version(self):
        return self.__certificate_version
    
    @certificate_version.setter
    def certificate_version(self, value):
        if not isinstance(value, six.string_types):
            raise TypeError('Expecting string type for "certificate_version" '
                            'got %r type' % type(value))
        self.__certificate_version = value
                        
    @property
    def ca_true(self):
        """Set to true to issue *CA* certificates by default"""
        return self.__ca_true

    @ca_true.setter
    def ca_true(self, value):
        if isinstance(value, six.string_types):
            self.__ca_true = value.lower() in ('1', 'true')
            
        elif isinstance(value, six.integer_types):
            self.__ca_true = six.integer_types[-1](value)
        else:
            raise TypeError('Expecting int or long type for '
                            '"ca_true" got %r type' % type(value))
        
    @property
    def subject_alt_name(self):
        """Set to true to set subject alt name in certificates by default"""
        return self.__subject_alt_name

    @subject_alt_name.setter
    def subject_alt_name(self, value):
        if isinstance(value, six.string_types):
            self.__subject_alt_name = value.lower() in ('1', 'true')
            
        elif isinstance(value, six.integer_types):
            self.__subject_alt_name = six.integer_types[-1](value)
        else:
            raise TypeError('Expecting int or long type for '
                            '"ca_true" got %r type' % type(value))        
                
    def issue_certificate(self, 
                        cert_req,
                        subject_name=None, 
                        digest=AbstractCA.DIGEST_TYPE_DEFAULT,
                        certificate_version=AbstractCA.CERTIFICATE_VERSION3,
                        ca_true=False,
                        subject_alt_name=None,
                        extensions=None):
        """
        Generate a certificate given a certificate request.
    
        @param cert_req: Certificate request to use
        @param not_before_time_nsecs: Timestamp (relative to now) when the 
        certificate starts being valid
        @param subject_name: set alternate subject name to one specified in the
        certificate request
        @type subject_name: OpenSSL.crypto.X509Name
        @param digest: Digest method to use for signing, default is sha256
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
        
        # Certificate extensions - requires byte string, unicode will fail
        if ca_true:
            basic_constraints = b'CA:true'
            x509_extensions = [
                crypto.X509Extension(b"keyUsage", True, 
                                     b"keyCertSign, cRLSign"),
                crypto.X509Extension(b"subjectKeyIdentifier", False, 
                                     b"hash", subject=cert)
            ]
        else:
            basic_constraints = b'CA:false'
            x509_extensions = []
            
        # Add basic constraints as first element of extensions list
        basic_constraints_ext = crypto.X509Extension(b'basicConstraints', 
                                                     True, 
                                                     basic_constraints)
        x509_extensions += [basic_constraints_ext]
            
        # Check for a subject alt names extension, if present add as is.
        if isinstance(subject_alt_name, six.string_types):
            subject_alt_name_ext = crypto.X509Extension(b'subjectAltName', 
                                                False, 
                                                six.b(str(subject_alt_name)))
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
            dn = ''.join(["/%s=%s" % (_unicode_for_py3(k), _unicode_for_py3(v)) 
                          for k,v in cert.get_subject().get_components()])
            
            log.info('Issuing certificate with subject %r', dn)
        
        return cert 
    
    def _add_certificate_ext(self, cert, extensions):
        """Add certificate extension - derived classes can override to customise
        behaviour
        """
        x509_extensions = []
        for ext_name, ext_val, ext_crit in extensions:
            # Six and str calls required to yield byte string output for 
            # Python 3 and 2 and respectively.
            x509_cust_ext = crypto.X509Extension(six.b(str(ext_name)), 
                                                 ext_crit, 
                                                 six.b(str(ext_val)))
            x509_extensions.append(x509_cust_ext)
            
        return x509_extensions
    
    
    @classmethod
    def gen_root_ca_cert(cls, 
                    dn, 
                    digest_type=AbstractCA.DIGEST_TYPE_DEFAULT,
                    not_before_time=AbstractCA.CACERT_DEFAULT_NOT_BEFORE_TIME,
                    not_after_time=AbstractCA.CACERT_DEFAULT_NOT_AFTER_TIME):
        '''Helper method - Generate key pair and certificate for a root CA'''
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, cls.MIN_KEY_NBITS_DEFAULT)
    
        ca_cert = crypto.X509()
        
        # Versioning is zero indexed!!
        ca_cert.set_version(cls.CERTIFICATE_VERSION3)
        ca_cert.set_serial_number(1)
        
        # Set subject name fields from the input distinguished name
        subj = ca_cert.get_subject()
        for k, v in dn:
            setattr(subj, k, v)
            
        ca_cert.gmtime_adj_notBefore(not_before_time)
        ca_cert.gmtime_adj_notAfter(not_after_time)
        ca_cert.set_issuer(ca_cert.get_subject())
        ca_cert.set_pubkey(ca_key)
        ca_cert.add_extensions([
          crypto.X509Extension(b"basicConstraints", True, 
                               b"CA:true, pathlen:0"),
          crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
          crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash",
                                       subject=ca_cert),
          ])
        ca_cert.sign(ca_key, digest_type)
        
        return ca_key, ca_cert
    
    @classmethod
    def gen_root_ca(cls, *gen_root_ca_args, **gen_root_ca_kwargs):
        '''Instantiate certificate authority object containing a newly
        created root CA cert and key pair.  NB. caller must take responsibility
        to populate other CA object attributes
        '''
        ca = CertificateAuthority()
        ca.key, ca.cert = cls.gen_root_ca_cert(*gen_root_ca_args,
                                               **gen_root_ca_kwargs)
        
        return ca