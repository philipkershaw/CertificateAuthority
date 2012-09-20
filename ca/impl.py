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

from ca.base import AbstractCertificateAuthority, CertificateAuthorityError
from ca.cert_req import CertReqUtils


class CertificateAuthorityCSRError(CertificateAuthorityError):
    """Error with input certificate signing request"""


class CertificateAuthority(AbstractCertificateAuthority):
    '''Certificate Authority implementation entirely based on PyOpenSSL bindings
    '''
    
    def issue_certificate(
        self, 
        cert_req, 
        (not_before_ndays, not_after_ndays), 
        digest=CertReqUtils.MESSAGE_DIGEST_TYPE_DEFAULT,
        certificate_version=AbstractCertificateAuthority.CERTIFICATE_VERSION3,
        ca_true=False,
        subject_alt_name=False,
        extensions=None):
        """
        Generate a certificate given a certificate request.
    
        @param cert_req: Certificate request to use
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
        pkey = cert_req.get_pubkey()
        pkey_nbits = pkey.bits()
        if pkey_nbits < self.min_key_nbits:
            raise CertificateAuthorityCSRError('Certificate signing request '
                                               'must use a key with at least '
                                               '%d bits, input request has a '
                                               'key with %d bits' % pkey_nbits)
        
        cert = crypto.X509()
        
        # Update serial number from value stored in file if available
        if self.serial_filepath:
            self._read_serial_file()
        
        cert.set_serial_number(self.serial_num_counter)
        
        cert.gmtime_adj_notBefore(not_before_ndays)
        cert.gmtime_adj_notAfter(not_after_ndays)
        
        cert.set_issuer(self.cert.get_subject())
        cert.set_subject(cert_req.get_subject())
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
