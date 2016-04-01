"""Certificate Authority implementation using openssl excutable callout
"""
__author__ = "P J Kershaw"
__date__ = "19/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import tempfile
import string
import subprocess
import os
import logging
log = logging.getLogger(__name__)
    
import six

from OpenSSL import crypto

from contrail.security.ca.base import (AbstractCertificateAuthority,
                                       CertificateIssuingError)


class CertificateAuthorityWithCallout(AbstractCertificateAuthority):
    '''Certificate Authority implementation using a callout to an OpenSSL
    executable to issue certificates.  This enables more flexibility in how
    certificates are configured
    '''
    __slots__ = AbstractCertificateAuthority.__slots__ + ('__cert_issue_cmd', )
    
    def __init__(self):
        super(CertificateAuthorityWithCallout, self).__init__()
        self.__cert_issue_cmd = None
        
    def issue_certificate(self, cert_req):
        '''Certificate issuing from a callout to an OpenSSL executable
    
        @param cert_req: Certificate request to use
        @return: output certificate
        ''' 
        try:
            out_cert_file = tempfile.NamedTemporaryFile(delete=False)
            in_csr_file = tempfile.NamedTemporaryFile(delete=False)
            s_cert_req = crypto.dump_certificate_request(crypto.FILETYPE_PEM, 
                                                         cert_req)
            in_csr_file.seek(0)
            in_csr_file.write(s_cert_req)
            in_csr_file.close()
            
            cmd_tmpl = string.Template(self.cert_issue_cmd)
            populated_cmd = cmd_tmpl.substitute(in_csr=in_csr_file.name,
                                                out_cert=out_cert_file.name)
            
            log.debug('Executing command to issue certificate: %r', 
                      populated_cmd)
            
            cmd_args = populated_cmd.split()
                    
            proc = subprocess.Popen(cmd_args, 
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
    
            stdoutdata, stderrdata = proc.communicate()           
            if proc.returncode == 0:
                if stdoutdata:
                    log.info('stdout message: \'%s\'; for command: %r', 
                             stdoutdata,
                             populated_cmd)
            
                if stderrdata:
                    log.info('stderr message: \'%s\'; for command: %r', 
                              stderrdata,
                              populated_cmd)
 
                out_cert = crypto.load_certificate(
                                               crypto.FILETYPE_PEM, 
                                               open(out_cert_file.name).read())
            else:
                error_msg = ''
                if stdoutdata:
                    error_msg += ('stdout message: \'%s\'; for command: %r' %
                                                (stdoutdata, populated_cmd))
            
                if stderrdata:
                    error_msg += ('stderr message: \'%s\'; for command: %r' % 
                                                (stderrdata, populated_cmd))
                    
                raise CertificateIssuingError('Error issuing certificate: %s' %
                                              error_msg)
        finally:
            os.unlink(in_csr_file.name)
            os.unlink(out_cert_file.name)
            
        return out_cert
    
    @property
    def cert_issue_cmd(self):
        return self.__cert_issue_cmd
    
    @cert_issue_cmd.setter
    def cert_issue_cmd(self, value):
        if not isinstance(value, six.string_types):
            raise TypeError('Expecting string type for "cert_issue_cmd" '
                            'got %r type' % type(value))
        self.__cert_issue_cmd = value