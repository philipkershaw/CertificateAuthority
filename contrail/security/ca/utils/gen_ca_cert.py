#/usr/bin/env python
"""Utility to generate Certificate Authority certificate and key
"""
__author__ = "P J Kershaw"
__date__ = "10/08/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
from optparse import OptionParser
import logging

import six
from OpenSSL import crypto

from contrail.security.ca.impl import CertificateAuthority


DEF_CACERT_FILEPATH = "./ca.crt"
DEF_CAPRIKEY_FILEPATH = "./ca.key"
DEF_CACERT_SUBJECT = [('CN', 'NDG Test CA'), ('O', 'NDG'), ('OU', 'Security')]


def main():
    '''Utility to fetch data using HTTP or HTTPS GET from a specified URL.
    '''
    
    def _parse_subject_name(subj):
        for item in subj.split(','):
            field, value = item.split('=')
            yield field.strip(), value.strip()
            
    parser = OptionParser(usage="%prog [options]")
    
    parser.add_option("-c", "--ca-cert-out", dest="cacert_filepath", 
                      metavar="FILE",
                      default=DEF_CACERT_FILEPATH,
                      help="Certificate file - defaults to %r" % 
                            DEF_CACERT_FILEPATH)

    parser.add_option("-k", "--ca-pri-key-out", dest="cakey_filepath", 
                      metavar="FILE",
                      default=DEF_CAPRIKEY_FILEPATH,
                      help="CA Private key file - defaults %r" % 
                            DEF_CAPRIKEY_FILEPATH)

    parser.add_option("-p", "--ca-pri-key-passphrase", dest="cakey_passphrase", 
                      metavar="PASSPHRASE",
                      default=None,
                      help="CA Private key file passphrase")
    
    parser.add_option("-s", "--subject", dest="cert_subj", 
                      metavar="O=Org,OU=Org unit,CN=Common name, ...",
                      default=DEF_CACERT_SUBJECT,
                      help="Subject name for new CA certificate - defaults %r" % 
                            ','.join(['%s=%s' % i for i in DEF_CACERT_SUBJECT]))
    
    parser.add_option("-d", "--debug", action="store_true", dest="debug", 
                      default=False,
                      help="Print debug information.")

    options = parser.parse_args()[0]

    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if isinstance(options.cert_subj, six.string_types):
        cert_subj = _parse_subject_name(options.cert_subj)
    else:
        cert_subj = options.cert_subj
    
    if options.cakey_passphrase is not None:
        dump_privatekey_args = ("blowfish", options.cakey_passphrase)  
    else:
        dump_privatekey_args = ()
        
    ca = CertificateAuthority.gen_root_ca(cert_subj)
    
    s_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, ca.key, 
                                   *dump_privatekey_args)
    with open(options.cakey_filepath, 'wb') as key_file:
        key_file.write(s_key)
    
    s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, ca.cert)
    with open(options.cacert_filepath, 'wb') as cert_file:
        cert_file.write(s_cert)


if __name__=='__main__':
    main()