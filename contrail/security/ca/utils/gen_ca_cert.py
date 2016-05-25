#/usr/bin/env python
"""Utility to generate Certificate Authority certificate and key
"""
__author__ = "P J Kershaw"
__date__ = "10/08/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
from OpenSSL import crypto

class CAGeneration(object):
    YEARS_VALIDITY = 5
    SECS_IN_YEAR = 24 * 60 * 60 * 365
    KEY_N_BITS = 2048
    X509_VERSION = 3
    SIGNING_ALG_ID = "sha256"
    
    @classmethod
    def gen_ca_cert(cls, dn, years_validity=YEARS_VALIDITY):
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, cls.KEY_N_BITS)
    
        ca_cert = crypto.X509()
        
        # Versioning is zero indexed!!
        x509_version = cls.X509_VERSION
        ca_cert.set_version(x509_version - 1)
        ca_cert.set_serial_number(1)
        subj = ca_cert.get_subject()
        for k, v in dn:
            setattr(subj, k, v)
            
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(cls.SECS_IN_YEAR * years_validity)
        ca_cert.set_issuer(ca_cert.get_subject())
        ca_cert.set_pubkey(ca_key)
        ca_cert.add_extensions([
          crypto.X509Extension(b"basicConstraints", True, 
                               b"CA:true, pathlen:0"),
          crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
          crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash",
                                       subject=ca_cert),
          ])
        ca_cert.sign(ca_key, cls.SIGNING_ALG_ID)
        
        return ca_key, ca_cert


DEF_CACERT_FILEPATH = "./ca.crt"
DEF_CAPRIKEY_FILEPATH = "./ca.key"
DEF_CACERT_SUBJECT = [('CN', 'NDG Test CA'), ('O', 'NDG'), ('OU', 'Security')]

def main():
    '''Utility to fetch data using HTTP or HTTPS GET from a specified URL.
    '''
    from optparse import OptionParser
    import logging
    
    import six
    
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
        
    key_pair, cert = CAGeneration.gen_ca_cert(cert_subj)
    
    s_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
    with open(options.cakey_filepath, 'wb') as key_file:
        key_file.write(s_key)
    
    s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    with open(options.cacert_filepath, 'wb') as cert_file:
        cert_file.write(s_cert)


if __name__=='__main__':
    main()