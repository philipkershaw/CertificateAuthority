#/usr/bin/env python
'''
Created on Aug 10, 2012

@author: philipkershaw
'''
from OpenSSL import crypto


def gen_ca_cert(dn):
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_cert = crypto.X509()
    ca_cert.set_version(3)
    ca_cert.set_serial_number(1)
    subj = ca_cert.get_subject()
    for k, v in dn.items():
        setattr(subj, k, v)
        
    ca_cert.gmtime_adj_notBefore(0)       
    ca_cert.gmtime_adj_notAfter(24 * 60 * 60)
    ca_cert.set_issuer(ca_cert.get_subject())
    ca_cert.set_pubkey(ca_key)
    ca_cert.add_extensions([
      crypto.X509Extension("basicConstraints", True,
                                   "CA:true, pathlen:0"),
      crypto.X509Extension("keyUsage", True,
                                   "keyCertSign, cRLSign"),
      crypto.X509Extension("subjectKeyIdentifier", False, "hash",
                                   subject=ca_cert),
      ])
    ca_cert.sign(ca_key, "sha1")
    
    return ca_key, ca_cert

        
if __name__ == "__main__":
    from os import path
    import sys
    this_dir = path.abspath(path.dirname(__file__))
    
    if len(sys.argv) == 3:
        cakey_filepath, cacert_filepath = sys.argv[1:2]
    else:
        cakey_filepath = path.join(this_dir, 'myca.key')
        cacert_filepath = path.join(this_dir, 'myca.crt')
    
    dn = {'CN': 'NDG Test CA', 'O': 'NDG', 'OU': 'Security'}
    key_pair, cert = gen_ca_cert(dn)
    
    s_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
    open(cakey_filepath, 'w').write(s_key)
    s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    open(cacert_filepath, 'w').write(s_cert)

