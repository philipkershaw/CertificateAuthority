#/usr/bin/env python
"""Utility to generate Certificate Authority certificate and key
"""
__author__ = "P J Kershaw"
__date__ = "10/08/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import sys
from optparse import OptionParser, OptionGroup
from argparse import ArgumentParser
import logging

import six
from OpenSSL import crypto

from contrail.security.ca.impl import CertificateAuthority


class CertificateAuthorityCLI(object):
    """Certificate authority command line interface"""
    GEN_CA_CMD = "gen_ca"
    ISSUE_CERT_CMD = "issue_cert"

    DEF_CACERT_FILEPATH = "./ca.crt"
    DEF_CAPRIKEY_FILEPATH = "./ca.key"
    DEF_CACERT_SUBJECT = [('CN', 'NDG Test CA'), ('O', 'NDG'), 
                          ('OU', 'Security')]
    
    DEF_CERTREQ_FILEPATH = './request.csr'
    DEF_CERT_FILEPATH = './cert.crt'
    PASSPHRASE_ENCR_ALG = "blowfish"
    
    @classmethod
    def _parse_passphrase_cmdline_arg(cls, passphrase_in):
        '''Convenience utility for managing passphrase input from stdin
        '''
        if passphrase_in == "-":
            return sys.stdin.read().strip()
        else:
            return passphrase_in
        
    def __init__(self):
        self.ca = CertificateAuthority()

    @staticmethod
    def parse_subject_name(subj):
        '''Convert a certificate subject name from a string into a list of
        key value pair tuples
        
        :return: list of key value pair tuples corresponding to subject name
        fields
        '''
        for item in subj.split(','):
            field, value = item.split('=')
            yield field.strip(), value.strip()
        
    def _issue_cert(self, cmdline_args):
        '''Issue certificate based on command line arguments

        :type    argparse.Namespace
        :param     cmdline_args: command line arguments from argparse 
        ArgumentParser
        '''
        with open(cmdline_args.cacert_in_filepath, 'rb') as cacert_file:
            s_cacert = cacert_file.read()
            
        self.ca.cert = crypto.load_certificate(crypto.FILETYPE_PEM, s_cacert)

        with open(cmdline_args.cakey_in_filepath, 'rb') as cakey_file:
            s_cakey = cakey_file.read()
            
        self.ca.key = crypto.load_privatekey(crypto.FILETYPE_PEM, s_cakey)

        with open(cmdline_args.certreq_filepath, 'rb') as certreq_file:
            s_certreq = certreq_file.read()

        certreq = crypto.load_certificate_request(crypto.FILETYPE_PEM, 
                                                  s_certreq)
            
        cert = self.ca.issue_certificate( 
                        certreq,
                        ca_true=False,
                        subject_alt_name=cmdline_args.subject_alt_names)
        
        s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    
        with open(cmdline_args.cert_filepath, 'wb') as cert_file:
            cert_file.write(s_cert)  
              
    def _gen_root_ca(self, cmdline_args):
        '''Generate fresh root CA cert and key based on command line inputs
        
        :type    argparse.Namespace
        :param     cmdline_args: command line arguments from argparse 
        ArgumentParser
        '''
           
        if isinstance(cmdline_args.cacert_subj, six.string_types):
            cacert_subj = self.__class__.parse_subject_name(
                                                cmdline_args.cacert_subj)
        else:
            cacert_subj = cmdline_args.cacert_subj
        
        if cmdline_args.cakey_passphrase is not None:
            cakey_passphrase = self.__class__._parse_passphrase_cmdline_arg(
                                                cmdline_args.cakey_passphrase)
            dump_privatekey_args = (self.__class__.PASSPHRASE_ENCR_ALG, 
                                    cakey_passphrase)  
        else:
            dump_privatekey_args = ()
            
        ca = CertificateAuthority.gen_root_ca(cacert_subj)
        
        s_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, ca.key, 
                                       *dump_privatekey_args)
        with open(cmdline_args.cakey_filepath, 'wb') as key_file:
            key_file.write(s_key)
        
        s_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, ca.cert)
        with open(cmdline_args.cacert_filepath, 'wb') as cert_file:
            cert_file.write(s_cert)
        
    def main(self, *args):
        '''Main method for parsing arguments from the command line or input
        tuple and calling appropriate command
        
        :type *args: tuple
        :param *args: list containing command line arguments.  If not set, 
        arguments are set from sys.argv
        '''
                
        parser = ArgumentParser(
                            description='Simple Certificate Authority utility')
                  
        parser.add_argument("-d", "--debug", action="store_true", dest="debug", 
                          default=False,
                          help="Print debug information.")
                
        sub_parsers = parser.add_subparsers(help='Set required command:')
        
        # Generate CA cert and key command configuration
        gen_ca_descr_and_help = 'Generate a new certificate and key for the CA'
        gen_ca_arg_parser = sub_parsers.add_parser(self.__class__.GEN_CA_CMD,
                                           help=gen_ca_descr_and_help,
                                           description=gen_ca_descr_and_help)
        
        gen_ca_arg_parser.add_argument("-c", "--ca-cert-out", 
                          dest="cacert_filepath", 
                          metavar="FILE",
                          default=self.__class__.DEF_CACERT_FILEPATH,
                          help="CA Certificate file - defaults to %r" % 
                                self.__class__.DEF_CACERT_FILEPATH)
    
        gen_ca_arg_parser.add_argument("-k", "--ca-pri-key-out",
                          dest="cakey_filepath", 
                          metavar="FILE",
                          default=self.__class__.DEF_CAPRIKEY_FILEPATH,
                          help="CA Private key file - defaults %r" % 
                                self.__class__.DEF_CAPRIKEY_FILEPATH)
    
        gen_ca_arg_parser.add_argument("-p", "--ca-pri-key-passphrase-out", 
                          dest="cakey_passphrase", 
                          metavar="PASSPHRASE",
                          default=None,
                          help="Optional setting - set passphrase to protect "
                               "access to new CA Private key file. Set "
                               "to '-' to read from standard input")
        
        gen_ca_arg_parser.add_argument("-s", "--ca-cert-subject", 
                          dest="cacert_subj", 
                          metavar="'O=Org,OU=Org unit,CN=Common name, ...'",
                          default=self.__class__.DEF_CACERT_SUBJECT,
                          help="Subject name for new CA certificate - "
                               "defaults %r" % 
                                ','.join(['%s=%s' % i 
                                for i in self.__class__.DEF_CACERT_SUBJECT]))
        
        gen_ca_arg_parser.set_defaults(func=self._gen_root_ca)
        
        # Issue certificate command configuration
        issue_cert_descr_and_help = 'Issue a new certificate from the CA'
        issue_cert_arg_parser = sub_parsers.add_parser(
                                        self.__class__.ISSUE_CERT_CMD,
                                        help=issue_cert_descr_and_help,
                                        description=issue_cert_descr_and_help)
        
        issue_cert_arg_parser.add_argument("-q", "--cert-req-in", 
                          dest="certreq_filepath", 
                          metavar="FILE",
                          default=self.__class__.DEF_CERTREQ_FILEPATH,
                          help="Input certificate request file - defaults to "
                            "%r" % self.__class__.DEF_CERTREQ_FILEPATH)  
                
        issue_cert_arg_parser.add_argument("-o", "--cert-out", 
                          dest="cert_filepath", 
                          metavar="FILE",
                          default=self.__class__.DEF_CERT_FILEPATH,
                          help="Output certificate file - defaults to %r" % 
                                self.__class__.DEF_CERT_FILEPATH)    
        
        issue_cert_arg_parser.add_argument("-C", "--ca-cert-in", 
                          dest="cacert_in_filepath", 
                          metavar="FILE",
                          default=self.__class__.DEF_CACERT_FILEPATH,
                          help="Input CA Certificate file for issuing a new "
                                " certificate - defaults to %r" % 
                                self.__class__.DEF_CACERT_FILEPATH)
    
        issue_cert_arg_parser.add_argument("-K", "--ca-pri-key-in", 
                          dest="cakey_in_filepath", 
                          metavar="FILE",
                          default=self.__class__.DEF_CAPRIKEY_FILEPATH,
                          help="Input CA private key file for issuing a new "
                                " certificate - defaults %r" % 
                                self.__class__.DEF_CAPRIKEY_FILEPATH)
    
        issue_cert_arg_parser.add_argument("-P", "--ca-pri-key-passphrase-in", 
                          dest="cakey_passphrase", 
                          metavar="PASSPHRASE",
                          default=None,
                          help="Passphrase for CA Private key file - required "
                               "if private key file is password protected. Set "
                               "to '-' to read from standard input")
            
        issue_cert_arg_parser.add_argument("-S", "--subject-alt-names", 
                          dest="subject_alt_names", 
                          metavar="<hostname 1>, ... <hostname n>",
                          default=None,
                          help="Subject alternative names extension.  Set to "
                               "the hostname or hostnames to include.")
                        
        issue_cert_arg_parser.set_defaults(func=self._issue_cert)
        
        # Parses from arguments input to this method if set, otherwise parses 
        # from sys.argv
        parsed_args = parser.parse_args(args)
        if parsed_args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
         
        # Call appropriate command function assigned via set_defaults calls 
        # above   
        parsed_args.func(parsed_args)
    

if __name__=='__main__':
    CertificateAuthorityCLI().main()