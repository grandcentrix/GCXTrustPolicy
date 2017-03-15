#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ssl
import socket
import sys
import json
import time
import getopt
import base64
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
# lib, load_privatekey, _new_mem_buf, _ffi, _bio_to_string, FILETYPE_ASN1
from cryptography.hazmat.primitives import serialization
from subprocess import Popen, PIPE

OUTPUT_FOLDER = "output"
DATA_FOLDER = "data"
CERTIFICATE_FOLDER = "certs"


class Signer:
    def __init__(self, customer):
        self.customer = customer
        # public files
        self.publickey_file_pem = '%s/%s.pem' % (OUTPUT_FOLDER, customer)
        self.publickey_file = '%s/%s.crt' % (OUTPUT_FOLDER, customer)
        self.signed_json_file = '%s/%s.json.signed' % (OUTPUT_FOLDER, customer)
        # private files
        self.privatekey_file = '%s/%s.key' % (CERTIFICATE_FOLDER, customer)
        self.config_file = '%s/%s.config' % (CERTIFICATE_FOLDER, customer)
        # input files
        self.domain_file = '%s/%s.domains' % (DATA_FOLDER, customer)
        self.json_file = '%s/%s.json' % (DATA_FOLDER, customer)

    @staticmethod
    def load_certificate_from_host(host, port=443):
        cert = ssl.get_server_certificate((host, port))
        x509 = load_certificate(FILETYPE_PEM, cert)

        return x509

    def load_certificates(self):
        """Downloads certificates from servers"""

        hashes = []

        df = open(self.domain_file, 'r')

        eprint("* Loading certificates for customer %s" % self.customer)

        for line in df.read().split("\n"):
            if line == "":
                continue
            (hostname, hostport) = line.split(":")

            eprint("** loading SSL certificate from %s:%s" % (hostname, hostport))

            host_hash = {}
            try:
                certificate = self.load_certificate_from_host(hostname, hostport)
                fingerprint = certificate.digest('sha256').decode('utf8').lower().replace(':', '')
                publickey = certificate.get_pubkey().to_cryptography_key()
                pk_bytes = publickey.public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)

                host_hash['hostname'] = hostname
                host_hash['port'] = hostport
                host_hash['fp'] = [fingerprint]
                host_hash['pk'] = [base64.b64encode(pk_bytes).decode('utf8')]

                hashes.append(host_hash)
            except socket.gaierror:
                eprint("Host not found: %s:%s" % (hostname, hostport))

        df.close()

        return hashes

    def sign_hashes(self, hashes, test_timestamp):
        """signes the hashes with the per customer public key"""

        payload = {'customer': self.customer, 'hashes': hashes}

        if test_timestamp:
            payload['timestamp'] = int(time.time()) + 60*60*24*365*20  # now + 20 jears
        else:
            payload['timestamp'] = int(time.time())

        json_string = json.dumps(payload)

        # generate certificate if it is not available
        if not os.path.isfile(self.privatekey_file):
            self.generate_certificates()

        eprint("* Sign JSON for customer %s" % self.customer)
        # sign json with openssl
        with Popen(['openssl', 'smime', '-sign', '-nodetach',
                    '-signer', self.publickey_file_pem,
                    '-inkey', self.privatekey_file,
                    '-outform', 'der',
                    '-out', self.signed_json_file], stdout=PIPE, stderr=PIPE, stdin=PIPE) as p:
            p.stdin.write(json_string.encode('utf8'))
            p.stdin.close()
            p.stdout.close()
            p.stderr.close()

        p = Popen(['openssl', 'smime', '-verify',
                   '-in', self.signed_json_file,
                   '-inform', 'der',
                   '-CAfile', self.publickey_file_pem], stdout=PIPE, stderr=PIPE)
        p.wait()

        ret = p.returncode

        if ret == 0:
            eprint("** signed file here: %s" % self.signed_json_file)
        else:
            os.unlink(self.signed_json_file)

        return p.returncode

    def generate_certificates(self):
        """generate new customer certificate"""
        eprint("* Generate new certificate for customer %s" % self.customer)

        # generate certificate folder
        if not os.path.isdir(CERTIFICATE_FOLDER):
            os.mkdir(CERTIFICATE_FOLDER, 0o700)

        openssl_config = """# OpenSSL configuration
    #
    # openssl req -config bla.cnf -new -out csr.pem
    [ req ]
    default_bits       = 4096
    default_md         = sha512
    prompt             = no
    encrypt_key        = no

    # base request
    distinguished_name = req_distinguished_name

    # distinguished_name
    [ req_distinguished_name ]
    countryName            = "DE"
    stateOrProvinceName    = "NRW"
    localityName           = "Cologne"
    organizationName       = "grandcentrix"
    commonName             = "%s"

    # vim:ft=config""" % self.customer

        df = open(self.config_file, 'w')

        df.write(openssl_config)
        df.close()

        p = Popen(['openssl', 'genrsa', '-out', self.privatekey_file, '4096'], stdout=PIPE, stderr=PIPE, stdin=PIPE)
        p.wait()
        p.stdin.close()
        p.stdout.close()
        p.stderr.close()

        # this generates certificate wich is valid for 20 years from now
        p = Popen(['openssl', 'req',
                   '-config', self.config_file,
                   '-new', '-x509', '-days', '7300',
                   '-key', self.privatekey_file,
                   '-out', self.publickey_file,
                   '-outform', 'der'], stdout=PIPE, stderr=PIPE, stdin=PIPE)
        p.wait()
        p.stdin.close()
        p.stdout.close()
        p.stderr.close()

        # convert to PEM
        p = Popen(['openssl', 'x509',
                   '-in', self.publickey_file,
                   '-inform', 'der',
                   '-out', self.publickey_file_pem],
                  stdout=PIPE, stderr=PIPE, stdin=PIPE)
        p.wait()
        p.stdin.close()
        p.stdout.close()
        p.stderr.close()

        os.unlink(self.config_file)

        eprint("** new certificate located here: %s" % self.publickey_file)
        eprint("*** PLEASE BACKUP THIS, SINCE IT IS THE NOW VALID TRUST ANCHOR ***")

        eprint("** Base64 of public key:")
        df = open(self.publickey_file, 'rb')
        eprint(base64.b64encode(df.read()).decode('utf8'))
        df.close()


def usage():
    print('%s [-f|--force_update] [-c|--customer <customer>] <customer> [<customer>]' % __file__)


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def main(argv):
    force_update = False
    test_timestamp = False

    try:
        opts, args = getopt.getopt(argv, "hfc:t", ["force_update", 'customer=', 'test_timestamp'])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    # set customers to all arguments
    customers = args

    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt in ("-f", "--force_update"):
            force_update = True
        elif opt in ("-c", "--customer"):
            customers.append(arg)
        elif opt in ("-t", "--test_timestamp"):
            test_timestamp = True

    if len(customers) == 0:
        usage()
        sys.exit(3)

    if not os.path.isdir(OUTPUT_FOLDER):
        os.mkdir(OUTPUT_FOLDER, 0o766)

    for customer in customers:
        signer = Signer(customer)

        if not os.path.isfile(signer.domain_file):
            eprint('Customer "%s" not found. Please create %s.' % (customer, signer.domain_file))
            continue

        if force_update or not os.path.isfile(signer.json_file):
            certificates = signer.load_certificates()
            json.dump(certificates, open(signer.json_file, 'w'))
        else:
            certificates = json.load(open(signer.json_file, 'r'))

        signer.sign_hashes(certificates, test_timestamp)


if __name__ == "__main__":
    main(sys.argv[1:])
