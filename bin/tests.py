#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from unittest import TestCase, main
from unittest.mock import patch
from signer import Signer
from subprocess import Popen, PIPE

GRANDCENTRIX_CERTIFICATE = b"""-----BEGIN CERTIFICATE-----
MIIGQjCCBSqgAwIBAgIQDS6s5zqCFF3Xk664mvOWEjANBgkqhkiG9w0BAQsFADBN
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E
aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTcwMzA3MDAwMDAwWhcN
MTkwMzEyMTIwMDAwWjBlMQswCQYDVQQGEwJERTEMMAoGA1UECBMDTlJXMRAwDgYD
VQQHEwdDb2xvZ25lMRswGQYDVQQKExJHcmFuZCBDZW50cml4IEdtYkgxGTAXBgNV
BAMTEGdyYW5kY2VudHJpeC5uZXQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQDbjX0/P7ApD6qDCy0MdlqwfaDlUz+nTddOx9MocPxMKyhO0t6MxCafQ1s+
+uXlEGAdSEmTngVHpXojsI6UrVjS/33vcUJl5ImmyjXrwdzMbjH6pPxEcxAS1iNb
yU+PXuEMN6GX6dPUAcYwBsQ8/2cSK/DlvK0QwYHOPoR3zJIzaqHaTb5vVLujXUrr
HTfi+VB+cYSVqvLQQHOAJsppb4O7OCZYEEt45tFbaVrLixjh/GjZXfAhkGRmmH0L
iis4aexx2VQpLyCFk6ychCadmaIL0RLiHAZzzDuSL9A1j9nt4p09uFjtOmGkEr6h
O3XloEYLO2UNyWmUR9tzO3HzFcF5p4sX71sxs071HNRElx6725JD3WNjSVcAyupC
MJeWKG0UmJZh1/wTvAb3+Vrs/NxYxPm2DkNdiWyYARU86Fok/Qg0W/BN0Ss3dTmO
zxgAexMJC8wxgRj8URiI/13slGN/pfCwWqlkY1C6m9b7MY5TnNpQAXGams8ak8Cc
ojKZmjkS63G5CjfbB5/GD0x2cRx91hicB5yMeWZTuCj7ZrMqs3SsmmwdXuUT/XgW
bZpwNKP8QAuDgBE5JObOxzKOSGEnAQYJaZdqNjzyhaVC1R6q+jvLJ4AClnisZpd1
hxQuuPYPHP6zKOchseYpMuoy1qZbCIK+OCYCSxtpX4jrHTVfGQIDAQABo4ICBDCC
AgAwHwYDVR0jBBgwFoAUD4BhHIIxYdUvKOeNRji0LOHG2eIwHQYDVR0OBBYEFE00
S23blC4IqhAhMBzO7fhc+V2IMEgGA1UdEQRBMD+CEGdyYW5kY2VudHJpeC5uZXSC
FHd3dy5ncmFuZGNlbnRyaXgubmV0ghVibG9nLmdyYW5kY2VudHJpeC5uZXQwDgYD
VR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNV
HR8EZDBiMC+gLaArhilodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEy
LWc1LmNybDAvoC2gK4YpaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NzY2Etc2hh
Mi1nNS5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYc
aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBAgIwfAYIKwYBBQUH
AQEEcDBuMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYI
KwYBBQUHMAKGOmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNI
QTJTZWN1cmVTZXJ2ZXJDQS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsF
AAOCAQEAqDrCtQQBcaaGx6cxdyn0f/3HPMvG1lBU4UylkRF8C5aToQSDak/lWth8
6P2K0g1XJDQkkGw7bCPcIgipHiVaKsOuWI+2yZHC3LT4hJJXcmbBDoE1q8Ft5nS6
HRN47ycQoyCb3KgtD2UfBZnYo2TZujc2q7B4xzD8wj2Fyf2KtXid37qLArI4YA2N
c3aWM0DqzlchHKbKIBNUi7svZDbAmFumo5IZjYcCRGADZkp4YanwWu50vq39ufN5
AC1fWlLMZEHdzvqi7MXWVy7hq8XfLKH5Z1scMSkopBaBWFe5oPPBFhk8RU+P7kBy
goQICN8UXJOOemSg4TyfG5w0LIU3Ow==
-----END CERTIFICATE-----"""

GRANDCENTRIX_HOST = "www.grandcentrix.net"
TEST_CUSTOMER = "test_customer"


class TestSignerGenerateCertificate(TestCase):
    signer = None

    @classmethod
    def setUpClass(cls):
        cls.signer = Signer(TEST_CUSTOMER)
        cls.signer.generate_certificates()

    @classmethod
    def tearDownClass(cls):
        for file in [cls.signer.privatekey_file, cls.signer.publickey_file, cls.signer.publickey_file_pem]:
            if os.path.isfile(file):
                os.unlink(file)

    def test_check_if_privat_key_exists(self):
        # test if file exists
        if not os.path.isfile(self.signer.privatekey_file):
            self.fail("Private Key does not exists")

    def test_check_if_public_key_exists(self):
        if not os.path.isfile(self.signer.publickey_file):
            self.fail("DER encoding of Public Key does not exists")

    def test_check_if_public_key_in_PEM_format_exists(self):
        if not os.path.isfile(self.signer.publickey_file_pem):
            self.fail("PEM encoding of Public Key does not exists")

    # TODO validate, that the content of the Cert is correct


class TestSignerLoadCertificate(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = Signer(TEST_CUSTOMER)

    def test_correct_certificate(self):
        with patch('ssl.get_server_certificate', return_value=GRANDCENTRIX_CERTIFICATE):
            x509 = self.signer.load_certificate_from_host(GRANDCENTRIX_HOST)

        self.assertListEqual(x509.get_subject().get_components(),
                             [(b'C', b'DE'), (b'ST', b'NRW'), (b'L', b'Cologne'),
                              (b'O', b'Grand Centrix GmbH'), (b'CN', b'grandcentrix.net')],
                             "Subject is not correct")

    def test_generate_json_without_domains_file(self):
        with patch('ssl.get_server_certificate', return_value=GRANDCENTRIX_CERTIFICATE):
            with self.assertRaises(Exception) as context:
                self.signer.load_certificates()

            self.assertIsInstance(context.exception, FileNotFoundError, "JSON not exists does not raise FileNotFound")

    def test_generate_json(self):
        df = open(self.signer.domain_file, 'w')
        df.write(GRANDCENTRIX_HOST+":443")
        df.close()

        def cleanup():
            if os.path.isfile(self.signer.domain_file):
                os.unlink(self.signer.domain_file)

        self.addCleanup(cleanup)

        with patch('ssl.get_server_certificate', return_value=GRANDCENTRIX_CERTIFICATE):
            json = self.signer.load_certificates()

        self.assertListEqual(json, [{
            'hostname': 'www.grandcentrix.net',
            'port': '443',
            'fp': ['a51c532d960cbbf63fdbfb3bf3e4b2816e2b902914a20a87541fdab72f7ae081'],
            'pk': ['MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2419Pz+wKQ+qgwstDHZasH2g5VM/p03XTsfTKHD8TCso' +
                   'TtLejMQmn0NbPvrl5RBgHUhJk54FR6V6I7COlK1Y0v9973FCZeSJpso168HczG4x+qT8RHMQEtYjW8lPj17hDDeh' +
                   'l+nT1AHGMAbEPP9nEivw5bytEMGBzj6Ed8ySM2qh2k2+b1S7o11K6x034vlQfnGElary0EBzgCbKaW+DuzgmWBBL' +
                   'eObRW2lay4sY4fxo2V3wIZBkZph9C4orOGnscdlUKS8ghZOsnIQmnZmiC9ES4hwGc8w7ki/QNY/Z7eKdPbhY7Tph' +
                   'pBK+oTt15aBGCztlDclplEfbcztx8xXBeaeLF+9bMbNO9RzURJceu9uSQ91jY0lXAMrqQjCXlihtFJiWYdf8E7wG' +
                   '9/la7PzcWMT5tg5DXYlsmAEVPOhaJP0INFvwTdErN3U5js8YAHsTCQvMMYEY/FEYiP9d7JRjf6XwsFqpZGNQupvW' +
                   '+zGOU5zaUAFxmprPGpPAnKIymZo5EutxuQo32wefxg9MdnEcfdYYnAecjHlmU7go+2azKrN0rJpsHV7lE/14Fm2a' +
                   'cDSj/EALg4AROSTmzscyjkhhJwEGCWmXajY88oWlQtUeqvo7yyeAApZ4rGaXdYcULrj2Dxz+syjnIbHmKTLqMtam' +
                   'WwiCvjgmAksbaV+I6x01XxkCAwEAAQ==']}])


class TestSignerSignHashes(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = Signer(TEST_CUSTOMER)

    def test_correct_certificate(self):
        with patch('ssl.get_server_certificate', return_value=GRANDCENTRIX_CERTIFICATE):
            self.signer.sign_hashes([{'hostname': "www.grandcentrix.net"}], False)

        p = Popen(['openssl', 'smime', '-verify',
                   '-in', self.signer.signed_json_file,
                   '-inform', 'der',
                   '-CAfile', self.signer.publickey_file_pem], stdout=PIPE, stderr=PIPE)
        p.wait()
        p.stdout.close()
        p.stderr.close()

        self.assertEqual(p.returncode, 0, "File wrongly signed")

    # TODO: write test to check content
    # TODO: Write Test to check failed workflow


if __name__ == '__main__':
    main()
