Certificate Pinning Tool
========================

This tool will download the current SSL Certificates from the URLs you specify for a given Customer, stores them in an JSON file and Signes them with a per Customer RSA Key.

This script should run every five minutes, because it sets a timestamp to show the singed file is fresh.


Install
-------

- apt-get install python3 python3-openssl 

Starting
--------

- create file "data/`customer`.domains"
- run "./signer.py `customer`"
