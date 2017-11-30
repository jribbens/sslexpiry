Python 3 script to keep an eye on the expiry dates of your SSL certificates
===========================================================================

This script connects to a given set of servers, fetches and verifies their
SSL certificates, and checks the expiry dates and signature algorithms
thereof. It will warn you if:

  * the connection does not succeed,
  * the SSL negotiation does not succeed,
  * the SSL certificate does not verify,
  * the SSL certificate does not match the server hostname,
  * the server does not support SSL,
  * the certificate uses MD5,
  * the certificate uses SHA1 and its expiry is in 2016 or later,
  * the certificate has expired,
  * or the certificate will expire soon.

The intended use is that you will put the list of your servers using
SSL in a text file, and run `sslexpiry.py` on a daily cron job to warn
you if your certificates will expire soon.

(Chrome browser complains about SHA1 with certificate expiry dates
of 2016 and later, hence this check.)


Requirements
------------

The script relies upon Python 3 (it has been tested under Python 3.4 and 3.6),
and `gnutls-cli` (it has been tested with 3.2.16 and 3.5.8). You can install
these on Ubuntu 14.04 and later with:

    sudo apt-get install python3 gnutls-bin


Usage
-----

    usage: sslexpiry.py [-h] [-c FILENAME] [-d DAYS] [-t SECONDS] [-v]
                        [-f FILENAME]
                        [SERVER [SERVER ...]]

    positional arguments:
      SERVER                Check the specified server.

    optional arguments:
      -h, --help            show this help message and exit
      -c FILENAME, --certs-file FILENAME
                            The certificates file to use for verification
                            (default=/etc/ssl/certs/ca-certificates.crt)
      -d DAYS, --days DAYS  The number of days at which to warn of expiry
                            (default=30)
      -t SECONDS, --timeout SECONDS
                            The number of seconds to allow for server response
                            (default=30)
      -v, --verbose         Display verbose output.
      -f FILENAME, --from-file FILENAME
                            Read the servers to check from the specified file.

Files containing lists of servers can contain blank lines, and any
characters from a '#' onwards are ignored as comments.

Servers specified in the files or on the command line are of the form:

    [!]hostname[:port][/protocol]

`port` can be a number or a standard service name (e.g. 'https'). If it
is omitted then 'https' is assumed. If the hostname is prefixed with
`!` then only that server's certificate's imminent expiry will cause
a problem to be reported, not weak signature algorithms.

`protocol` specifies a protocol that should be followed before the SSL
negotiation begins. Valid values include `smtp`, `imap` or `none`. If
it is omitted then `none` is assumed, except for ports `smtp` or
`submission`, where `smtp` is assumed, and `imap`, where `imap` is
assumed.

The `-v` option can be specified multiple times. If it is not specified
at all, then there will be no output unless a problem is found. If it
is specified once, then output will be shown with any problems found
first, then all tested servers listed with soonest expiry date first.
If it is specified more than once then an annoyingly large amount of
detailed debug output will be produced.

The process exit code will be zero if no problems were found, and
non-zero otherwise.


Example server list file
------------------------

    # This is an example server list file

    www.example.com
    example.com
    mail.example.com:smtp
    othermail.example.com:2525/smtp # this server listens for smtp on port 2525


Example output
--------------

    $ ./sslexpiry.py -vf example.conf
    www.example.com                 Expiry date is 30 Jan 2016 and signature algorithm is RSA-SHA1
    example.com                     The certificate is NOT trusted. The name in the certificate does not match the expected.
    othermail.example.com:2525/smtp 03 Jul 2015
    mail.example.com:smtp           10 Oct 2015


Notes
-----

The `smtp` or `imap` protocol negotiation is implemented in the script,
because the version of `gnutls-cli` available on Ubuntu 14.04 does not provide
the `starttls-proto` option that has been added in later versions. Similarly,
the `gnutls-cli` program is used rather than the more common `openssl`
program, because the version available on Ubuntu 14.04 does not support the
`verify_hostname` option.
