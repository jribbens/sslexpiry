#!/usr/bin/env python3

"""Check expiry dates on SSL certificates."""

import argparse
import datetime
import os
import re
import signal
import socket
import subprocess
import sys


CERTS_FILE = "/etc/ssl/certs/ca-certificates.crt"

_RE_ENDCERT = re.compile(r"^-+END CERTIFICATE-+\s*$", re.MULTILINE)
_RE_BADISSUERS = re.compile(
    r"symantec|thawte|rapidssl|geotrust", re.IGNORECASE)
_RE_ISSUER_CN = re.compile(r"^\s+Issuer:\s+CN=([^,]+)", re.MULTILINE)
_RE_STATUS = re.compile(r"^- Status: (.*)", re.MULTILINE)
_RE_EXPIRY = re.compile(
    r"^\s+Not After: ([a-z]{3} [a-z]{3} \d{2}"
    r" \d{2}:\d{2}:\d{2} UTC \d{4})\s*$",
    re.MULTILINE | re.IGNORECASE)
_RE_STARTDATE = re.compile(
    r"^\s+Not Before: ([a-z]{3} [a-z]{3} \d{2}"
    r" \d{2}:\d{2}:\d{2} UTC \d{4})\s*$",
    re.MULTILINE | re.IGNORECASE)
_RE_SIGNATURE = re.compile(r"^\s+Signature Algorithm: (.*)", re.MULTILINE)
_RE_RECEIVED = re.compile(r"^- Received\[(\d+)\]: ")
_RE_SENT = re.compile(r"^- Sent: (\d+) bytes$")


class StartTLSError(Exception):
    """Exception to indicate error occurred during STARTTLS handling."""
    pass


def alarm_handler(signum, frame):
    """Handle SIGALRM."""
    # pylint: disable=unused-argument
    raise StartTLSError("Timeout during STARTTLS processing")


def starttls_readline(gnutls, verbose):
    """Read a line of data from the gnutls process."""
    while True:
        data = gnutls.stdout.readline()
        if not data:
            raise StartTLSError("Unexpected EOF from gnutls-cli")
        match = _RE_SENT.match(data)
        if not match:
            break
    match = _RE_RECEIVED.match(data)
    if match:
        data = data[match.end():]
    if verbose >= 3:
        print("Read: {!r}".format(data))
    return data


def starttls_write(gnutls, data, verbose):
    """Write some data to the gnutls process."""
    if verbose >= 3:
        print("Writing: {!r}".format(data))
    gnutls.stdin.write(data)
    gnutls.stdin.flush()


def do_starttls(gnutls, protocol, verbose):
    """Do STARTTLS processing using the given process."""
    # pylint: disable=too-many-branches,too-many-statements
    while True:
        line = gnutls.stdout.readline()
        if not line:
            return
        if verbose >= 3:
            print("Read: {!r}".format(line))
        if line == "- Simple Client Mode:\n":
            gnutls.stdout.readline()
            break
    if protocol == "smtp":
        data = starttls_readline(gnutls, verbose)
        if not data.startswith("220 "):
            raise StartTLSError(
                "Unexpected SMTP greeting: {!r}".format(data))
        starttls_write(gnutls, "EHLO mail.example.com\n", verbose)
        data = starttls_readline(gnutls, verbose)
        found = False
        if not data.startswith("250-"):
            raise StartTLSError(
                "Unexpected EHLO response: {!r}".format(data))
        while data.startswith("250-"):
            if "STARTTLS" in data:
                found = True
            data = starttls_readline(gnutls, verbose)
        if not data.startswith("250 "):
            raise StartTLSError(
                "Unexpected EHLO response: {!r}".format(data))
        if "STARTTLS" in data:
            found = True
        if not found:
            raise StartTLSError("SMTP server does not support STARTTLS")
        starttls_write(gnutls, "STARTTLS\n", verbose)
        data = starttls_readline(gnutls, verbose)
        if not data.startswith("220 "):
            raise StartTLSError(
                "Unexpected STARTTLS response: {!r}".format(data))
    elif protocol == "imap":
        data = starttls_readline(gnutls, verbose)
        if not data.startswith("* OK"):
            raise StartTLSError(
                "Unexpected IMAP greeting: {!r}".format(data))
        starttls_write(gnutls, "a CAPABILITY\r\n", verbose)
        data = starttls_readline(gnutls, verbose)
        if not data.startswith("* CAPABILITY"):
            raise StartTLSError(
                "Unexpected IMAP CAPABILITY response: {!r}".format(data))
        if "STARTTLS" not in data:
            raise StartTLSError("IMAP server does not support STARTTLS")
        data = starttls_readline(gnutls, verbose)
        if not data.startswith("a OK"):
            raise StartTLSError(
                "Unexpected IMAP CAPABILITY response: {!r}".format(data))
        starttls_write(gnutls, "a STARTTLS\r\n", verbose)
        data = starttls_readline(gnutls, verbose)
        if not data.startswith("a OK"):
            raise StartTLSError(
                "Unexpected IMAP STARTTLS response: {!r}".format(data))
    else:
        raise StartTLSError("Unknown STARTTLS protocol {!r}".format(protocol))


def check_server(server, certs_file, days, timeout, verbose):
    """Check the specified server.
    Returns an error string, or the expiry date of the certificate."""
    # pylint: disable=too-many-branches,too-many-return-statements
    # pylint: disable=too-many-statements,too-many-locals
    if verbose >= 2:
        print(server + ":")
    expiryonly = False
    if server.startswith("!"):
        server = server[1:]
        expiryonly = True
    starttls = None
    if "/" in server:
        server, starttls = server.split("/", 1)
    port = "443"
    if ":" in server:
        server, port = server.split(":", 1)
    if not port.isdigit():
        try:
            port = str(socket.getservbyname(port, "tcp"))
        except OSError:
            return "Unknown port {!r}".format(port)
    if starttls is None:
        starttls = {25: "smtp", 143: "imap", 587: "smtp"}.get(int(port))
    if starttls in ("none", "http", "https"):
        starttls = None
    args = [
        "gnutls-cli",
        "-V",
        "--x509cafile",
        certs_file,
        "-p",
        port,
        server
    ]
    if starttls:
        args.insert(-1, "--starttls")
    try:
        if verbose >= 3:
            print("exec:", args)
        gnutls = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, encoding="iso-8859-1")
        if starttls:
            prevalarm = signal.signal(signal.SIGALRM, alarm_handler)
            try:
                signal.alarm(timeout)
                do_starttls(gnutls, starttls, verbose)
            finally:
                signal.alarm(0)
                prevalarm = signal.signal(signal.SIGALRM, prevalarm)
        # pylint: disable=unexpected-keyword-arg
        out, err = gnutls.communicate(timeout=timeout)
        # pylint: enable=unexpected-keyword-arg
    except StartTLSError as exc:
        gnutls.kill()
        gnutls.communicate()
        return str(exc)
    except subprocess.TimeoutExpired:
        gnutls.kill()
        gnutls.communicate()
        return "Timed out"
    if verbose >= 2 and out:
        print("\nSTDOUT:\n", out)
    if verbose >= 2 and err:
        print("\nSTDERR:\n", err)
    match = _RE_STATUS.search(out)
    if match:
        if match.group(1).strip() != "The certificate is trusted.":
            return match.group(1)
    else:
        return err.strip().split("\n")[-1] or "Couldn't understand output"
    match = _RE_ENDCERT.search(out)
    if not match:
        return err.strip().split("\n")[-1] or "Couldn't understand output"
    certinfo = out[:match.end()]
    match = _RE_EXPIRY.search(certinfo)
    if not match:
        return "Unable to determine expiry date"
    expiry = datetime.datetime.strptime(
        match.group(1), "%a %b %d %H:%M:%S UTC %Y")
    match = _RE_SIGNATURE.search(certinfo)
    if not match:
        return "Unable to determine signature algorithm"
    signature = match.group(1)
    if verbose >= 2:
        print("Signature: {}".format(signature))
    now = datetime.datetime.now()
    if expiry <= now:
        return "Certificate expired on {}!".format(
            expiry.strftime("%d %b %Y"))
    remaining = expiry - now
    if remaining.days <= days:
        return "Expiry date is {} - {} day{}".format(
            expiry.strftime("%d %b %Y"), remaining.days,
            "" if remaining.days == 1 else "s")
    if expiryonly:
        return expiry
    if "MD5" in signature or "SHA1" in signature:
        return "Signature algorithm is bad: {}".format(signature)
    match = _RE_STARTDATE.search(certinfo)
    if not match:
        return "Unable to determine start date"
    startdate = datetime.datetime.strptime(
        match.group(1), "%a %b %d %H:%M:%S UTC %Y")
    lifetime = (expiry - startdate).days
    if verbose >= 2:
        print("Start date: {}".format(startdate.strftime("%d %b %Y")))
        print("Lifetime: {} days".format(lifetime))
    if startdate >= datetime.datetime(2018, 3, 1) and lifetime > 825:
        return "Certificate lifetime of {} days is too long".format(lifetime)
    match = _RE_ISSUER_CN.search(certinfo)
    if not match:
        return "Unable to determine certificate issuer"
    issuer_cn = match.group(1)
    if verbose >= 2:
        print("Issuer: {}".format(issuer_cn))
    if _RE_BADISSUERS.search(issuer_cn):
        if verbose >= 2:
            print("Distrusted issuer")
        if startdate < datetime.datetime(2016, 6, 1):
            distrustdate = datetime.datetime(2018, 3, 15)
        else:
            distrustdate = datetime.datetime(2018, 9, 13)
        remaining = distrustdate - now
        if remaining.days <= days:
            return "Chrome will distrust on {} - {} day{}".format(
                distrustdate.strftime("%d %b %Y"), remaining.days,
                "" if remaining.days == 1 else "s")
    return expiry


def main():
    """Parse command-line arguments and check appropriately."""
    # pylint: disable=too-many-branches
    parser = argparse.ArgumentParser(description="SSL expiry checker")
    parser.add_argument(
        "-c", "--certs-file", metavar="FILENAME",
        default=CERTS_FILE,
        help="The certificates file to use for verification"
        " (default={})".format(CERTS_FILE))
    parser.add_argument(
        "-d", "--days", metavar="DAYS", type=int, default=30,
        help="The number of days at which to warn of expiry"
        " (default=30)")
    parser.add_argument(
        "-t", "--timeout", metavar="SECONDS", type=int,
        default=30,
        help="The number of seconds to allow for server response"
        " (default=30)")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Display verbose output.")
    parser.add_argument(
        "-f", "--from-file", metavar="FILENAME",
        type=argparse.FileType("r", encoding="utf-8"), action="append",
        help="Read the servers to check from the specified file.")
    parser.add_argument(
        "servers", nargs="*", metavar="SERVER", default=(),
        help="Check the specified server.")
    args = parser.parse_args()
    results = []
    if args.from_file:
        for stream in args.from_file:
            for line in stream:
                if "#" in line:
                    line = line.split("#", 1)[0]
                line = line.strip()
                if line:
                    results.append((
                        line,
                        check_server(line, args.certs_file, args.days,
                                     args.timeout, args.verbose)
                    ))
    if args.servers:
        for server in args.servers:
            results.append((
                server,
                check_server(server, args.certs_file, args.days, args.timeout,
                             args.verbose)
            ))
    exitcode = os.EX_OK
    if not results:
        sys.exit(exitcode)
    longest = max(len(server) for server, result in results)
    expiries = []
    for server, result in results:
        if isinstance(result, datetime.datetime):
            expiries.append((result, server))
        else:
            print("{}{} {}".format(
                server, " " * (longest - len(server)), result))
            exitcode = os.EX_IOERR
    if args.verbose >= 1:
        expiries.sort()
        for result, server in expiries:
            if isinstance(result, datetime.datetime):
                if args.verbose >= 1:
                    print("{}{} {}".format(
                        server,
                        " " * (longest - len(server)),
                        result.strftime("%d %b %Y")))
    sys.exit(exitcode)


if __name__ == "__main__":
    main()
