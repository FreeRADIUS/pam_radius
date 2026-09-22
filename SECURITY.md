# Security Policy

All security vulnerabilities should be reported to <security@freeradius.org>

All security disclosures are published on the FreeRADIUS web site, at <https://www.freeradius.org/security/>

### Git "master" branch.

We accept security reports for the "master" branch.

The "master" branch may have temporary issues as development
continues.  The "master" branch may even have compile failures from
time to time.

## Reporting a Vulnerability

All security vulnerabilities should be reported to <security@freeradius.org>

### Use of AI

Security reports must also follow the [policy on AI agents](AGENTS.md).  We are
happy to accept reports where people have used AI, _provided_ that the
results have been verified by a person.  Simply forwarding AI results
to us will likely just get you banned.

You must take personal responsibility for the content and correction
of any security reports which were generated using AI tools.

### CVEs

We do not issue CVEs for the git `master` branch.  The code is in
development, and is not part of any official release.

Given the rise of AI analysis tools, we are also putting a hold on
issuing CVEs for older releases.  If anyone can download
the source and "find a bug" by using $0.02 of AI tokens, then the
landscape has changed.  There is no reason to give credit to the
"discoverer", when the discoverer is an AI tool and not a person.
There is no reason to have an embargo period when anyone else with a
keyboard and credit card can make the same discovery with 5 minutes of
effort.

### PGP Key

The following PGP key can be used to sign messages which are sent to
security@freeradius.org.  The key is also available on PGP key servers
(for aland@freeradius.org), and on the FreeRADIUS web site at
https://www.freeradius.org/pgp/aland@freeradius.org

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.0.6 (GNU/Linux)
Comment: For info see http://www.gnupg.org

mQCNAzx7wFMAAAEEALq2yahNGENq7Z8xqIaaxlMYPEqdnWme+QQRobX+0mHJ+xjv
uU9icVaQJrgrcgmH9Sx5avAZViypk/bBSwxUxbUZfF9LRsEPJB2Rpg2eLuxShYiE
x0CMCAIQvDFCmygm4+dqgkj1/BCImki8nvQIoW56uTTkskZuq6kul4vkAkl9AAUR
tCRBbGFuIFQuIERlS29rIDxhbGFuZEBmcmVlcmFkaXVzLm9yZz6JAJUDBRA8e8BT
qS6Xi+QCSX0BAXvOA/wPxVKQXtyfQSFi8WrPa0QUaRzm8j9Kna9u9Xn2wzF18neH
ogxzDIdJZtB2zDRKaRbNeYrcz0LnC5sxZqMco0NkI7P2ifE42aWXauSuYaYA9uG6
kP+CFjprorK0Cc6NUL47nWxB5x5zkix85MUjkMbOFyrZrUKKcHAeWfjzMf0Vkg==
=VwDM
-----END PGP PUBLIC KEY BLOCK-----
```
