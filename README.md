python-dnssec
=============

python-dnssec is a set of scripts and modules from the original
[DNSSEC-Tools](http://www.dnssec-tools.org/) project rewritten in python.


Development status
==================

This project is in active development.
Many of the core features is not implemented at this moment.


Requirements
============

* Python >= 3.4 (the whole project requires Python 3.0+,
but the unix socket implementation requires Python 3.4+)
* dnspython3 >= 1.12.0


Difference between DNSSEC-Tools
===============================

* Auto-detection of the default settings has been simplified.
So it's better to use a distribution provided DNSSEC-Tools configuration
and don't rely on the undefined variables.


Configuration parsers
---------------------

There is a few configuration parsers already implemented
which can open, parse and save configuration files used by DNSSEC-Tools.

* dnssec.parsers.rollrec.RollRec is *.rollrec files parser
* dnssec.parsers.keyrec.KeyRec is *.krf files parser


pyrollctl
---------

pyrollctl is a rollctl tool rewriten in python.

* It should be 90% compatible with the original rollctl.
* It can communicate with both pyrollerd and original rollerd.
* Unstable and was developed for debugging purposes only.


pyrollerd
---------

pyrollerd is a rollerd daemon rewriten in python.
Only 10% of original rollerd features has been implemented at this moment:

* Script was named "rollerd" for compatibility with the original rollctl.
* Conflicts with the original daemon, avoid running them both at the same time.
* Command line options
* Daemonization and rollctl management interface (only "status" command is implemented atm)
* Initial zone signing
* KSK Phase 1-7
* Automatic keyset transfer in KSK phase 4 (using gandi.net API)
