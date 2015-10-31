Project moved to SourceForge
----------------------------

Project moved to https://sourceforge.net/p/python-dnssec/


python-dnssec
=============

python-dnssec is a set of scripts and modules from the original
[DNSSEC-Tools](http://www.dnssec-tools.org/) project rewritten in python.


Requirements
============

* Python >= 3.4 (the whole project requires Python 3.0+,
but the unix socket implementation requires Python 3.4+)
* dnspython3 >= 1.12.0


Difference between DNSSEC-Tools
===============================

Configuration parsers
---------------------

There is a few configuration parsers written from scratch
which can open, parse and save configuration files used by DNSSEC-Tools.

* dnssec.parsers.rollrec.RollRec is a .rollrec files parser
* dnssec.parsers.keyrec.KeyRec is a .krf files parser


pyrollerd
---------

pyrollerd is a rollerd daemon rewriten in python.

* Script was named "rollerd" for compatibility with the original rollctl.
* Conflicts with the original daemon, avoid running them both at the same time.
* rollctl management interface is not implemented yet.
* Automatic keyset transfer in KSK phase 4 (using gandi.net API).
* The only available eventmaster type is EVT_FULLLIST.
* Event queues is not implemented.


pyrollctl
---------

pyrollctl is a rollctl tool rewriten in python.

* It should be 90% compatible with the original rollctl.
* It can communicate with both pyrollerd and original rollerd.
* Unstable and was developed for debugging purposes only.
