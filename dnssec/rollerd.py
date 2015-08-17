# Copyright (C) 2015 Okami, okami@fuzetsu.info

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

import datetime
import os
import pwd
import re
import shlex
import signal
import subprocess
import sys
import time

from .cmd import CmdMixin
from .common import CommonMixin
from .daemon import DaemonMixin
from .defs import *
from .keyrec import KSKMixin
from .rolllog import *
from .rollmgr import *
from .rollrec import RollRecMixin


class RollerD(
        CmdMixin,
        CommonMixin,
        DaemonMixin,
        KSKMixin,
        RollLogMixin,
        RollMgrMixin,
        RollRecMixin):

    NAME = 'pyrollerd'
    VERS = '%s version: 0.0.1' % NAME
    DTVERS = 'DNSSEC-Tools Version: N/A'

    # Some path variables to be set from the config file.
    dtconfig = ''  # DNSSEC-Tools configuration file.
    rndc = ''  # BIND name server control program.
    rrchk = ''  # Rollrec file checking program.
    zonesigner = ''  # Zone-signing program.
    rndcopts = ''  # Options for rndc.

    krollmethod = RM_ENDROLL  # Rollover calculation to use for KSKs.
    zrollmethod = RM_ENDROLL  # Rollover calculation to use for ZSKs.

    # Data required for command line options.
    rollrecfile = ''  # Rollrec file to be managed.
    dtconf = {}  # DNSSEC-Tools config file.

    opts = {
        'rrfile': '',  # Rollrec file.
        'directory': '',  # Execution directory.
        'display': False,  # Use output GUI.
        'logfile': '',  # Log file.
        'loglevel': '',  # Logging level.
        'logtz': '',  # Logging timezone.
        'noreload': False,  # Don't reload zone files.
        'pidfile': '',  # pid storage file.
        'dtconfig': '',  # dnssec-tools config file to use.
        'sleep': 0,  # Sleep amount (in seconds.)
        'parameters': False,  # Display the parameters and exit.
        'autosign': False,  # Autosign flag.
        'singlerun': False,  # Single run:  process everything once.
        'foreground': False,  # Run in the foreground; don't fork.
        'alwayssign': False,  # Always sign when running in singlerun.
        'username': '',  # User name for which to run as.
        'realm': '',  # Realm we're running in.
        'help': False,  # Give a usage message and exit.
        'verbose': False,  # Verbose output.
        'Version': False,  # Display the version number.
        'zonesigner': '',  # Location of zonesigner executable.
        'zsargs': '',  # Arguments for zonesigner.
    }

    # Flag values for the various options.  Variable/option connection should
    # be obvious.
    alwayssign = False  # Always sign the zone in -singlerun.
    autosign = False  # Autosign updated zones.
    dtcf = ''  # DNSSEC-Tools configuration file.
    foreground = False  # Run in the foreground.
    logfile = ''  # Log file.
    loglevel = ''  # Logging level.
    loglevel_save = ''  # Saved logging level.
    logtz = ''  # Logging timezone.
    zoneload = True  # Zone-reload flag.
    pidfile = ''  # Pid storage file.
    realm = ''  # Our realm.
    singlerun = False  # Single run only.
    sleep_override = False  # Sleep-override flag.
    sleepcnt = 0  # Time we've slept so far.
    sleeptime = 0  # Sleep interval in seconds.
    username = ''  # User name we'll change to.
    gzsargs = ''  # Global zsargs for zonesigner.
    verbose = False  # Verbose option.

    display = False  # Do display processing.

    boottime = datetime.datetime.now()  # Timestamp of rollerd's start time.

    keyarch = ''  # Key-archive program.
    packed = False  # Flag indicating if running packed.
    xqtdir = ''  # Execution directory.

    # "full list" queue processing is the classic rollerd method of handling its
    # queue.  Every N seconds, the entire queue of zones is scanned to see if any
    # rollover events must be handled.
    #
    # "soon" queue processing is experimental.  It maintains a sub-queue of the
    # rollover events that must be handled soon.  Rather than processing the full
    # queue of managed zones every N seconds, the "soon queue" is handled as the
    # events occur.
    #
    # "soon" processing is still being tested and should *not* be considered
    # reliable!  (yet...)
    eventmaster = EVT_FULLLIST
    event_methods = (
        'dummy',
        'Full List',
        'Soon Queue',
    )

    queue_eventtimes = []
    queue_maxttls = []
    queue_signtimes = []
    queue_allzones = []
    queue_sooners = []

    queue_firstsoon = 0  # Index of first unprocessed soon entry.
    queue_lastscan = 0  # GMT of last full scan.
    queue_scantime = 0  # Time taken for last full scan.
    queue_scanskips = 0  # Count of zones skipped in scan.
    queue_soonend = 0  # End of current "soon" period.

    queued_int = False  # Queued-SIGINT flag.
    queued_hup = False  # Queued-SIGHUP flag.

    wassigned = False  # Flag indicating zone was signed.

    ret = 0  # Return code from main().
    runerr = 0  # Execution error -- used in runner().

    rrferrors = 0  # Count of times through list.

    def main(self):
        '''
        Do Everything.

        basic steps:
            while rollrec file is not empty
                read rollrec file

                for each rollrec in the rollrec file
                    handle according to its phase
        '''
        # Parse our command line into an options hash.
        self.opts = self.get_options(self.opts) or self.usage()

        # If there's a -dtconfig command line option, we'll use that,
        self.dtconfig = '/etc/dnssec-tools/dnssec-tools.conf'
        if self.opts[OPT_DTCONF] and os.path.exists(self.opts[OPT_DTCONF]):
            self.dtconfig = self.opts[OPT_DTCONF]

        # Check our options and arguments.
        self.optsandargs()

        # Check our required external commands.
        self.getprogs()

        # Daemonize ourself.
        if not self.singlerun and not self.foreground:
            pid = os.fork()
            if pid:
                sys.exit(0)
            os.setsid()

        # Ensure we're the only rollerd running and drop a pid file.
        if not self.rollmgr_dropid():
            print('another pyrollerd is already running', file=sys.stderr)
            self.rolllog_log(LOG_ALWAYS, '', 'another pyrollerd tried to start')
            self.cleanup()

        # If it hasn't been set yet, get the pathname for zonesigner.
        if not self.zonesigner:
            print(
                'no absolute path defined for zonesigner; exiting...',
                file=sys.stderr)
            self.rolllog_log(
                LOG_ALWAYS, '',
                'no absolute path defined for zonesigner; exiting...')
            self.cleanup()

        # Tell the log we're up.
        self.bootmsg(True)

        # Mark the domains as being under our control.
        self.eminent_domains()

        # Set up the command channel.
        ch_ret = self.rollmgr_channel(True)
        if ch_ret != 1:
            errs = (
                'Unable to connect to the server.',
                'Unable to create a Unix socket.',
                'Unable to bind to the Unix socket.',
                'Unable to change the permissions on the Unix socket.',
                'Unable to listen on the Unix socket.',
                'Communications socket name was longer than allowed for a Unix socket.',
            )
            self.rolllog_log(
                LOG_FATAL, '',
                'unable to create control communications channel:  %s' %
                errs[ch_ret])
            sys.exit(3)

        # Main event loop.  If the rollrec file is okay, we'll read it,
        # check its zones -- rolling 'em if need be -- and saving its state.
        # We'll always check for user commands and then sleep a bit.
        if self.eventmaster == EVT_FULLLIST:
            self.rolllog_log(LOG_ALWAYS, '', ' ')
            self.full_list_event_loop()
        elif self.eventmaster == EVT_QUEUE_SOON:
            self.rolllog_log(LOG_ALWAYS, '', ' ')
            self.queue_soon_event_loop()
        else:
            self.rolllog_log(
                LOG_FATAL, '',
                'invalid event handler specified; cannot continue')
            print(
                'pyrollerd:  invalid event handler specified; cannot continue',
                file=sys.stderr)
            sys.exit(1)

    def eminent_domains(self):
        '''
        Mark the domains in the rollrec file as being under our control.

        @returns: status
        @rtype: bool
        '''
        # Exit with failure if the rollrec file is bad.
        if not self.rrfokay(''):
            self.rolllog_log(LOG_FATAL, '', 'rollrec file "%s" invalid' % self.rollrecfile)
            return False

        # Get the current contents of the rollrec file.
        self.rollrec_lock()
        self.rollrec_read()

        # For each rollrec entry, get the keyrec file and mark its zone
        # entry as being controlled by us.
        for rname in self.rollrec_names():
            # Get the rollrec for this name.
            rrr = self.rollrec_fullrec(rname)
            if not rrr.is_active:
                continue

            # Build the keyrec file.
            keyrec = rrr.keyrec()

            # Set the error flag if either the zonefile or the keyrec
            # file don't exist.
            if not keyrec:
                self.rolllog_log(
                    LOG_ERR, rname,
                    'keyrec "%s" does not exist' % rrr.keyrec_path)
                continue

            # Mark the keyrec's zone as being under our control.
            keyrec[rname]['rollmgr'] = 'pyrollerd'
            keyrec.save()

        # Save the current rollrec file state.
        self.rollrec_close()
        self.rollrec_unlock()

        # Return success.
        return True

    def full_list_event_loop(self):
        '''
        Rollover event handler -- full queue.
        Every $sleeptime seconds, it checks the entire set of rollrecs
        to see if any rollover actions must be taken.

        This method works fine for small numbers of zones; it gets
        unwieldy as the number of managed zones increases.
        '''
        while 42:
            # Turn off signal handlers so they don't interrupt us
            # while we're running the queue.
            self.controllers(False)
            self.sleep_override = False

            # Return to our execution directory.
            self.rolllog_log(
                LOG_TMI, '',
                'execution directory:  chdir(%s)' % self.xqtdir)
            os.chdir(self.xqtdir)

            # If we have a valid rollrec file, we'll read its contents
            # and handle for expired KSKs and ZSKs.
            if self.rrfchk():
                # Get the contents of the rollrec file and check
                # for expired KSKs and ZSKs.
                self.rollrec_lock()
                if self.rollrec_read():
                    # Check the zones for expired ZSKs.  We'll also
                    # keep track of how long it takes to check the
                    # ZSKs.
                    kronos1 = datetime.datetime.now()
                    self.rollkeys()
                    kronos2 = datetime.datetime.now()
                    kronodiff = kronos2 - kronos1
                    kronos = '%d seconds' % kronodiff.seconds
                    self.rolllog_log(LOG_TMI, '<timer>', 'keys checked in %s' % kronos)

                    # Save the current rollrec file state.
                    self.rollrec_close()
                self.rollrec_unlock()

            # Check for user commands.
            self.commander()

            # We'll stop now if we're only running the queue once.
            if self.singlerun:
                self.rolllog_log(
                    LOG_INFO, '',
                    'rollover manager shutting down at end of single-run execution')
                self.halt_handler()
                sys.exit(0)

            # Turn on our signal handlers and then take a nap.
            self.controllers(True)
            self.sleeper()

    def rollkeys(self):
        '''
        Go through the zones in the rollrec file and start rolling
        the ZSKs and KSKs for those which have expired.
        '''
        # Check the zones in the rollrec file to see if they're ready
        # to roll.
        for rname in self.rollrec_names():
            # Close down if we've received an INT signal.
            if self.queued_int:
                self.rolllog_log(LOG_INFO, rname, 'received immediate shutdown command')
                self.halt_handler()

            # Return to our execution directory.
            self.rolllog_log(LOG_TMI, rname, 'execution directory:  chdir(%s)' % self.xqtdir)
            os.chdir(self.xqtdir)

            # Ensure the logging level is set correctly.
            self.loglevel = self.loglevel_save

            # Get the rollrec for this name.  If it doesn't have one,
            # whinge and continue to the next.
            # (This should never happen, but...)
            rrr = self.rollrec_fullrec(rname)

            # Set the logging level to the rollrec entry's level (if it
            # has one) for the duration of processing this zone.
            self.loglevel_save = self.loglevel
            if 'loglevel' in rrr:
                llev = self.rolllog_num(rrr['loglevel'])
                if llev != -1:
                    self.loglevel = rrr['loglevel']
                    self.loglevel = self.rolllog_level(self.loglevel, False)
                else:
                    self.rolllog_log(
                        LOG_ERR, rname,
                        'invalid rollrec logging level "%s"' % rrr['loglevel'])

            # Don't do anything with skip records.
            if not rrr.is_active:
                self.rolllog_log(LOG_TMI, rname, 'is a skip rollrec')
                continue

            # If this rollrec has a directory record, we'll move into that
            # directory for execution; if it doesn't we'll stay put.
            # If the chdir() fails, we'll skip this rollrec.
            if 'directory' in rrr:
                if (os.path.exists(rrr['directory']) and
                        os.path.isdir(rrr['directory'])):
                    os.chdir(rrr['directory'])
                else:
                    continue

            # If the zone's keyrec file doesn't exist, we'll try to
            # create it with a simple zonesigner call.
            if not rrr.keyrec():
                self.rolllog_log(
                    LOG_ERR, rname,
                    'keyrec "%s" does not exist; running initial zonesigner' %
                    rrr.keyrec_path)
                self.signer(rname, 'initial')

            # Ensure the record has the KSK and ZSK phase fields.
            if 'kskphase' not in rrr:
                self.rolllog_log(LOG_TMI, rname, 'new kskphase entry')
                self.nextphase(rname, rrr, 0, 'KSK')
            if 'zskphase' not in rrr:
                self.rolllog_log(LOG_TMI, rname, 'new zskphase entry')
                self.nextphase(rname, rrr, 0, 'ZSK')

            # Turn off the flag indicating that the zone was signed.
            self.wassigned = False

            # If this zone's current KSK has expired, we'll get it rolling.
            if self.ksk_expired(rname, rrr, 'kskcur'):
                if int(rrr['zskphase']) == 0:
                    self.rolllog_log(LOG_TMI, rname, 'current KSK has expired')
                self.ksk_phaser(rname, rrr)
            else:
                self.rolllog_log(LOG_TMI, rname, 'current KSK still valid')

            # If this zone's current ZSK has expired, we'll get it rolling.
            if self.zsk_expired(rname, rrr, 'zskcur'):
                if int(rrr['zskphase']) == 0:
                    self.rolllog_log(LOG_INFO, rname, 'current ZSK has expired')
                self.zsk_phaser(rname, rrr)
            else:
                self.rolllog_log(LOG_TMI, rname, 'current ZSK still valid')

            # If -alwayssign was specified, always sign the zone
            # even if we didn't need to for this period.
            if self.alwayssign and not self.wassigned:
                extraargs = ''  # Phase-dependent argument.

                self.rolllog_log(
                    LOG_TMI, rname,
                    'signing the zone "%s" (-alwayssign specified)' % rname)

                # Tell the signer what phase we're in so it
                # can decide what key to use.
                if int(rrr['zskphase']) > 0:
                    extraargs = 'ZSK phase %s' % rrr['zskphase']
                elif int(rrr['kskphase']) > 0:
                    extraargs = 'KSK phase %s' % rrr['kskphase']

                # KSK signing uses double-signature so nothing
                # is needed since zonesigner always uses all
                # available keys.

                # Actually do the signing.
                ret = self.signer(rname, extraargs, rrr.keyrec())
                if ret != 0:
                    self.rolllog_log(LOG_ERR, 'signing %s failed!' % rname)

        # Ensure the logging level is set correctly.
        self.loglevel = self.loglevel_save
        self.loglevel = self.rolllog_level(self.loglevel, False)

    def usage(self):
        '''
        Routine: usage()
        Purpose: Print a usage message and exit.
        '''
        print('''usage:  pyrollerd [options]
\toptions:
\t\t-rrfile <rollrec-file>
\t\t-directory <dir>
\t\t-logfile <logfile>
\t\t-loglevel <level>
\t\t-noreload
\t\t-pidfile <pidfile>
\t\t-sleep <sleeptime>
\t\t-dtconfig <dnssec-tools-config-file>
\t\t-zonesigner <full-path-to-zonesigner>
\t\t-display
\t\t-parameters
\t\t-autosign | -noautosign
\t\t-singlerun
\t\t-foreground
\t\t-alwayssign
\t\t-username <username>
\t\t-zsargs <argument-list>
\t\t-verbose
\t\t-Version
\t\t-help''', file=sys.stderr)
        sys.exit(0)


    def parseconfig(self, path):
        config = {}
        for line in open(path, 'r').readlines():
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith(';'):
                key, sep, value = line.replace('\t', ' ').partition(' ')
                if key and value:
                    config[key.strip()] = value.strip()
        return config

    def rrfokay(self, mp=''):
        '''
        Routine: rrfokay()
        Purpose: This routine checks to see if a rollrec file is okay.
                Returns:
                    0 - file is in error
                    1 - file is okay
        '''
        ret = True  # Return code.
        err = ''  # Error message.

        # Check that the file exists and is non-zero in length.  If one of
        # those conditions fails, we'll set an error message and return code.
        if not os.path.exists(self.rollrecfile):
            err = 'rollrec file "%s" does not exist' % self.rollrecfile
            ret = False
        elif os.stat(self.rollrecfile).st_size == 0:
            err = 'rollrec file "%s" is zero length' % self.rollrecfile
            ret = False

        # If we found an error, we'll (maybe) give an error message and
        # bump our error count.
        if ret == False:
            if self.rrferrors == 0:
                # self.rolllog_log(LOG_ERR, mp, err)
                print(err, file=sys.stderr)
                self.rrferrors = MAXRRFERRS
            else:
                self.rrferrors -= 1
            return False

        # Reset our error count and return success.
        self.rrferrors = 0;
        return True

    def optsandargs(self):
        '''
        Routine: optsandargs()
        Purpose: Parse our options and arguments.
        '''
        self.opterrs = 0  # Count of option-related errors.

        # Get the base values.
        self.dtconf = self.parseconfig(self.dtconfig)

        # Get a bunch of option values.
        self.singlerun = self.opts[OPT_SINGLERUN]
        self.foreground = self.opts[OPT_FOREGROUND]
        self.alwayssign = self.opts[OPT_ALWAYSSIGN] or False
        self.pidfile = self.opts[OPT_PIDFILE]
        self.realm = self.opts[OPT_REALM]
        self.verbose = self.opts[OPT_VERBOSE]
        self.logfile = self.opts[OPT_LOGFILE] or self.dtconf.get(DT_LOGFILE)
        self.loglevel = self.opts[OPT_LOGLEVEL] or self.dtconf.get(DT_LOGLEVEL) or LOG_DEFAULT
        self.logtz = self.opts[OPT_LOGTZ] or self.dtconf.get(DT_LOGTZ)
        self.sleeptime = self.opts[OPT_SLEEP] or int(self.dtconf.get(DT_SLEEP)) or DEFAULT_NAP
        self.dtcf = self.opts[OPT_DTCONF] or self.dtconfig
        self.display = self.opts[OPT_DISPLAY] or False
        self.gzsargs = self.opts[OPT_ZSARGS] or ''
        self.username = self.opts[OPT_USERNAME] or self.dtconf.get(DT_USERNAME) or ''
        self.xqtdir = self.opts[OPT_DIR] or '.'
        self.zonesigner = (
            self.opts[OPT_ZONESIGNER] or self.dtconf.get(OPT_ZONESIGNER)
            or '/usr/sbin/zonesigner')

        # Check for autosign presence or absence.
        self.autosign = self.opts[OPT_AUTOSIGN] or (self.dtconf.get(OPT_AUTOSIGN) == '1') or False

        # Determine whether or not we'll load zones.
        self.zoneload = not self.opts[OPT_NORELOAD] or (self.dtconf.get(DT_LOADZONE) == '1')

        # Show the version number if requested
        if self.opts[OPT_HELP]:
            self.usage()
        if self.opts[OPT_VERSION]:
            self.version()

        # Check for a rollrec file name.
        self.rollrecfile = self.opts[OPT_RRFILE] or '/etc/dnssec-tools/dnssec-tools.rollrec'

        # Validate and switch to the given username -- if we can.
        if self.username:
            uid = 0

            # If the username is really a uid, we'll convert it to a name.
            if self.username.isdigit():
                self.username = pwd.getpwuid(int(self.username)).pw_name

            # Convert the name to a uid.
            try:
                uid = pwd.getpwnam(self.username).pw_uid
            except KeyError:
                print(
                    'pyrollerd:  unknown user "%s"' % self.username,
                    file=sys.stderr)
                self.opterrs += 1

            # Change the uid of the process.
            try:
                os.setuid(uid)
            except PermissionError:
                print(
                    'pyrollerd:  unable to switch to user "%s"' % self.username,
                    file=sys.stderr)
                self.opterrs += 1

        # Build a global zonesigner argument string.  We'll convert the
        # internal equals signs to dashes or spaces, as appropriate.
        if self.gzsargs:
            args = self.gzsargs.split(' ')

            # Put the arguments into the form zonesigner is expecting
            # and join up the bits into a single argument string.
            self.gzsargs = ' '.join(
                arg.replace('=', '-', 1).replace('=', ' ', 1) for arg in args)

        # Validate our execution directory.
        if self.xqtdir == '.':
            self.xqtdir = os.getcwd()
        if not self.xqtdir:
            print('pyrollerd:  no execution directory defined', file=sys.stderr)
            self.opterrs += 1
        if not os.path.exists(self.xqtdir):
            print(
                'pyrollerd:  execution directory "%s" does not exist' % self.xqtdir,
                file=sys.stderr)
            self.opterrs += 1
        if not os.path.isdir(self.xqtdir):
            print(
                'pyrollerd:  execution directory "%s" is not a directory' % self.xqtdir,
                file=sys.stderr)
            self.opterrs += 1

        # If the user only wants the parameters, print 'em and exit.
        if self.opts[OPT_PARAMS]:
            print('''%(ME)s parameters:
\trollrec file   "%(rollrecfile)s"
\tdirectory      "%(xqtdir)s"
\tconfig file    "%(dtconfig)s"
\tlogfile        "%(logfile)s"
\tloglevel       "%(loglevel)s"
\tlogtz          "%(logtz)s"
\tautosign       "%(autosign)s"
\tzone reload    "%(zoneload)s"
\tsleeptime      "%(sleeptime)s"''' % {
                'ME': ME,
                'rollrecfile': self.rollrecfile,
                'xqtdir': self.xqtdir,
                'dtconfig': self.dtconfig,
                'logfile': self.logfile,
                'loglevel': self.loglevel,
                'logtz': self.logtz,
                'autosign': self.autosign,
                'zoneload': self.zoneload,
                'sleeptime': self.sleeptime,
            })
            sys.exit(0)

        # Whine if the rollrec file doesn't exist.
        if not self.rrfokay(''):
            print(
                'pyrollerd:  rollrec file "%s" does not exist' % self.rollrecfile,
                file=sys.stderr)
            print(
                'pyrollerd:  not stopping execution; waiting for a rollrec',
                file=sys.stderr)

        # Move into our execution directory.
        os.chdir(self.xqtdir)

        # Ensure a log file was given on the command line or in the config file.
        if not self.logfile:
            print(
                'pyrollerd:  no logfile specified on command line or in dnssec-tools.conf',
                file=sys.stderr)
            self.opterrs += 1

        # Ensure the log file's directory actually exists.
        if self.logfile and self.logfile != '-':
            # Get the log directory without the logfile.
            logdir = os.path.dirname(os.path.abspath(self.logfile))
            # Check for the existence of the log directory.
            if not os.path.exists(logdir):
                print(
                    'pyrollerd:  logfile\'s directory "%s" does not exist' % logdir,
                    file=sys.stderr)
                self.opterrs += 1

        # If a pid file was specified, we'll pass it to the rollmgr module.
        # NOOP

        # Set the logging level and file.
        self.loglevel = self.rolllog_level(self.loglevel, True)
        self.loglevel_save = self.loglevel
        self.logfile = self.rolllog_file(self.logfile, True)

        # Set the called-command options.
        self.rndcopts = self.dtconf.get(DT_RNDCOPTS)

        # Set a dummy value to turn off KSK phase 5 mail, iff no recipient
        # has been set.
        if not self.dtconf.get('admin-email'):
            self.dtconf['admin-email'] = 'nomail'

        # Set the logging timezone.
        logtz = self.rolllog_settz(self.logtz)
        if logtz:
            self.logtz = logtz
        else:
            print(
                'pyrollerd:  invalid log timezone "%s"' % logtz,
                file=sys.stderr)
            self.opterrs += 1

        # Exit if there were any option-related errors.
        if self.opterrs > 0:
            sys.exit(1)

        # Start up our display program if -display was given.
        # NOT IMPLEMENTED

    def getprogs(self):
        '''
        Routine: getprogs()
        Purpose: Get some program paths.
        '''
        # Get the paths to the external commands.  If they aren't defined,
        # use the default command names.
        self.keyarch = self.dtconf.get('keyarch') or '/usr/sbin/keyarch'
        self.rrchk = self.dtconf.get('rollchk') or '/usr/sbin/rollchk'
        self.rndc = self.dtconf.get('rndc') or '/usr/sbin/rndc'
        self.rndcopts = self.dtconf.get('rndcopts') or ''

    def cleanup(self):
        '''
        Routine: cleanup()
        Purpose: Perform whatever clean-up is required.
        '''
        if self.loglevel == LOG_TMI:
            self.rolllog_log(LOG_ALWAYS, 'cleaning up...')
        sys.exit(0)

    def bootmsg(self, bootflag):
        '''
        Routine: bootmsg()
        Purpose: Write a start-up message to the log.
        bootflag - Boot flag.
        '''
        if bootflag:
            self.rolllog_log(LOG_ALWAYS, '', ME + ' starting ' + ('-' * 40))
        else:
            self.rolllog_log(LOG_ALWAYS, '', ME + ' changing logfiles ' + ('-' * 31))

        self.rolllog_log(LOG_ALWAYS, '', ME + ' parameters:');
        self.rolllog_log(LOG_ALWAYS, '', '    rollrec file "%s"' % self.rollrecfile)
        self.rolllog_log(LOG_ALWAYS, '', '    realm        "%s"' % self.realm)
        self.rolllog_log(LOG_ALWAYS, '', '    directory    "%s"' % self.xqtdir)
        self.rolllog_log(LOG_ALWAYS, '', '    config file  "%s"' % self.dtconfig)
        self.rolllog_log(LOG_ALWAYS, '', '    logfile      "%s"' % self.logfile)
        self.rolllog_log(LOG_ALWAYS, '', '    loglevel     "%d"' % self.loglevel)
        self.rolllog_log(LOG_ALWAYS, '', '    logtz        "%s"' % self.logtz)
        self.rolllog_log(LOG_ALWAYS, '', '    always-sign  "%s"' % self.alwayssign)
        self.rolllog_log(LOG_ALWAYS, '', '    autosign     "%s"' % self.autosign)
        self.rolllog_log(LOG_ALWAYS, '', '    single-run   "%s"' % self.singlerun)
        self.rolllog_log(LOG_ALWAYS, '', '    zone reload  "%s"' % self.zoneload)
        if self.eventmaster == EVT_FULLLIST:
            self.rolllog_log(LOG_ALWAYS, '',
                                         '    sleeptime    "%d"' % self.sleeptime)
        # self.rolllog_log(LOG_ALWAYS, '', '    zone reload  "%s"' % self.zoneload)
        self.rolllog_log(LOG_ALWAYS, '', '    event method "%s"' % self.event_methods[self.eventmaster])

        if self.username:
            self.rolllog_log(LOG_ALWAYS, '',
                                         '    running as   "%s"' % self.username)
        self.rolllog_log(LOG_ALWAYS, '', ' ')

    def groupcmd(self, cmd, data):
        '''
        Routine: groupcmd()
        Purpose: Execute a command for each zone in a zone group.
        cmd - Client's command.
        data - Command's data.
        '''
        # Get the list of recognized zone-group commands.  If the requested
        # command isn't allowed for zone groups, we'll quietly run it as
        # a regular command.
        if cmd not in self.zg_commands:
            singlecmd(cmd, data)
            return

        # Run the named command on each zone in the specified zone group.
        rollrec = self.rollrec_read(self.rollrecfile)

        # For each rollrec entry, get the keyrec file and mark its zone
        # entry as being controlled by us.
        rollrec = self.rollrec_read(self.rollrecfile)
        for zn, rrr in rollrec.rolls():
            singlecmd(cmd, zn)

    def singlecmd(self, cmd, data):
        '''
        Routine: singlecmd()
        Purpose: Execute a single command.
        cmd - Client's command.
        data - Command's data.
        '''
        if cmd == ROLLCMD_DISPLAY:
            self.cmd_display(data)
        elif cmd == ROLLCMD_DSPUB:
            self.cmd_dspub(data)
        elif cmd == ROLLCMD_DSPUBALL:
            self.cmd_dspuball()
        elif cmd == ROLLCMD_LOGFILE:
            self.cmd_logfile(data)
        elif cmd == ROLLCMD_LOGLEVEL:
            self.cmd_loglevel(data)
        elif cmd == ROLLCMD_LOGMSG:
            self.cmd_logmsg(data)
        elif cmd == ROLLCMD_LOGTZ:
            self.cmd_logtz(data)
        elif cmd == ROLLCMD_MERGERRFS:
            self.cmd_mergerrfs(data)
        elif cmd == ROLLCMD_PHASEMSG:
            self.cmd_phasemsg(data)
        elif cmd == ROLLCMD_ROLLALL:
            self.cmd_rollall()
        elif cmd == ROLLCMD_ROLLALLKSKS:
            self.cmd_rollallksks()
        elif cmd == ROLLCMD_ROLLALLZSKS:
            self.cmd_rollallzsks()
        elif cmd == ROLLCMD_ROLLREC:
            if self.cmd_rollrec(data):
                return True
        elif cmd == ROLLCMD_ROLLKSK:
            self.cmd_rollnow(data, 'KSK')
        elif cmd == ROLLCMD_ROLLZONE:
            self.cmd_rollzone(data)
        elif cmd == ROLLCMD_ROLLZSK:
            self.cmd_rollnow(data, 'ZSK')
        elif cmd == ROLLCMD_RUNQUEUE:
            self.cmd_runqueue(data)
        elif cmd == ROLLCMD_QUEUELIST:
            self.cmd_queuelist(data)
        elif cmd == ROLLCMD_QUEUESTATUS:
            self.cmd_queuestatus(data)
        elif cmd == ROLLCMD_SHUTDOWN:
            self.cmd_shutdown(data)
        elif cmd == ROLLCMD_SIGNZONE:
            self.cmd_signzone(data)
        elif cmd == ROLLCMD_SIGNZONES:
            self.cmd_signzones(data)
        elif cmd == ROLLCMD_SKIPALL:
            self.cmd_skipall()
        elif cmd == ROLLCMD_SKIPZONE:
            self.cmd_skipzone(data)
        elif cmd == ROLLCMD_SLEEPTIME:
            self.cmd_sleeptime(data)
        elif cmd == ROLLCMD_SPLITRRF:
            self.cmd_splitrrf(data)
        elif cmd == ROLLCMD_STATUS:
            self.cmd_status(data)
        elif cmd == ROLLCMD_ZONEGROUP:
            self.cmd_zonegroup(data)
        elif cmd == ROLLCMD_ZONELOG:
            self.cmd_zonelog(data)
        elif cmd == ROLLCMD_ZONESTATUS:
            self.cmd_zonestatus(data)
        elif cmd == ROLLCMD_ZSARGS:
            self.cmd_zsargs(data)
        else:
            self.rolllog_log(LOG_ERR, '<command>', 'invalid command  - "%s"' % cmd)
        return False

    def signer(self, rname, zsflag, krr=None):
        '''
        Signs a zone with a specified ZSK.
        On success, the return value of the zone-signing command is returned.
        On failure, '' is returned.

        @param rname: Name of rollrec.
        @type rname: str
        zsflag - Flag for key generation.
        krr - Reference to zone's keyrec.

        @returns: string
        @rtype: str
        '''
        initial = False  # Initial-signing flag.
        signonly = ''  # Sign-only flag.

        # If we've been requested to sign a quiescent zone, we'll set a
        # flag and remove the marker from the phase indicator.
        if '-signonly' in zsflag:
            signonly = '-signonly'
            zsflag = zsflag.replace('-signonly', '')

        # Convert the caller's version of zsflag into what it actually
        # means for the zonesigner execution.
        if zsflag == 'KSK phase 2':
            zsflag = '-newpubksk'
        elif zsflag == 'KSK phase 7':
            zsflag = '-rollksk'
        elif zsflag in ('ZSK phase 2', 'ZSK phase 3'):
            zsflag = '-usezskpub'
        elif zsflag == 'ZSK phase 4':
            self.signer(rname, 'ZSK phase 4a' , krr)
            self.signer(rname, 'ZSK phase 4b', krr)
            return
        elif zsflag == 'ZSK phase 4a':
            zsflag = '-rollzsk'
        elif zsflag == 'ZSK phase 4b':
            zsflag = ''
        elif zsflag == 'always-sign':
            zsflag = '-usezskpub'
        elif zsflag == 'initial':
            zsflag = '-genkeys'
            initial = True
        elif re.match(r'[KZ]SK phase [013567]', zsflag):
            zsflag = ''

        # Get the rollrec and any user-specified zonesigner arguments
        # for this zone.
        rrr = self.rollrec_fullrec(rname)
        zsargs = rrr.get('zsargs', '')

        # If there are any user-specified zonesigner arguments, add them
        # to the zonesigner options.  If there aren't any, we'll add
        # any global zonesigner args (from rollerd's -zsargs option).
        if zsargs:
            zsflag += ' ' + zsargs
        elif self.gzsargs:
            zsflag += ' ' + self.gzsargs

        # If the -zone flag wasn't specified, we'll force it in here.
        if '-zone' not in zsflag:
            zsflag += ' -zone %s' % rrr['zonename']

        # If the -krf flag wasn't specified, we'll force it in here.
        if '-krfile' not in zsflag:
            zsflag += ' -krfile %s' % rrr['keyrec']

        # If the -krf flag wasn't specified, we'll force it in here.
        if signonly:
            zsflag += ' -signonly'

        # Set up a few data for the zonesigner command.  Normally, these
        # will be taken from the keyrec file.  In the unusual(?) case of
        # needing an initial signing, these will be generated.
        if initial:
            zonefile = rrr['zonename']
            zonesigned = ''
        else:
            # Dig a few data out of the zone's keyrec file.
            zonefile = krr[rname].get('zonefile')
            if not zonefile:
                return ''
            zonesigned = krr[rname].get('signedzone')
            if not zonesigned:
                return ''

        # Build the command to execute.
        cmdstr = (
            '%(zonesigner)s -rollmgr pyrollerd -dtconfig %(dtcf)s '
            '%(zsflag)s %(zonefile)s %(zonesigned)s' % {
            'zonesigner': self.zonesigner,
            'dtcf': self.dtcf,
            'zsflag': zsflag,
            'zonefile': zonefile,
            'zonesigned': zonesigned,
        })
        self.rolllog_log(LOG_INFO, rname, 'executing "%s"' % cmdstr)

        # Have zonesigner sign the zone for us.
        ret = self.runner(rname, cmdstr, rrr['keyrec'], 0)
        if not ret:
            # Error logging is done in runner(), rather than here
            # or in zoneerr().
            rrr.is_active = False
            rrr.zoneerr()
        else:
            rrr['signed'] = 1
            self.wassigned = True

        return ret

    def runner(self, rname, cmd, krf, negerrflag):
        '''
        Routine: runner()
        Purpose: This routine executes another command.
                 This other command is almost certainly going to be zonesigner.
        rname - Name of rollrec rec.
        cmd - Command to execute.
        krf - Zone's keyrec file.
        negerrflag - Only-negative-error flag.
        '''
        ret = 0  # Command's return code.
        out = ''  # Command's output.

        # Close the current keyrec file.
        # NOOP

        # Execute the specific command.
        self.rolllog_log(LOG_TMI, rname, 'executing "%s"' % cmd)

        # Execute the given command.  We'll save the stdout and stderr
        # output in case of error.
        p = subprocess.Popen(
            shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=os.getcwd())
        ret = p.wait()
        out = p.stdout.read().decode('utf8')

        # If the error flag is set and the command exited with an error,
        # we'll log the output.
        if not negerrflag and ret != 0:
            self.rolllog_log(LOG_ERR, rname, 'execution error for command "%s"' % cmd)
            self.rolllog_log(LOG_ERR, rname, 'error return - %d' % ret)
            self.rolllog_log(LOG_ERR, rname, 'error output - "%s"' % out)

        # Re-read current keyrec file and return a success/fail indicator.
        return ret == 0

    def rrfchk(self):
        '''
        This routine performs initial checking of the rollrec file.
        Several errors and problems are checked for in each rollrec
        marked as a roll rollrec.

        Errors:
            The following errors are checked:
                - the zonefile exists
                - the keyrec file exists

                If any of these are violated, the rollrec's type will
                be changed to a skip rollrec.  This prevents lots of
                unnecessary repeated log messages of an invalid rollrec.

        Problems:
            The following problems are checked:
                - no zonename field exists

            If any of these problems are found, they will be fixed.
        '''
        modified = False  # Modified flag.

        # Return failure if the rollrec file is bad.
        if not self.rrfokay(''):
            return False

        # Get the current contents of the rollrec file.
        self.rollrec_lock()
        self.rollrec_read()

        # For each roll rollrec, check if its zonefile and keyrec file exist.
        # If not, we'll change it to being a skip rollrec.
        for rname in self.rollrec_names():
            # Get the rollrec for this name.  If it doesn't have one,
            # whinge and continue to the next.
            rrr = self.rollrec_fullrec(rname)
            if not rrr:
                rolllog_log(LOG_ERR, rname, 'no rollrec defined for zone')
                continue

            # Don't look at skip records.
            if not rrr.is_active:
                continue

            # Check for a directory.  We'll use rollerd's execution
            # directory if one isn't defined.
            prefix = rrr.get('directory', self.xqtdir)

            ###################################################################
            # NOT IMPLEMENTED
            ###################################################################

        return True


    def nextphase(self, rname, rrr, phase, phasetype):
        '''
        Moves a rollrec into the next rollover phase, setting both the
        phase number and the phase start time.

        @param rname: Name of rollrec.
        @type rname: str
        @param rrr: Rollrec reference.
        @type rrr: Roll
        @param phase: New phase.
        @type phase: str
        @param phasetype: Type of rollover.
        @type phasetype: str
        '''
        # Give a log message about this rollover phase.
        if phase == 1:
            self.rolllog_log(
                LOG_TMI, rname, 'starting %s rollover' % phasetype)
        else:
            self.rolllog_log(
                LOG_TMI, rname, 'moving to %s phase %d' %
                (phasetype, phase))

        # This is the source of the log messages that look like
        # "KSK phase 3" and "ZSK phase 4".
        self.rolllog_log(LOG_PHASE, rname, '%s phase %d' % (phasetype, phase))

        # Get the latest and greatest rollrec file.
        # self.rollrec_close()
        # self.rollrec_read()

        # Change the zone's phase and plop it on disk.
        rrr['%sphase' % phasetype.lower()] = str(phase)
        rollrec_write()
        # rollrec_close()
        # rollrec_read()

        # Get the rollin' key's keyrec for our zone.
        krec = rrr.keyrec()
        krname = krec[rname]['%scur' % phasetype]
        setrec = getattr(rrr.keyrec()[rname], '%scur' % phasetype)
        if not setrec:
            self.rolllog_log(
                LOG_ERR, rname,
                'unable to find a keyrec for the %scur phase signing set in "%s"' %
                (phasetype, krname))
            return

        # Make sure we've got an actual set keyrec and keys.
        if not isinstance(setrec, KeySet):
            self.rolllog_log(
                LOG_ERR, rname,
                '"%s"\'s keyrec is not a set keyrec; unable to move to '
                '%s phase %d' % (krname, phasetype, phase))
            return
        if not setrec.keys:
            self.rolllog_log(
                LOG_ERR, rname,
                '"%s" has no keys; unable to move to %s phase %d' %
                (krname, phasetype, phase))
            return

        # Find the key with the shortest lifetime.
        exptime = setrec.minlife_key().life

        # Send phase info to the display program.
        if phase != 0:
            exptime = rrr['maxttl'] * 2

        chronostr = '% secs' % exptime
        self.rolllog_log(
            LOG_INFO, rname,
            '    %s expiration in %s' % (phasetype, chronostr))

        # Reset the phasestart field if we've completed a rollover cycle.
        if phase == 0:
            rollrec_settime(rname)
            rollrec_write()

    def zonemodified(self, rrr, rname):
        '''
        Checks if a zone file has been modified more recently than
        its signed version.  If so, then the zone file will be
        re-signed -- without any keys created or other rollover
        actions taken.

        The "more recent" check is performed by comparing the date
        of last modification for the two zone files.  If the unsigned
        zonefile's date is greater than the signed zonefile's date,
        then it is assumed the unsigned zonefile was modified.

        This only works if the signed and unsigned zonefiles are
        in different files.

        @param rrr: Rollrec reference.
        @type rrr: RollRec
        @param rname: Zone under consideration.
        @type rname: str
        '''
        krf = rrr.keyrec()  # Zone's keyrec file.

        # Go no further here if we aren't autosigning.
        if not self.autosign:
            return

        # Get the name of the zonefile.
        zfu = krf[rname]['zonefile']

        # Now we'll get the name of the signed zonefile.
        zfs = krf[rname]['signedzone']
        if zfs != rrr['zonefile']:
            self.rolllog_log(
                LOG_ERR, rname,
                'rollrec and keyrec disagree about name of signed zone file')
            self.rolllog_log(
                LOG_ERR, rname,
                "  rollrec's signed zone file - %s" % rrr['zonefile'])
            self.rolllog_log(
                LOG_ERR, rname,
                "  keyrec's signed zone file  - %s" % zfs)

        # Get the last modification time of the signed zonefile.
        zfutime = os.stat(krf[rname].zonefile_path).st_mtime

        # Get the last modification time of the unsigned zonefile.
        zfstime = os.stat(krf[rname].signedzone_path).st_mtime

        # Check the last modification times, and sign the zonefile if it's
        # been changed more recently than the unsigned zonefile.
        if zfutime > zfstime:
            self.rolllog_log(LOG_PHASE, rname, 'zonefile modified; re-signing')

            # Sign -- just sign -- the zone.
            if signer(rname, rrr.phaseargs, krf) == 0:
                self.rolllog_log(LOG_TMI, rname, 'rollerd signed zone')
            else:
                self.rolllog_log(LOG_ERR, rname, 'unable to sign zone')
