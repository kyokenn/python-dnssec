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

from ..common import CommonMixin
from ..defs import *
from ..parsers.keyrec import KeySet
from ..rolllog import *
from ..rollmgr import *
from ..rollrec import RollRecMixin
from .conf import ConfMixin
from .cmd import CmdMixin
from .daemon import DaemonMixin
from .ksk import KSKMixin
from .message import MessageMixin
from .zsk import ZSKMixin


class RollerD(
        ConfMixin,
        CmdMixin,
        CommonMixin,
        DaemonMixin,
        KSKMixin,
        MessageMixin,
        RollLogMixin,
        RollMgrMixin,
        RollRecMixin,
        ZSKMixin):

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
        'lockfile': '',  # rollrec lock file
        'sockfile': '',  # socket file
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
    lockfile = ''  # rollrec lock file
    sockfile = ''  # socket file
    realm = ''  # Our realm.
    singlerun = False  # Single run only.
    sleep_override = False  # Sleep-override flag.
    sleepcnt = 0  # Time we've slept so far.
    sleeptime = 0  # Sleep interval in seconds.
    username = ''  # User name we'll change to.
    gzsargs = ''  # Global zsargs for zonesigner.
    verbose = False  # Verbose option.

    display = False  # Do display processing.

    auto = False  # automatic keyset transfer
    provider = None  # DNSSEC provider
    provider_key = ''  # DNSSEC provider API KEY

    boottime = datetime.datetime.now()  # Timestamp of rollerd's start time.

    keyarch = ''  # Key-archive program.
    packed = False  # Flag indicating if running packed.
    xqtdir = ''  # Execution directory.

    # "full list" queue processing is the classic rollerd method of handling its
    # queue.  Every N seconds, the entire queue of zones is scanned to see if any
    # rollover events must be handled.

    # "soon" queue processing is experimental.  It maintains a sub-queue of the
    # rollover events that must be handled soon.  Rather than processing the full
    # queue of managed zones every N seconds, the "soon queue" is handled as the
    # events occur.

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

    def main(self, args):
        '''
        Do Everything.

        basic steps:
            while rollrec file is not empty
                read rollrec file

                for each rollrec in the rollrec file
                    handle according to its phase
        '''
        # Parse our command line into an options hash.
        self.opts = self.get_options(self.opts, args[1:]) or self.usage()

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
                    self.rolllog_log(LOG_TMI, '<timer>', 'keys checked in %s' % kronodiff)

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
                if self.auto and self.provider and self.provider_key:
                    self.rolllog_log(
                        LOG_ERR, rname, 'transfer new keyset to the parent')
                    ret = rrr.dspub(self.provider, self.provider_key)
                    if not ret:
                        self.rolllog_log(
                            LOG_ERR, rname,
                            'automatic keyset transfer failed')

            # Ensure the record has the KSK and ZSK phase fields.
            if 'kskphase' not in rrr:
                self.rolllog_log(LOG_TMI, rname, 'new kskphase entry')
                self.nextphase(rname, rrr, 0, 'ksk')
            if 'zskphase' not in rrr:
                self.rolllog_log(LOG_TMI, rname, 'new zskphase entry')
                self.nextphase(rname, rrr, 0, 'zsk')

            # Turn off the flag indicating that the zone was signed.
            self.wassigned = False

            # If this zone's current KSK has expired, we'll get it rolling.
            if self.ksk_expired(rname, rrr, 'kskcur'):
                if rrr.zskphase == 0:
                    self.rolllog_log(LOG_TMI, rname, 'current KSK has expired')
                self.ksk_phaser(rname, rrr)
            else:
                self.rolllog_log(LOG_TMI, rname, 'current KSK still valid')

                # If this zone's current ZSK has expired, we'll get it rolling.
                if self.zsk_expired(rname, rrr, 'zskcur'):
                    if rrr.zskphase == 0:
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
                if rrr.zskphase > 0:
                    extraargs = 'ZSK phase %d' % rrr.zskphase
                elif rrr.kskphase > 0:
                    extraargs = 'KSK phase %d' % rrr.kskphase

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
        self.lockfile = self.opts['lockfile']
        self.sockfile = self.opts['sockfile']
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
        self.autosign = self.opts[OPT_AUTOSIGN] or (self.dtconf.get(DT_AUTOSIGN) == '1') or False

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
            self.parameters()

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

        # autopublish settings for KSK phase 5
        self.auto = self.dtconf.get('roll_auto') == '1'
        self.provider = self.dtconf.get('roll_provider')
        self.provider_key = self.dtconf.get('roll_provider_key')

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
            self.rolllog_log(LOG_ALWAYS, '', 'cleaning up...')
        sys.exit(0)

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

        # Additional options for dnssec-signzone
        # zsflag += ' -szopts "-o %s"' % rname

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
        # self.rolllog_log(LOG_INFO, rname, 'executing "%s"' % cmdstr)

        # Have zonesigner sign the zone for us.
        ret = self.runner(rname, cmdstr, rrr['keyrec'], False)
        if not ret:
            # Error logging is done in runner(), rather than here
            # or in zoneerr().
            rrr.is_active = False
            rrr.zoneerr()
        else:
            # rrr['signed'] = 1
            self.wassigned = True

        return ret

    def runner(self, rname, cmd, krf, negerrflag):
        '''
        This routine executes another command.
        This other command is almost certainly going to be zonesigner.

        @param rname: Name of rollrec rec.
        @type rname: str
        @param cmd: Command to execute.
        @type cmd: str
        @param krf: Zone's keyrec file.
        @type krf: KeyRec
        @param negerrflag: Only-negative-error flag.
        @type bool
        '''
        ret = 0  # Command's return code.
        out = ''  # Command's output.

        # Execute the specific command.
        self.rolllog_log(LOG_TMI, rname, 'executing "%s"' % cmd)

        # Execute the given command.  We'll save the stdout and stderr
        # output in case of error.
        p = subprocess.Popen(
            shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=os.getcwd())
        rcode = p.wait()
        out = p.stdout.read().decode('utf8')

        # If the error flag is set and the command exited with an error,
        # we'll log the output.
        # if not negerrflag and rcode != 0:
        if rcode != 0:
            self.rolllog_log(
                LOG_ERR, rname, 'execution error for command "%s"' % cmd)
            self.rolllog_log(LOG_ERR, rname, 'error return - %d' % rcode)
            self.rolllog_log(LOG_ERR, rname, 'error output - "%s"' % out)

        # Re-read current keyrec file and return a success/fail indicator.
        return rcode == 0

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
                self.rolllog_log(LOG_ERR, rname, 'no rollrec defined for zone')
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
                LOG_TMI, rname, '>>> starting %s rollover' % phasetype.upper())
        else:
            self.rolllog_log(
                LOG_TMI, rname, '>>> moving to %s phase %d' %
                (phasetype.upper(), phase))

        # This is the source of the log messages that look like
        # "KSK phase 3" and "ZSK phase 4".
        self.rolllog_log(
            LOG_PHASE, rname, '%s phase %d' % (phasetype.upper(), phase))

        # Get the latest and greatest rollrec file.
        self.rollrec_close()
        self.rollrec_read()
        rrr = self.rollrec_fullrec(rname)

        # Change the zone's phase and plop it on disk.
        rrr['%sphase' % phasetype.lower()] = str(phase)
        rrr.settime()
        self.rollrec_write()
        self.rollrec_close()
        self.rollrec_read()
        rrr = self.rollrec_fullrec(rname)

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

        if phase == 0:
            # Find the key with the shortest lifetime.
            exptime = setrec.minlife_key().life
        else:
            exptime = rrr.maxttl()

        chronostr = '%s' % (
            rrr.phasestart_date + datetime.timedelta(seconds=exptime) -
            datetime.datetime.now()
        )
        self.rolllog_log(
            LOG_INFO, rname,
            '        %s expiration in %s' % (phasetype.upper(), chronostr))

        # Reset the phasestart field if we've completed a rollover cycle.
        if phase == 0:
            rrr.settime()
            self.rollrec_write()

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
            if self.signer(rname, rrr.phaseargs, krf):
                self.rolllog_log(LOG_TMI, rname, 'rollerd signed zone')
            else:
                self.rolllog_log(LOG_ERR, rname, 'unable to sign zone')

    def phasecmd(self, phasefunc, rname, rrr, phase, ptaux=None):
        '''
        Run a list of commands for this rollover phase.  If a list is
        not defined for this phase, then we'll use the default action.

        @param phasefunc: Reference to phase function.
        @type phasefunc: function
        @param rname: Zone name.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll
        @param phase: Phase we're handling.
        @type phase: str
        @param ptaux: Auxiliary phase type.
        @type ptaux: str
        '''
        progkey = 'prog-%s' % phase  # Config. key for phase's programs.

        # Get the command list for this rollover phase.  Force the default
        # if a command list isn't defined for the phase.
        cmdlist = self.dtconf.get(progkey, 'default')
        cmds = cmdlist.split('!')

        # Break out the phase atoms.  If this is a normal phase, then
        # we'll be alchemists and transmute the atoms we need.
        if phase == 'normal':
            phasetype = 'normal'
            phasenum = 1
        else:
            blob = re.match(r'([kz]sk)(\d)', phase.lower())
            phasetype = blob.group(1)
            phasenum  = int(blob.group(2))

            # Set a variable for phasewait().
            ptaux = ptaux or phasetype

        # Run the commands defined for this phase.  The default commands
        # are handled internally to rollerd.
        for cmd in cmds:
            # Get rid of any leading or trailing blanks.
            cmd = cmd.strip()

            # Take this phase's normal rollover action if the command
            # is "default".
            if cmd == 'default':
                # Run the phase-specific routine.
                ret = phasefunc(rname, rrr, phasenum, ptaux)
                if ret is not None and ret < 0:
                    return phasenum

                # This is a special case for when we're in normal
                # rollover.
                # (Yes, in this situation, normal is a special case.)
                if phase == '0':
                    phasenum = 0

                # Save the return code as our new phase.
                newphase = ret
            else:
                # Set up the arguments for the command.
                cmdargs = ' '.join(
                    rrr['zonename'], phase, rname,
                    self.rollrecfile, rrr.keyrec_path)

                # Execute the phase's locally defined program.
                ret = self.localprog(rname, cmd, cmdargs, phase)

                # Stay in this phase if this command didn't succeed.
                if ret != 0:
                    return phasenum

        # If we've reached the final rollover phase, we'll go to non-rollover.
        if phase in ('ksk7', 'zsk4'):
            newphase = 0

        # Special handling if the phase has changed, followed by special
        # handling if it hasn't.
        if phasenum != newphase:
            # Set the new KSK phase.
            if phase.startswith('ksk'):
                self.nextphase(rname, rrr, newphase, 'ksk')

            # Set the new ZSK phase.
            if phase.startswith('zsk'):
                self.nextphase(rname, rrr, newphase, 'zsk')

            if newphase == 0:
                self.zonemodified(rrr, rname)
        else:
            # Re-sign the zone file if it has been modified more recently
            # than the signed zone file.
            self.zonemodified(rrr, rname)

        # Return the phase number we should be in.
        return newphase

    def phasewait(self, rname, rrr, phase, phasetype):
        '''
        Check if this zone's rollover wait phase is over.
        The zone's phase number -- current or new -- is returned.
        KSKs will also be checked for trust-anchorship and if the
        hold-down timer has expired.

        @param rname: Name of rollrec.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll
        @param phase: Rollover phase.
        @type phase: str
        @param phasetype: Rollover phase type.
        @type: str

        @returns: next phase number
        @rtype: int
        '''
        # Make sure we've got the latest and greatest rollrec.
        rrr = self.rollrec_fullrec(rname)
        ttlleft = rrr.ttlleft()

        self.rolllog_log(
            LOG_INFO, rname,
            '%s phase %d; cache expires in %s' %
            (phasetype.upper(), phase, ttlleft))

        # Check if we can go to the next rollover phase.  If not, we'll
        # go to the next rollrec entry and return to this later.
        if phasetype == 'zsk':
            if ttlleft:
                return phase
        elif phasetype == 'ksk':
            if ttlleft:
                return phase
            if rrr['istrustanchor'] == 'yes':
                hdleft = rrr.holddownleft()
                self.rolllog_log(
                    LOG_INFO, rname,
                    '%s phase %d; hold-down timer expires in %s' &
                    (phasetype.upper(), phase, hdleft))
                if hdleft:
                    return phase

        # Return the next phase number.
        return phase + 1

    def loadzone(self, rname, rrr, phase):
        '''
        Initiates zone-reload, but obeys the $zoneload flag.

        @param rname: Rollrec name of zone.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll
        @param phase: Zone's current phase.
        @type phase: str

        @returns: True on success
        @rtype: bool
        '''
        useopts = rrr.get('rndc_opts', self.rndcopts)

        # If the user doesn't want to reload the zone, we'll pretend we have.
        if not self.zoneload:
            self.rolllog_log(
                LOG_INFO, rname, 'not reloading zone for %s' % phase)
            return False

        # Reload the zone for real.
        self.rolllog_log(LOG_INFO, rname, 'reloading zone for %s' % phase)
        ret = rrr.loadzone(self.rndc, useopts)
        return ret == 0

    def rollnow(self, zone, rolltype, force):
        '''
        This command moves a zone into immediate rollover for the
        specified key type.  It doesn't sit in the initial waiting
        period, but starts right off in rollover phase 2.

        @param zone: Command's data.
        @type zone: str
        @param rolltype: Type of roll to start.
        @type rolltype: str
        @param force: Force-rollover flag.
        @type force: bool
        '''
        # Re-read the rollrec file and change the record's type.  We'll
        # also move the zone to phase 2 of rollover.
        self.rollrec_lock()
        self.rollrec_read()

        # Get the rollrec for the zone.
        rndir = os.getcwd()

        # Get the rollrec for the zone.
        rrr = self.rollrec_fullrec(zone)
        if not rrr:
            self.rolllog_log(
                LOG_ERR, '<command>', 'no rollrec defined for zone %s' % zone)
            self.rollrec_close()
            self.rollrec_unlock()
            return 0

        # If the caller isn't demanding a rollover, we'll make sure
        # the zone isn't already rolling.
        if not force:
            if rrr.kskphase > 0:
                self.rolllog_log(
                    LOG_TMI, '<command>',
                    'in KSK rollover (phase %d); not attempting rollover' %
                    rrr.kskphase)
                self.rollrec_close()
                self.rollrec_unlock()
                return 0
            if rrr.zskphase > 0:
                self.rolllog_log(
                    LOG_TMI, '<command>',
                    'in ZSK rollover (phase %d); not attempting rollover' %
                    rrr.zskphase)
                self.rollrec_close()
                self.rollrec_unlock()
                return 0

        # A skip record is changed to a regular rollrec.
        if not rrr.is_active:
            self.rolllog_log(
                LOG_INFO, '<command>',
                '%s skip rollrec changed to a roll rollrec' % zone)
            rrr.is_active = True

        # Change the zone's phase to rollover phase 1 (starting).
        # WJH: This used to be set to phase 2 to bypass
        # the initial rollover waiting period and get right to the
        # nitty gritty of doing a rollover.  But I changed it back
        # to phase one, which is especially important for frequent
        # or sudden rollovers.
        if rolltype == 'KSK':
            self.nextphase(zone, rrr, 1, 'KSK')
        elif rolltype == 'ZSK':
            self.nextphase(zone, rrr, 1, 'ZSK')
        elif rolltype == 'restart':
            # Do nothing, just move from skip to roll.
            pass

        return 1
