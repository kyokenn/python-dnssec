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
import re
import os
import pwd
import signal
import sys
import time

from . import defs
from .common import CommonMixin
from .cmd import *
from .defs import *
from .rolllog import *
from .rollmgr import *
from .rollrec import *


INC = os.path.dirname(defs.__file__)


class RollerD(CmdMixin, RollLogMixin, RollRecMixin, RollMgrMixin, CommonMixin):
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

    curdir = ''  # Directory.
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

    def rrfokay(self, rrf, mp):
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
        if not os.path.exists(rrf):
            err = 'rollrec file "%s" does not exist' % rrf
            ret = False
        elif os.stat(rrf).st_size == 0:
            err = 'rollrec file "%s" is zero length' % rrf
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
        if not self.rrfokay(self.rollrecfile, ''):
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
        self.loglevel_save = self.loglevel
        self.loglevel = self.rolllog_level(self.loglevel, True)
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

    def eminent_domains(self, rrf):
        '''
        Routine: eminent_domains()
        Purpose: Mark the domains in the rollrec file as being under our control.
        rrf - Rollrec file.
        '''
        # Exit with failure if the rollrec file is bad.
        if not self.rrfokay(rrf, ''):
            self.rolllog_log(LOG_FATAL, '', 'rollrec file "%s" invalid' % rrf)
            return 0

        # Get the current contents of the rollrec file.
        self.rollrec_lock()
        self.rollrec_read(self.rollrecfile)

        # For each rollrec entry, get the keyrec file and mark its zone
        # entry as being controlled by us.
        for rname in rollrec_names():
            # Get the rollrec for this name.
            rrr = self.rollrec_fullrec(rname)

            # Build the keyrec file.
            keyrec = rrr.keyrec()

            # Mark the keyrec's zone as being under our control.
            keyrec[rname]['rollmgr'] = 'pyrollerd'
            keyrec.save()

        # Save the current rollrec file state.
        self.rollrec_close()
        self.rollrec_unlock()

        # Return success.
        return True

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

    def commander(self):
        '''
        Routine: commander()
        Purpose: Get any commands sent to rollerd's command socket.
        '''
        gstr = ROLLMGR_GROUP  # Group command indicator.
        self.rolllog_log(LOG_TMI, '<command>', 'checking commands')

        # Read and handle all the commands we've been sent.
        while 42:
            # Get the command, return if there wasn't one.
            cmd, data = self.rollmgr_getcmd(5)
            if not cmd:
                return

            self.rolllog_log(LOG_TMI, '<command>', 'cmd   - "%s"' % cmd)
            if data:
                self.rolllog_log(LOG_TMI, '<command>', 'data  - "%s"' % data)

            # Deal with the command as zone-related or as a group command.
            if cmd.startswith(gstr):
                cmd = cmd[len(gstr):]
                self.groupcmd(cmd, data)
            else:
                if self.singlecmd(cmd, data):
                    break
            self.rollmgr_closechan()


    def intcmd_handler(self):
        '''
        Routine: intcmd_handler()
        Purpose: Handle an interrupt and get a command.
        '''
        self.rolllog_log(LOG_TMI, '<command>', 'rollover manager:  got a command interrupt\n')
        self.controllers(False)
        self.commander()
        self.controllers(True)

    def halt_handler(self):
        '''
        Routine: halt_handler()
        Purpose: Handle the "halt" command.
        '''
        self.rolllog_log(LOG_ALWAYS, '', 'rollover manager shutting down...\n')
        # self.rollrec_write(self.rollrecfile)  # dump the current file with commands
        # self.rollmgr_rmid()
        sys.exit(0)

    def queue_int_handler(self):
        '''
        Routine: queue_int_handler()
        Purpose: Remember that a sig INT was received for later processing.
        '''
        self.queued_int = True

    def queue_hup_handler(self):
        '''
        Routine: queue_hup_handler()
        Purpose: Remember that a sig HUP was received for later processing.
        '''
        self.queued_hup = True

    def controllers(self, onflag):
        '''
        Routine: controllers()
        Purpose: Initialize handlers for our externally provided commands.
        onflag - Handler on/off flag.
        '''
        # Set the signal handlers that will manage incoming commands.
        if onflag:
            if self.queued_int:
                self.queued_int = False
                self.halt_handler()
            if self.queued_hup:
                self.queued_hup = False
                self.intcmd_handler()
            signal.signal(
                signal.SIGHUP,
                lambda signalnum, frame: self.intcmd_handler())
            signal.signal(
                signal.SIGINT,
                lambda signalnum, frame: self.halt_handler())
        else:
            signal.signal(
                signal.SIGHUP,
                lambda signalnum, frame: self.queue_hup_handler())
            signal.signal(
                signal.SIGINT,
                lambda signalnum, frame: self.queue_int_handler())

    def sleeper(self):
        '''
        Routine: sleeper()
        Purpose: Sleep for a specific amount of time.  This will take into
                 account interrupts we've taken from rollctl.
                 We may be overridden by a rollctl command.
        '''
        if self.sleep_override:
            return
        self.rolllog_log(LOG_TMI, '', 'sleeping for $sleeptime seconds')
        self.sleepcnt = 0
        while self.sleepcnt < self.sleeptime:
            nap = self.sleeptime - self.sleepcnt
            self.sleepcnt += nap
            time.sleep(nap)

    def signer(self, rname, zsflag, krr):
        '''
        Routine: signer()
        Purpose: Signs a zone with a specified ZSK.
                On success, the return value of the zone-signing command
                is returned.
                On failure, "" is returned.
        rname - Name of rollrec.
        zsflag - Flag for key generation.
        krr - Reference to zone's keyrec.
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
        if '-krf' not in zsflag:
            zsflag += ' -krf %s' % rrr['keyrec']

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
            '%(zonesigner)s -rollmgr rollerd -dtconfig %(dtcf)s '
            '%(zsflag)s %(zonefile)s %(zonesigned)s' % {
            'zonesigner': self.zonesigner,
            'dtcf': self.dtcf,
            'zsflag': self.zsflag,
            'zonefile': zonefile,
            'zonesigned': zonesigned,
        })
        self.rolllog_log(LOG_INFO, rname, 'executing "%s"' % cmdstr)

        # Have zonesigner sign the zone for us.
        # NOT IMPLEMENTED
        # ret = self.runner(rname, cmdstr, rrr['keyrec'], 0)
        # if ret != 0:
        #     # Error logging is done in runner(), rather than here
        #     # or in zoneerr().
        #     self.skipnow(rname)
        #     self.zoneerr(rname, rrr)
        # else:
        #     rrr['signed'] = 1
        #     wassigned = 1

        # return ret

    def rollkeys(self, rollrec):
        '''
        Routine: rollkeys()
        Purpose: Go through the zones in the rollrec file and start rolling
                 the ZSKs and KSKs for those which have expired.
        '''
        # Let the display program know we're starting a roll cycle.
        # NOT IMPLEMENTED

        # Check the zones in the rollrec file to see if they're ready
        # to roll.
        for rname, rrr in rollrec.rolls():
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
            # NOT IMPLEMENTED

            # Set the logging level to the rollrec entry's level (if it
            # has one) for the duration of processing this zone.
            self.loglevel_save = self.loglevel
            if 'loglevel' in rrr:
                llev = self.rolllog_num(rrr['loglevel'])
                if llev != -1:
                    self.loglevel = llev
                    self.rolllog_level(self.loglevel, 0)
                else:
                    self.rolllog_log(
                        LOG_ERR, rname,
                        'invalid rollrec logging level "%s"' rrr['loglevel'])

            # Don't do anything with skip records.
            if not rrr.is_active:
                self.rolllog_log(LOG_TMI, rname, 'is a skip rollrec')
                continue

            # If this rollrec has a directory record, we'll move into that
            # directory for execution; if it doesn't we'll stay put.
            # If the chdir() fails, we'll skip this rollrec.
            if rrr.get('directory'):
                if (os.path.exists(rrr['directory']) and
                        os.path.isdir(rrr['directory'])):
                    os.chdir(rrr['directory'])
                else:
                    continue

            # If the zone's keyrec file doesn't exist, we'll try to
            # create it with a simple zonesigner call.
            if not rrr.get('keyrec'):
                self.rolllog_log(
                    LOG_ERR, rname,
                    "keyrec \"rrr['keyrec']\" does not exist; "
                    'running initial zonesigner')
                self.signer(rname, 'initial', 0)

            ########################################################################
            # NOT IMPLEMENTED
            ########################################################################

    def full_list_event_loop(self):
        '''
        Routine: full_list_event_loop()
        Purpose: Rollover event handler -- full queue.
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
            self.rolllog_log(LOG_TMI,'','execution directory:  chdir()' % self.xqtdir)
            os.chdir(self.xqtdir)

            # If we have a valid rollrec file, we'll read its contents
            # and handle for expired KSKs and ZSKs.
            if self.rrfchk(self.rollrecfile):
                # Get the contents of the rollrec file and check
                # for expired KSKs and ZSKs.
                self.rollrec_lock()
                if self.rollrec_read(self.rollrecfile):
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
                    rollrec_close()
                rollrec_unlock()

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

    def main(self):
        '''
        Routine: main()
        Purpose: Do Everything.

        basic steps:
            while rollrec file is not empty
                read rollrec file

                for each rollrec in the rollrec file
                    handle according to its phase
        '''
        # Parse our command line into an options hash.
        self.opts = self.get_options(self.opts) or self.usage()

        # If there's a -dtconfig command line option, we'll use that,
        self.dtconfig = os.path.join(INC, 'dnssec-tools.conf')
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
        self.eminent_domains(self.rollrecfile)

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
