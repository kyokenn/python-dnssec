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

import re
import signal
import sys

from .common import *
from .defs import *
from .rolllog import *
from .rollmgr import *


class RollCtl(RollMgrMixin, RollLogMixin, CommonMixin):
    NAME = 'pyrollctl'
    VERS = NAME + ' version: 0.0.1'
    DTVERS = 'DNSSEC-Tools Version: N/A'

    # Data required for command line options.
    opts = {
        'halt': '',  # Shutdown rollerd.
        'display': False,  # Turn on rollerd's graphical display.
        'dspub': False,  # Parent has published a DS record.
        'dspuball': False,  # Parents have published DS records.
        'logfile': '',  # Set rollerd's log file.
        'loglevel': '',  # Set rollerd's logging level.
        'logtz': '',  # Set rollerd's logging timezone.
        'mergerrfs': False,  # Merge a set of rollrec files.
        'phasemsg': '',  # Set rollerd's phase-message length.
        'pidfile': '',  # pid storage file.
        'nodisplay': False,  # Turn off rollerd's graphical display.
        'rollall': False,  # Resume all suspended zones.
        'rollallksks': False,  # KSK-roll all our zones.
        'rollallzsks': False,  # ZSK-roll all our zones.
        'rollksk': False,  # KSK roll the specified zone(s).
        'rollrec': '',  # Change the rollrec file.
        'rollzone': False,  # Restart the suspended, named zone(s).
        'rollzsk': False,  # ZSK roll the specified zone(s).
        'runqueue': False,  # Run the queue.
        'queuelist': False,  # Get list of zones in the soon queue.
        'queuestatus': False,  # Status of queue-soon event handler.
        'shutdown': '',  # Shutdown rollerd.
        'skipall': False,  # Stop all zones from rolling.
        'skipzone': False,  # Stop the named zone(s) from rolling.
        'signzone': False,  # Sign only the named zone(s).
        'signzones': False,  # Sign all the zones.
        'sleeptime': 0,  # Set rollerd's sleep time.
        'splitrrf': False,  # Split a rollrec file in two.
        'status': False,  # Get rollerd's status.
        'zonegroup': '',  # Get a list of current zone groups.
        'zonelog': False,  # Set a zone's/zones' logging level.
        'zonestatus': False,  # Get status of zones.
        'zsargs': False,  # Set zonesigner args for some zones.
        'group': False,  # Apply command to zone group.
        'Version': False,  # Display the version number.
        'quiet': False,  # Don't print anything.
        'help': False,  # Give a usage message and exit.
    }

    # Flags for the options.  Variable/option mapping should obvious.
    commandcount = 0

    dispflag = False
    dspubflag = False
    dspuballflag = False
    groupflag = False
    krollallflag = False
    logfileflag = False
    loglevelflag = False
    logtzflag = False
    logphasemsg = ''
    mergerrfsflag = False
    nodispflag = False
    rollallflag = False
    rollkskflag = False
    rollrecflag = False
    rollzoneflag = False
    rollzskflag = False
    runqueueflag = False
    queuelistflag = False
    queuestatusflag = False
    shutdownflag = 0
    signzoneflag = False
    signzonesflag = False
    skipallflag = False
    skipzoneflag = False
    sleeptimeflag = False
    splitrrfflag = False
    statusflag = False
    zonegroupflag = None
    zonelogflag = False
    zonestatflag = False
    zrollallflag = False
    zsargsflag = False
    pidfile = ''
    quiet = False
    version = False   # Display the version number.

    def usage(self):
        '''
        Routine: usage()
        '''
        print('''usage:  pyrollctl [options]
\t-halt [now]\t\tshutdown rollerd
\t-display\t\tstart graphical display
\t-dspub <zone>\t\tparent has published DS record for zone
\t-dspuball\t\tparents have published DS records for zones
\t-group\t\t\tapply command to zone group
\t-logfile <logfile>\tset log file
\t-loglevel <loglevel>\tset logging level
\t-logtz <log-timezone>\tset logging timezone
\t-phasemsg <length>\tset phase-message length
\t-pidfile <pidfile>\tset rollerd's process-id file
\t-nodisplay\t\tstop graphical display
\t-rollall\t\trestart all suspended zones
\t-rollallzsks\t\troll all zones
\t-rollksk <zone>\t\troll specified zone's KSK
\t-rollzone <zone>\trestart named suspended zone
\t-rollzsk <zone>\t\troll named zone
\t-rollrec <rollrec>\tset rollrec file
\t-runqueue\t\trun queue
\t-shutdown [now]\t\tshutdown rollerd
\t-signzone <zone>\tsign named zone (no key rollover)
\t-signzones [all|active]\tsign zones (no key rollover)
\t-skipall\t\tskip all zones
\t-skipzone <zone>\tskip named zone
\t-splitrrf <rrf entries>\tsplit the current rollrec file
\t-sleeptime <seconds>\tset sleep time (in seconds)
\t-status\t\t\tget rollerd's status
\t-zonegroup [zonegroup]\tshow zone groups
\t-zonelog\t\tset a zone's log level
\t-zonestatus\t\tget status of zones
\t-zsargs <args> <zone>\tset zonesigner arguments for zones
\t-Version\t\tdisplay version number
\t-quiet\t\t\tdon't give any output
\t-help\t\t\thelp message''')
        sys.exit(0)

    def showversion(self):
        '''
        Routine: showversion()
        Purpose: Print the version number(s) and exit.
        '''
        print(self.VERS, file=sys.stderr);
        print(self.DTVERS, file=sys.stderr);
        sys.exit(0)

    def showloglevels(self):
        '''
        Routine: showloglevels()
        Purpose: Print the logging levels and exit.
        '''
        levels = self.logstrs  # Valid logging levels.
        print('valid rollerd logging levels:')
        for level in levels:
            if level:
                lnum = self.rolllog_num(level)  # Numeric logging level.
                print('\t%s\t\t(%d)' % (level, lnum))
        sys.exit(0)

    def doopts(self, args):
        '''
        Routine: doopts()
        Purpose: This routine shakes and bakes our command line options.
                 A bunch of option variables are set according to the specified
                 options.  Then a little massaging is done to make sure that
                 the proper actions are taken.  A few options imply others, so
                 the implied options are set if the implying options are given.
        args - Command line arguments.
        '''
        # Give a usage flag if there aren't any options.
        if not args:
            self.usage()

        # Parse the options.
        self.opts = self.get_options(self.opts, sys.argv[1:]) or self.usage()

        # Give a usage flag if asked.
        if self.opts['help']:
            self.usage()

        # Set our option variables based on the parsed options.
        self.quiet = self.opts['quiet']

        # Command Options
        if self.opts['display']:
            self.dispflag = self.opts['display']
            self.commandcount += 1
        if self.opts['dspub']:
            self.dspubflag = opts['dspub']
            self.commandcount += 1
        if self.opts['dspuball']:
            self.dspuballflag = self.opts['dspuball']
            self.commandcount += 1
        if self.opts['group']:
            self.groupflag = self.opts['group']
        if self.opts['logfile']:
            self.logfileflag = self.opts['logfile']
            self.commandcount += 1
        if self.opts['loglevel']:
            self.loglevelflag = self.opts['loglevel']
            self.commandcount += 1
        if self.opts['logtz']:
            self.logtzflag = self.opts['logtz']
            self.commandcount += 1
        if self.opts['mergerrfs']:
            self.mergerrfsflag = True
            self.commandcount += 1
        if self.opts['nodisplay']:
            self.nodispflag = self.opts['nodisplay']
            self.commandcount += 1
        if self.opts['phasemsg']:
            self.logphasemsg = self.options['phasemsg']
            self.commandcount += 1
        if self.opts['pidfile']:
            self.pidfile = self.opts['pidfile']
        if self.opts['queuelist']:
            self.queuelistflag = self.opts['queuelist']
            self.commandcount += 1
        if self.opts['queuestatus']:
            self.queuestatusflag = self.opts['queuestatus']
            self.commandcount += 1
        if self.opts['rollall']:
            self.rollallflag = self.opts['rollall']
            self.commandcount += 1
        if self.opts['rollallksks']:
            self.krollallflag = self.opts['rollallksks']
            self.commandcount += 1
        if self.opts['rollallzsks']:
            self.zrollallflag = self.opts['rollallzsks']
            self.commandcount += 1
        if self.opts['rollksk']:
            self.rollkskflag = self.opts['rollksk']
            self.commandcount += 1
        if self.opts['rollrec']:
            self.rollrecflag = self.opts['rollrec']
            self.commandcount += 1
        if self.opts['rollzone']:
            self.rollzoneflag = self.opts['rollzone']
            self.commandcount += 1
        if self.opts['rollzsk']:
            self.rollzskflag = self.opts['rollzsk']
            self.commandcount += 1
        if self.opts['runqueue']:
            self.runqueueflag = self.opts['runqueue']
            self.commandcount += 1
        if self.opts['shutdown'] or self.opts['halt']:
            self.shutdownflag = 1
            if self.opts['shutdown'] == 'now' or self.opts['halt'] == 'now':
                self.shutdownflag = 2
            self.commandcount += 1
        if self.opts['signzone']:
            self.signzoneflag = self.opts['signzone']
            self.commandcount += 1
        if self.opts['signzones']:
            self.signzonesflag = self.opts['signzones']
            self.commandcount += 1
        if self.opts['skipall']:
            self.skipallflag = self.opts['skipall']
            self.commandcount += 1
        if self.opts['skipzone']:
            self.skipzoneflag = self.opts['skipzone']
            self.commandcount += 1
        if self.opts['sleeptime']:
            self.sleeptimeflag = self.opts['sleeptime']
            self.commandcount += 1
        if self.opts['splitrrf']:
            self.splitrrfflag = 1
            self.commandcount += 1
        if self.opts['status']:
            self.statusflag = self.opts['status']
            self.commandcount += 1
        if self.opts['zonegroup']:
            self.zonegroupflag = self.opts['zonegroup']
            self.commandcount += 1
        if self.opts['zonelog']:
            self.zonelogflag = self.opts['zonelog']
            self.commandcount += 1
        if self.opts['zonestatus']:
            self.zonestatflag = self.opts['zonestatus']
            self.commandcount += 1
        if self.opts['zsargs']:
            self.zsargsflag = self.opts['zsargs']
            self.commandcount += 1
        if self.opts['Version']:
            self.version = self.opts['Version']
            self.commandcount += 1

        # Ensure that only one command argument was given.
        # We'll get rid of the non-command options before checking.
        if self.commandcount > 1:
            print(
                'only one command argument may be specified per execution',
                file=sys.stderr)
            sys.exit(3)
        elif self.commandcount < 1:
            print('a command argument must be specified', file=sys.stderr)
            sys.exit(3)

        # Close our output descriptors if the -quiet option was given.
        if self.quiet:
            # NOT IMPLEMENTED
            pass

        # Show the version number if requested.
        if self.version:
            self.showversion()

        # Show the logging levels if one wasn't specified.
        # if not self.opts['loglevel']:
        #     self.showloglevels()

        # Ensure that conflicting options weren't given.
        if self.dispflag and self.nodispflag:
            print('-display and -nodisplay are mutually exclusive')
            sys.exit(1)

    def sendcmd(self, cmd, arg=None):
        '''
        Routine: sendcmd()
        Purpose: Send the command to rollerd.  We'll also prepend the
                 group-command indicator if -group was given.
        cmd - Command to send rollerd.
        arg - Command's optional argument.
        '''
        if self.groupflag:
            cmd = ROLLMGR_GROUP + cmd

        return self.rollmgr_sendcmd(CHANNEL_WAIT, cmd, arg)

    def main(self, args):
        rcret = 0  # Return code for rollctl.

        # Check our options.  All the commands are alphabetized, except
        # for shutdown.  We'll save that for last.
        self.doopts(args[1:])

        # If rollerd isn't running, we'll give an error message and exit.
        # Some rollmgr_running() implementations may not be fool-proof.
        if not self.rollmgr_running():
            print('rollerd is not running', file=sys.stderr)
            sys.exit(200)

        # Send commands for all the specified options.
        if self.dispflag:
            if not self.sendcmd(ROLLCMD_DISPLAY, 1):
                print('pyrollctl:  error sending command DISPLAY', file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollerd display started')
            else:
                print('rollerd display not started')
                rcret += 1
        elif self.dspubflag:
            if not args[2:]:
                print('pyrollctl: -dspub missing zone argument', file=sys.stderr)
                sys.exit(1)
            for zone in args[2:]:
                if not self.sendcmd(ROLLCMD_DSPUB, zone):
                    print(
                        'pyrollctl:  error sending command DSPUB(%s)' % zone,
                        file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print(
                        'rollerd informed that parent has published DS '
                        'record for zone %s' % zone)
                else:
                    print(resp)
                    rcret += 1
        elif self.dspuballflag:
            if not self.sendcmd(ROLLCMD_DSPUBALL, self.dspuballflag):
                print(
                    'pyrollctl:  error sending command DSPUBALL',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print(
                    'rollerd informed that parents have published DS '
                    'record for all zones in KSK rollover phase 5')
            else:
                print(resp)
                rcret += 1
        elif self.logfileflag:
            if not self.sendcmd(ROLLCMD_LOGFILE, self.logfileflag):
                print(
                    'pyrollctl:  error sending command LOGFILE',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollerd log file set to %s' % self.logfileflag)
            else:
                print('log-level set failed:  %s' % resp)
                rcret += 1
        elif self.loglevelflag:
            if not self.rolllog_validlevel(self.loglevelflag):
                print(
                    'invalid rollerd log level: %s' % self.loglevelflag,
                    file=sys.stderr)
                rcret += 1
            else:
                if not self.sendcmd(ROLLCMD_LOGLEVEL, self.loglevelflag):
                    print(
                        'pyrollctl:  error sending command LOGLEVEL',
                        file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print(
                        'rollerd log level set to %s' % self.loglevelflag,
                        file=sys.stderr)
                else:
                    print('log-level set failed:  %s' % resp)
                    rcret += 1
        elif self.logtzflag:
            if not self.sendcmd(ROLLCMD_LOGTZ, self.logtzflag):
                print('pyrollctl:  error sending command LOGTZ', file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollerd log timezone set to %s' % logtzflag)
            else:
                print('log-tz set failed:  %s' % resp)
                rcret += 1
        elif self.logphasemsg:
            if self.logphasemsg not in ('long', 'short'):
                print(
                    'invalid rollerd phase-message length: %s' %
                    self.logphasemsg,
                    file=sys.stderr)
                rcret += 1
            else:
                if not self.sendcmd(ROLLCMD_PHASEMSG, self.logphasemsg):
                    print(
                        'pyrollctl:  error sending command PHASEMSG',
                        file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print('rollerd phasemsg to %s' % self.logphasemsg)
                else:
                    print('phasemsg set failed:  %s' % resp)
                    rcret += 1
        elif self.mergerrfsflag:
            rrfs = ':'.join(args[2:]);
            if not self.sendcmd(ROLLCMD_MERGERRFS, rrfs):
                print(
                    'pyrollctl:  error sending command MERGERRFS',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollerd merged the rollrec files')
            else:
                print('rollerd did not merge the rollrec files')
                rcret += 1
        elif self.nodispflag:
            if not self.sendcmd(ROLLCMD_DISPLAY, 0):
                print('pyrollctl:  error sending command DISPLAY', file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollerd display stopped')
            else:
                print('rollerd display not stopped')
                rcret += 1
        elif self.rollallflag:
            if not self.sendcmd(ROLLCMD_ROLLALL):
                print('pyrollctl:  error sending command ROLLALL', file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('all suspended zones now resumed:  %s' % resp)
            else:
                print(resp)
                rcret += 1
        elif self.krollallflag:
            if not self.sendcmd(ROLLCMD_ROLLALLKSKS):
                print(
                    'pyrollctl:  error sending command ROLLALLKSKS',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('all zones now in KSK rollover:  %s' % resp)
            else:
                print(resp)
                rcret += 1
        elif self.zrollallflag:
            if not self.sendcmd(ROLLCMD_ROLLALLZSKS):
                print(
                    'pyrollctl:  error sending command ROLLALLZSKS',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('all zones now in ZSK rollover:  %s' % resp)
            else:
                print(resp)
                rcret += 1
        elif self.rollrecflag:
            if not self.sendcmd(ROLLCMD_ROLLREC, self.rollrecflag):
                print(
                    'pyrollctl:  error sending command ROLLREC',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollerd now using rollrec file %s' % self.rollrecflag)
            else:
                print('couldn\'t set rollrec file:  %s' % resp)
                rcret += 1
        elif self.rollkskflag:
            if not args[2:]:
                print('pyrollctl: -rollksk missing zone argument', file=sys.stderr)
                sys.exit(2)
            for zone in args[2:]:
                if not self.sendcmd(ROLLCMD_ROLLKSK, zone):
                    print(
                        'pyrollctl:  error sending command ROLLKSK(%s)' % zone,
                        file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print(resp)
                else:
                    print(
                        'unable to force KSK rollover process for %s:  %s' %
                        (zone, resp))
                    rcret += 1
        elif self.rollzoneflag:
            if not args[2:]:
                print(
                    'pyrollctl: -rollzone missing zone argument',
                    file=sys.stderr)
                sys.exit(2)
            for zone in args[2:]:
                if not self.sendcmd(ROLLCMD_ROLLZONE, zone):
                    print(
                        'pyrollctl:  error sending command ROLLZONE(%s)' % zone,
                        file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print('rollover restarted for zone %s' % zone)
                else:
                    print(
                        'unable to restart rollover for zone %s:  "%s"' %
                        (zone, resp))
                    rcret += 1
        elif self.rollzskflag:
            if not args[2:]:
                print('pyrollctl: -rollzsk missing zone argument', file=sys.stderr)
                sys.exit(2)
            for zone in args[2:]:
                if not self.sendcmd(ROLLCMD_ROLLZSK, zone):
                    print(
                        'pyrollctl:  error sending command ROLLZSK(%s)' % zone,
                        file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print(resp)
                else:
                    print(
                        'unable to force ZSK rollover process for %s:  %s' %
                        (zone, resp))
                    rcret += 1
        elif self.runqueueflag:
            if not self.sendcmd(ROLLCMD_RUNQUEUE):
                print(
                    'pyrollctl:  error sending command RUNQUEUE',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollerd checking rollrec queue')
            else:
                # Shouldn't ever get here...
                print('couldn\'t force the rollrec queue:  %s' % resp)
                rcret += 1
        elif self.queuelistflag:
            if not self.sendcmd(ROLLCMD_QUEUELIST):
                print(
                    'pyrollctl:  error sending command QUEUELIST',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print(resp)
            else:
                print('rollerd error response:  <%s>' % resp)
                rcret += 1
        elif self.queuestatusflag:
            if not self.sendcmd(ROLLCMD_QUEUESTATUS):
                print(
                    'pyrollctl:  error sending command QUEUESTATUS',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print(resp)
            else:
                print('rollerd error response:  <%s>' % resp)
                rcret += 1
        elif self.signzoneflag:
            if not args[2:]:
                print(
                    'pyrollctl: -signzone missing zone argument',
                    file=sys.stderr)
                sys.exit(2)
            for zone in args[2:]:
                if not self.sendcmd(ROLLCMD_SIGNZONE, zone):
                    print(
                        'pyrollctl:  error sending command SIGNZONE(%s)' % zone,
                        file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print('zone %s signed' % zone)
                else:
                    print('unable to sign zone %s:  "%s"' % (zone, resp))
                    rcret += 1
        elif self.signzonesflag:
            flag = args[2]
            if flag not in ('all', 'active'):
                print(
                    'pyrollctl:  -signzones must be given the "all" or '
                    '"active" argument',
                    file=sys.stderr)
                sys.exit(1)
            if not self.sendcmd(ROLLCMD_SIGNZONES, flag):
                print(
                    'pyrollctl:  error sending command SIGNZONES',
                    file=sys.stderr)
                exit(1);
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('all zones signed')
            else:
                print('unable to sign all zones:  "%s"' % resp)
                rcret += 1
        elif self.skipallflag:
            if not self.sendcmd(ROLLCMD_SKIPALL, self.skipzoneflag):
                print(
                    'pyrollctl:  error sending command SKIPALL',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollover stopped for all zones:  %s\n' % resp)
            else:
                print(resp)
                rcret += 1
        elif self.skipzoneflag:
            if not args[2:]:
                print(
                    'pyrollctl: -skipzone missing zone argument',
                    file=sys.stderr)
                sys.exit(2)
            for zone in args[2:]:
                if not self.sendcmd(ROLLCMD_SKIPZONE, zone):
                    print(
                        'pyrollctl:  error sending command SKIPZONE(%s)' % zone,
                        file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print('rollover stopped for zone %s' % zone)
                else:
                    print('unable to stop rollover for zone $zone:  "%s"' % resp)
                    rcret += 1
        elif self.sleeptimeflag:
            if not self.sendcmd(ROLLCMD_SLEEPTIME, self.sleeptimeflag):
                print(
                    'pyrollctl:  error sending command SLEEPTIME',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollerd sleep time set to %d' % sleeptimeflag)
            else:
                print('sleep-time set failed:  "%s"' % resp)
                rcret += 1
        elif self.splitrrfflag:
            rrfs = ':'.join(args[2:])
            if not self.sendcmd(ROLLCMD_SPLITRRF, rrfs):
                print(
                    'pyrollctl:  error sending command SPLITRRF',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print('rollerd split the rollrec file')
            else:
                print('rollerd did not split the rollrec files')
                rcret += 1
        elif self.statusflag:
            if not self.sendcmd(ROLLCMD_STATUS):
                print(
                    'pyrollctl:  error sending command ZONELOG',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print(resp)
            else:
                print('status failed:  "%s"' % resp)
                rcret += 1
        elif self.shutdownflag:
            if self.shutdownflag == 2:
                pid = self.rollmgr_getid()
                try:
                    os.kill(pid, signal.SIGINT)
                except OSError:
                    print(
                        'pyrollctl:  unable to send immediate SHUTDOWN',
                        file=sys.stderr)
                    sys.exit(1)
                else:
                    print(
                        'pyrollctl:  immediate SHUTDOWN notice sent to rollerd')
                    sys.exit(0)
            if not self.sendcmd(ROLLCMD_SHUTDOWN):
                print(
                    'pyrollctl:  error sending command SHUTDOWN',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                print(resp)
            else:
                print('shutdown failed:  "%s"' % resp)
                rcret += 1
        elif self.zonegroupflag:
            if not self.sendcmd(ROLLCMD_ZONEGROUP, self.zonegroupflag):
                print(
                    'pyrollctl:  error sending command ZONEGROUP',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp(self.zonegroupflag)
            if ret == ROLLCMD_RC_OKAY:
                print(resp)
            else:
                print(resp)
                rcret += 1
        elif self.zonelogflag:
            if not args[2:]:
                print(
                    'pyrollctl: -zonelog missing zone:loglevel argument',
                    file=sys.stderr)
                sys.exit(2)
            for zone in args[2:]:
                if not re.match(r'.+\:.+', zone):
                    print(
                        'pyrollctl:  improperly formed zone:loglevel pair',
                        file=sys.stderr)
                    continue
                if not self.sendcmd(ROLLCMD_ZONELOG, zone):
                    print(
                        'pyrollctl:  error sending command ZONELOG(%s)' % zone,
                        file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print('rollerd logging changed for %s' % zone)
                else:
                    print('zonelog failed:  %s' % resp)
                    rcret += 1
        elif self.zonestatflag:
            if not self.sendcmd(ROLLCMD_ZONESTATUS):
                print(
                    'pyrollctl:  error sending command ZONESTATUS',
                    file=sys.stderr)
                sys.exit(1)
            ret, resp = self.rollmgr_getresp()
            if ret == ROLLCMD_RC_OKAY:
                self.zonestatus(resp)
            else:
                print('zonestatus failed:  "%s"' % resp)
                rcret += 1
        elif self.zsargsflag:
            if not args[2:]:
                print(
                    'zoneargs failed:  arguments are required', file=sys.stderr)
                sys.exit(2)
            else:
                # Zonesigner arguments.
                zsargs = ','.join(args[2:])
                if not self.sendcmd(ROLLCMD_ZSARGS, zsargs):
                    print('pyrollctl:  error sending command ZSARGS', file=sys.stderr)
                    sys.exit(1)
                ret, resp = self.rollmgr_getresp()
                if ret == ROLLCMD_RC_OKAY:
                    print(resp)
                else:
                    print('zsarg failed:  "%s"' % resp)
                    rcret += 1
        return rcret
