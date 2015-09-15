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

import os

from ..defs import *
from ..rolllog import *


class CmdMixin(object):
    def groupcmd(self, cmd, data):
        '''
        Execute a command for each zone in a zone group.

        @param cmd: Client's command.
        @type cmd: str
        @param data: Command's data.
        @type data: str
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
        Execute a single command.

        @param cmd: Client's command.
        @type cmd: str
        @param data: Command's data.
        @type data: str

        @returns: status
        @rtype: bool
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

    def cmd_status(self, data):
        '''
        Give a caller some rollerd settings.

        @param data: Command's data.
        @type data: str
        '''
        outbuf = ''  # Response buffer.

        # Build status report.
        outbuf = '''boot-time:\t%(boottime)s
realm:\t\t%(realm)s
directory:\t%(curdir)s
rollrec file:\t%(rollrecfile)s
config file:\t%(dtconfig)s
logfile:\t%(lfile)s
loglevel:\t%(lvl)s
logtz:\t\t%(tz)s
always-sign:\t%(alwayssign)s
autosign:\t%(autosign)s
zone reload:\t%(zoneload)s
''' % {
            'boottime': self.boottime.strftime('%Y-%m-%d %H:%M:%S'),
            'realm': self.realm or '-',
            'curdir': os.getcwd(),
            'rollrecfile': self.rollrecfile,
            'dtconfig': self.dtconfig,
            'lfile': self.logfile,
            'lvl': self.loglevel,
            'tz': self.usetz,
            'alwayssign': self.alwayssign,
            'autosign': self.autosign,
            'zoneload': self.zoneload,
        }

        if self.eventmaster == EVT_FULLLIST:
            outbuf += 'sleeptime:\t%s\n' % self.sleeptime
        outbuf += 'event method:\t%s\n' % self.event_methods[self.eventmaster]

        if self.username:
            outbuf += 'running as:\t%s\n' % self.username

        outbuf += '''
%s
%s
''' % (self.VERS, self.DTVERS)

        # Send the status report to the caller.
        self.rolllog_log(LOG_TMI, '<command>', 'status command received')
        self.rollmgr_sendresp(ROLLCMD_RC_OKAY, outbuf)

    def cmd_signzone(self, zone):
        '''
        This command causes a zone signing, without any key creation or rolling.

        @param zone: Command's data.
        @type zone: str
        '''
        self.rolllog_log(LOG_TMI, '<command>', 'signzone command received')

        # Get the current phase values for the zone.
        self.rollrec_read()
        rrr = self.rollrec_fullrec(zone)
        krr = rrr.keyrec()

        # Sign the zone.
        self.rolllog_log(
            LOG_PHASE, '<command>',
            'mid-phase, user-initiated signing of %s' % zone)
        if self.signer(zone, rrr.phaseargs, krr):
            self.rolllog_log(
                LOG_TMI, '<command>', 'rollerd signed zone %s' % zone)
            self.rollmgr_sendresp(
                ROLLCMD_RC_OKAY, 'rollerd signed zone %s' % zone)
        else:
            self.rolllog_log(
                LOG_ERR, '<command>', 'unable to sign zone %s' % zone)
            self.rollmgr_sendresp(
                ROLLCMD_RC_BADZONE, 'unable to sign zone %s' % zone)

    def cmd_signzones(self, skipflag):
        '''
        This command causes all unskipped zones to be signed, without
        any key creation or rolling.

        @param skipflag: Command's data.
        @type skipflag: str
        '''
        errzones = []  # Unsigned zones.

        self.rolllog_log(
            LOG_TMI, '<command>',
            'signzones command received; data - "%s"' % skipflag)

        # Convert the textual zone-skip flag into an easy-to-use boolean.
        skipflag = skipflag == 'active'

        # Sign each active zone in the rollrec file.  Any skipped zones will
        # not be signed.
        self.rollrec_read()
        for zone in self.rollrec_names():
            # Get the current rollrec for this zone and (maybe) skip
            # any skipped zones.
            rrr = self.rollrec_fullrec(zone)
            if skipflag and not rrr.is_active:
                continue

            # Sign the zone.
            self.rolllog_log(LOG_PHASE,'<command>',"mid-phase, user-initiated signing of $zone");
            krr = rrr.keyrec()
            if not self.signer(zone, rrr.phaseargs, krr):
                errzones.append(zone)

        # If we signed all the zones, we'll send a success message.
        # If we couldn't sign any zones, we'll return the list of bad
        # zones to the caller.
        if not errzones:
            self.rolllog_log(LOG_TMI, '<command>', 'rollerd signed all zones')
            self.rollmgr_sendresp(ROLLCMD_RC_OKAY, 'rollerd signed all zones')
        else:
            errstr = ', '.join(errzones)
            self.rolllog_log(LOG_ERR, '<command>', 'unable to sign all zones:  %s' % errstr)
            self.rollmgr_sendresp(ROLLCMD_RC_BADZONE, 'unable to sign all zones:  %s' % errstr)

    def cmd_rollnow(self, zone, rolltype):
        '''
        This command moves a zone into immediate KSK or ZSK rollover.
        It calls rollnow() to move the zone into immediate rollover.

        @param zone: Command's data.
        @type zone: str
        @param rolltype: 'KSK' or 'ZSK'
        @type rolltype: str
        '''
        self.rolllog_log(
            LOG_TMI, '<command>', 'roll%s command received; zone - "%s"' %
            (rolltype.lower(), zone))

        # Get the zone's rollrec.
        self.rollrec_read()
        rrr = self.rollrec_fullrec(zone)
        if not rrr:
            self.rolllog_log(
                LOG_ERR, '<command>', 'no rollrec defined for zone %s' % zone)
            self.rollmgr_sendresp(
                ROLLCMD_RC_BADZONE, '%s not in rollrec file %s' %
                (zone, self.rollrecfile))
            return 0

        # Don't proceed if this zone is in the middle of KSK rollover.
        if rrr.kskphase > 0:
            self.rolllog_log(
                LOG_TMI, '<command>',
                'in KSK rollover (phase %d; not attempting ZSK rollover' %
                rrr.kskphase)
            self.rollmgr_sendresp(
                ROLLCMD_RC_KSKROLL,
                '%s is already engaged in a KSK rollover' % zone)
            return 0

        # Don't proceed if this zone is in the middle of ZSK rollover.
        if rrr.zskphase > 0:
            self.rolllog_log(
                LOG_TMI, '<command>',
                'in ZSK rollover (phase %d; not attempting ZSK rollover' %
                rrr.zskphase)
            self.rollmgr_sendresp(
                ROLLCMD_RC_ZSKROLL,
                '%s is already engaged in a ZSK rollover' % zone)
            return 0

        # Do the rollover and send an appropriate response.
        rollret = self.rollnow(zone, rolltype, 1)
        if rollret == 1:
            self.rollmgr_sendresp(
                ROLLCMD_RC_OKAY, '%s %s rollover started' % (zone, rolltype))
        elif rollret == 0:
            self.rolllog_log(
                LOG_ERR, '<command>', '%s not in rollrec file %s' %
                (zone, self.rollrecfile))
            self.rollmgr_sendresp(
                ROLLCMD_RC_BADZONE, '%s not in rollrec file %s' %
                (zone, self.rollrecfile))
        elif rollret == -1:
            self.rolllog_log(
                LOG_ERR, '<command>', '%s has bad values in rollrec file %s' %
                (zone, self.rollrecfile))
            self.rollmgr_sendresp(
                ROLLCMD_RC_BADZONEDATA, '%s has bad values in rollrec file %s' %
                (zone, self.rollrecfile))
