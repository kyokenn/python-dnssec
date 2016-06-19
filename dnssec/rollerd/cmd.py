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

from .. import defs
from ..rolllog import LOG


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
            self.singlecmd(cmd, data)
            return

        # Run the named command on each zone in the specified zone group.
        rollrec = self.rollrec_read()

        # For each rollrec entry, get the keyrec file and mark its zone
        # entry as being controlled by us.
        rollrec = self.rollrec_read()
        for zn, rrr in rollrec.rolls():
            self.singlecmd(cmd, zn)

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
        if cmd == defs.ROLLCMD_DISPLAY:
            self.cmd_display(data)
        elif cmd == defs.ROLLCMD_DSPUB:
            self.cmd_dspub(data)
        elif cmd == defs.ROLLCMD_DSPUBALL:
            self.cmd_dspuball()
        elif cmd == defs.ROLLCMD_LOGFILE:
            self.cmd_logfile(data)
        elif cmd == defs.ROLLCMD_LOGLEVEL:
            self.cmd_loglevel(data)
        elif cmd == defs.ROLLCMD_LOGMSG:
            self.cmd_logmsg(data)
        elif cmd == defs.ROLLCMD_LOGTZ:
            self.cmd_logtz(data)
        elif cmd == defs.ROLLCMD_MERGERRFS:
            self.cmd_mergerrfs(data)
        elif cmd == defs.ROLLCMD_PHASEMSG:
            self.cmd_phasemsg(data)
        elif cmd == defs.ROLLCMD_ROLLALL:
            self.cmd_rollall()
        elif cmd == defs.ROLLCMD_ROLLALLKSKS:
            self.cmd_rollallksks()
        elif cmd == defs.ROLLCMD_ROLLALLZSKS:
            self.cmd_rollallzsks()
        elif cmd == defs.ROLLCMD_ROLLREC:
            if self.cmd_rollrec(data):
                return True
        elif cmd == defs.ROLLCMD_ROLLKSK:
            self.cmd_rollnow(data, 'KSK')
        elif cmd == defs.ROLLCMD_ROLLZONE:
            self.cmd_rollzone(data)
        elif cmd == defs.ROLLCMD_ROLLZSK:
            self.cmd_rollnow(data, 'ZSK')
        elif cmd == defs.ROLLCMD_RUNQUEUE:
            self.cmd_runqueue(data)
        elif cmd == defs.ROLLCMD_QUEUELIST:
            self.cmd_queuelist(data)
        elif cmd == defs.ROLLCMD_QUEUESTATUS:
            self.cmd_queuestatus(data)
        elif cmd == defs.ROLLCMD_SHUTDOWN:
            self.cmd_shutdown(data)
        elif cmd == defs.ROLLCMD_SIGNZONE:
            self.cmd_signzone(data)
        elif cmd == defs.ROLLCMD_SIGNZONES:
            self.cmd_signzones(data)
        elif cmd == defs.ROLLCMD_SKIPALL:
            self.cmd_skipall()
        elif cmd == defs.ROLLCMD_SKIPZONE:
            self.cmd_skipzone(data)
        elif cmd == defs.ROLLCMD_SLEEPTIME:
            self.cmd_sleeptime(data)
        elif cmd == defs.ROLLCMD_SPLITRRF:
            self.cmd_splitrrf(data)
        elif cmd == defs.ROLLCMD_STATUS:
            self.cmd_status(data)
        elif cmd == defs.ROLLCMD_ZONEGROUP:
            self.cmd_zonegroup(data)
        elif cmd == defs.ROLLCMD_ZONELOG:
            self.cmd_zonelog(data)
        elif cmd == defs.ROLLCMD_ZONESTATUS:
            self.cmd_zonestatus(data)
        elif cmd == defs.ROLLCMD_ZSARGS:
            self.cmd_zsargs(data)
        else:
            self.rolllog_log(
                LOG.ERR, '<command>', 'invalid command  - "%s"' % cmd)
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
provider:\t%(provider)s
provider key:\t%(provider_key)s
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
            'provider': self.provider,
            'provider_key': bool(self.provider_key),
            'zoneload': self.zoneload,
        }

        if self.eventmaster == defs.EVT_FULLLIST:
            outbuf += 'sleeptime:\t%s\n' % self.sleeptime
        outbuf += 'event method:\t%s\n' % self.event_methods[self.eventmaster]

        if self.username:
            outbuf += 'running as:\t%s\n' % self.username

        outbuf += '''
%s
%s
''' % (self.VERS, self.DTVERS)

        # Send the status report to the caller.
        self.rolllog_log(LOG.TMI, '<command>', 'status command received')
        self.rollmgr_sendresp(defs.ROLLCMD_RC_OKAY, outbuf)

    def cmd_signzone(self, zone):
        '''
        This command causes a zone signing, without any key creation or rolling.

        @param zone: Command's data.
        @type zone: str
        '''
        self.rolllog_log(LOG.TMI, '<command>', 'signzone command received')

        # Get the current phase values for the zone.
        self.rollrec_read()
        rrr = self.rollrec_fullrec(zone)
        krr = rrr.keyrec()

        # Sign the zone.
        self.rolllog_log(
            LOG.PHASE, '<command>',
            'mid-phase, user-initiated signing of %s' % zone)
        if self.signer(zone, rrr.phaseargs, krr):
            self.rolllog_log(
                LOG.TMI, '<command>', 'rollerd signed zone %s' % zone)
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_OKAY, 'rollerd signed zone %s' % zone)
        else:
            self.rolllog_log(
                LOG.ERR, '<command>', 'unable to sign zone %s' % zone)
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_BADZONE, 'unable to sign zone %s' % zone)

    def cmd_signzones(self, skipflag):
        '''
        This command causes all unskipped zones to be signed, without
        any key creation or rolling.

        @param skipflag: Command's data.
        @type skipflag: str
        '''
        errzones = []  # Unsigned zones.

        self.rolllog_log(
            LOG.TMI, '<command>',
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
            self.rolllog_log(
                LOG.PHASE, '<command>',
                'mid-phase, user-initiated signing of %s' % zone)
            krr = rrr.keyrec()
            if not self.signer(zone, rrr.phaseargs, krr):
                errzones.append(zone)

        # If we signed all the zones, we'll send a success message.
        # If we couldn't sign any zones, we'll return the list of bad
        # zones to the caller.
        if not errzones:
            self.rolllog_log(LOG.TMI, '<command>', 'rollerd signed all zones')
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_OKAY, 'rollerd signed all zones')
        else:
            errstr = ', '.join(errzones)
            self.rolllog_log(
                LOG.ERR, '<command>', 'unable to sign all zones:  %s' % errstr)
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_BADZONE,
                'unable to sign all zones:  %s' % errstr)

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
            LOG.TMI, '<command>', 'roll%s command received; zone - "%s"' %
            (rolltype.lower(), zone))

        # Get the zone's rollrec.
        self.rollrec_read()
        rrr = self.rollrec_fullrec(zone)
        if not rrr:
            self.rolllog_log(
                LOG.ERR, '<command>', 'no rollrec defined for zone %s' % zone)
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_BADZONE, '%s not in rollrec file %s' %
                (zone, self.rollrecfile))
            return 0

        # Don't proceed if this zone is in the middle of KSK rollover.
        if rrr.kskphase > 0:
            self.rolllog_log(
                LOG.TMI, '<command>',
                'in KSK rollover (phase %d; not attempting ZSK rollover' %
                rrr.kskphase)
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_KSKROLL,
                '%s is already engaged in a KSK rollover' % zone)
            return 0

        # Don't proceed if this zone is in the middle of ZSK rollover.
        if rrr.zskphase > 0:
            self.rolllog_log(
                LOG.TMI, '<command>',
                'in ZSK rollover (phase %d; not attempting ZSK rollover' %
                rrr.zskphase)
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_ZSKROLL,
                '%s is already engaged in a ZSK rollover' % zone)
            return 0

        # Do the rollover and send an appropriate response.
        rollret = self.rollnow(zone, rolltype, 1)
        if rollret == 1:
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_OKAY, '%s %s rollover started' % (zone, rolltype))
        elif rollret == 0:
            self.rolllog_log(
                LOG.ERR, '<command>', '%s not in rollrec file %s' %
                (zone, self.rollrecfile))
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_BADZONE, '%s not in rollrec file %s' %
                (zone, self.rollrecfile))
        elif rollret == -1:
            self.rolllog_log(
                LOG.ERR, '<command>', '%s has bad values in rollrec file %s' %
                (zone, self.rollrecfile))
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_BADZONEDATA,
                '%s has bad values in rollrec file %s' %
                (zone, self.rollrecfile))

    def cmd_shutdown(self, data):
        ''' This command forces rollerd to shut down. '''
        self.rolllog_log(LOG.TMI, '<command>', 'shutdown command received')
        self.rollmgr_sendresp(defs.ROLLCMD_RC_OKAY, 'rollerd shutting down')
        self.halt_handler()

    def cmd_zonestatus(self, data):
        '''
        Return zone status to the control program.

        @param data: Command's data.
        @type data: str
        '''
        cnt = 0  # Zone count.
        outbuf = ''  # Zone status line.

        self.rolllog_log(LOG.TMI, '<command>', 'zonestatus command received')

        self.rollrec_lock()

        # Read the rollrec file.  If we couldn't, complain and return.
        if not self.rollrec_read():
            self.rollrec_unlock()
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_RRFOPEN,
                'unable to open rollrec file %s' % self.rollrecfile)
            self.rolllog_log(
                LOG.ALWAYS, '<command>',
                'unable to open rollrec file %s' % self.rollrecfile)
            return

        # Add the status of each zone in the rollrec file to our output buffer.
        for rname in self.rollrec_names():
            # Get the rollrec for this name.
            rrr = self.rollrec_fullrec(rname)

            # Get the data we're interested in.
            if rrr.kskphase > 0:
                phase = 'KSK %d' % rrr.kskphase
            else:
                phase = 'ZSK %d' % rrr.zskphase
            pstr = rrr.phase_description

            phase = '%s: %s' % (phase, pstr) if pstr else ''
            if not rrr.is_active:
                phase = '-'

            # Add the data to the output buffer and bump our zone count.
            outbuf += '%s/%s\t%s\t%s\n' % (
                rname, rrr['zonename'], rrr.rollrec_type, phase)
            cnt += 1

        # Send a response to the control program.
        if not cnt:
            self.rollmgr_sendresp(
                defs.ROLLCMD_RC_NOZONES,
                'no zones defined in %s' % self.rollrecfile)
            self.rolllog_log(
                LOG.ALWAYS, '<command>',
                'no zones defined in %s' % self.rollrecfile)
        else:
            self.rollmgr_sendresp(defs.ROLLCMD_RC_OKAY, outbuf)

        self.rollrec_unlock()

    def cmd_rollall(self):
        '''
        This command resumes rollover for all suspended zones in the
        rollrec file.  The zones' rollrec records are marked as being
        "roll" records, which will cause rollerd to start working on
        them.  This change is reflected in the rollrec file.  rollnow()
        is called for each suspended zone, in order to resume rollover.
        We'll also keep track of the suspended zones we were and weren't
        able to stop and report them to the caller.
        '''
        good = []  # Resumed zones.
        bad = []  # Unresumed zones.

        cnt = 0  # Total count.
        gcnt = 0  # Resumed count.
        bcnt = 0  # Unresumed count.

        self.rolllog_log(LOG.TMI, '<command>', 'rollall command received')

        # Each suspended zone in the rollrec file will be returned to the
        # rollover process.  We'll keep track of the suspended zones that were
        # resumed and those that weren't in order to provide an appropriate
        # response message.
        for zone in self.rollrec_names():
            cnt += 1

            # If the resume worked, increment the good count and add
            # the domain name to the list of good zones.  If it didn't
            # work, do the same for the bad count and bad-zone list.
            if self.rollnow(zone, 'restart', 1) == 1:
                gcnt += 1
                good.append(zone)
            else:
                bcnt += 1
                bad.append(zone)

        # Send a response message to the caller.
        if gcnt == cnt:
            self.rollmgr_sendresp(defs.ROLLCMD_RC_OKAY, ' '.join(good))
        else:
            resp = (
                'unable to resume roll process for zones:  %s\n' %
                ' '.join(bad))

            # If there were any zones that were resumed, we'll add them
            # to the message as well.
            if gcnt > 0:
                resp += 'zones now resumed:  %s\n' % ' '.join(good)

            self.rollmgr_sendresp(defs.ROLLCMD_RC_BADZONE, resp)

    def dspubber(self, cmd, zone):
        '''
        cmd - "dspub" or "dspuball"
        '''
        if self.provider and self.provider_key:
            self.rollrec_read()
            rnames = self.rollrec_names()
            if zone in rnames:
                rrr = self.rollrec_fullrec(zone)
                self.rolllog_log(
                    LOG.TMI, zone,
                    'transfering keyset to the parent')
                ret = rrr.dspub(self.provider, self.provider_key)
                if not ret:
                    self.rolllog_log(
                        LOG.ERR, zone, 'keyset transfer failed')

    def cmd_dspub(self, zone):
        '''
        Move a zone from KSK rollover phase 5 to phase 6.
        '''
        self.rolllog_log(
            LOG.TMI, '<command>',
            'dspub command received; zone - \"%s\"' % zone)

        self.dspubber('dspub', zone)

    def cmd_dspuball(self):
        '''
        Move all zones that are currently in KSK rollover phase 5
        to phase 6.
        '''
        self.rolllog_log(LOG.TMI, '<command>', 'dspuball command received')

        self.rollrec_read()
        for zone in self.rollrec_names():
            self.dspubber('dspuball', zone)
