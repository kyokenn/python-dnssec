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

from .defs import *
from .rolllog import *


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
