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
    def cmd_status(self, data):
        '''
        Routine: cmd_status()
        Purpose: Give a caller some rollerd settings.
        data - Command's data.
        '''
        # my $lfile;                  # Log file.
        # my $lvl;                    # Logging level.
        # my $lvlstr;                 # Logging level string.
        # my $tz;                     # Logging timezone.
        outbuf = ''  # Response buffer.

        # Get the info to report.
        # $lfile  = rolllog_file();
        # $lvl    = rolllog_level();
        # $lvlstr = rolllog_str($lvl);
        # $tz     = rolllog_gettz();

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
