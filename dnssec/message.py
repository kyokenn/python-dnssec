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

from .defs import *
from .rolllog import *


class MessageMixin(object):
    def usage(self):
        ''' Print a usage message and exit. '''
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

    def parameters(self):
        ''' Print the parameters and exim. '''
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

    def bootmsg(self, bootflag):
        '''
        Write a start-up message to the log.
        @param bootflag: Boot flag.
        @type bootflag: bool
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
