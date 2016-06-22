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

import time
import signal
import sys

from .. import rollmgr
from ..rolllog import LOG


class DaemonMixin(object):
    def commander(self):
        '''
        Get any commands sent to rollerd's command socket.
        '''
        gstr = rollmgr.ROLLMGR_GROUP  # Group command indicator.
        self.rolllog_log(LOG.TMI, '<command>', 'checking commands')

        # Read and handle all the commands we've been sent.
        while 42:
            # Get the command, return if there wasn't one.
            cmd, data = self.rollmgr_getcmd(5)
            if not cmd:
                return

            self.rolllog_log(LOG.TMI, '<command>', 'cmd   - "%s"' % cmd)
            if data:
                self.rolllog_log(LOG.TMI, '<command>', 'data  - "%s"' % data)

            # Deal with the command as zone-related or as a group command.
            if cmd.startswith(gstr):
                cmd = cmd[len(gstr):]
                self.groupcmd(cmd, data)
            else:
                if self.singlecmd(cmd, data):
                    break
            self.rollmgr_closechan()

    def intcmd_handler(self):
        ''' Handle an interrupt and get a command. '''
        self.rolllog_log(
            LOG.TMI, '<command>',
            'rollover manager:  got a command interrupt\n')
        self.controllers(False)
        self.commander()
        self.controllers(True)

    def halt_handler(self):
        ''' Handle the "halt" command. '''
        self.rolllog_log(LOG.ALWAYS, '', 'rollover manager shutting down...\n')
        # self.rollrec_write()   # dump the current file with commands
        sys.exit(0)

    def queue_int_handler(self):
        ''' Remember that a sig INT was received for later processing. '''
        self.queued_int = True

    def queue_hup_handler(self):
        ''' Remember that a sig HUP was received for later processing. '''
        self.queued_hup = True

    def controllers(self, onflag):
        '''
        Initialize handlers for our externally provided commands.

        @param onflag: Handler on/off flag.
        @type onflag: bool
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
        self.rolllog_log(
            LOG.TMI, '', 'sleeping for %s seconds' % self.sleeptime)
        self.sleepcnt = 0
        while self.sleepcnt < self.sleeptime:
            nap = self.sleeptime - self.sleepcnt
            self.sleepcnt += nap
            time.sleep(nap)
