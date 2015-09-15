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

import fcntl
import os

from .parsers.rollrec import RollRec


class RollRecMixin(object):
    ROLLREC = None
    RRLOCK = None

    def rollrec_lock(self):
        '''
        Lock rollrec processing so that only one process reads a
        rollrec file at a time.

        The actual rollrec file is not locked; rather, a synch-
        ronization file is locked.  We lock in this manner due to
        the way the rollrec module's functionality is spread over
        a set of routines.
        '''
        # Open (and create?) our lock file.
        if not self.RRLOCK:
            if not os.path.exists('/run/dnssec-tools'):
                os.mkdir('/run/dnssec-tools')
            self.RRLOCK = open(
                self.lockfile or '/run/dnssec-tools/rollrec.lock', 'w')
            # self.RRLOCK.write(' ')
            # self.RRLOCK.flush()
        # Lock the lock file.
        fcntl.flock(self.RRLOCK, fcntl.LOCK_EX)

    def rollrec_unlock(self):
        '''
        Unlock rollrec processing so that other processes may read
        a rollrec file.
        '''
        # Unlock the lock file.
        fcntl.flock(self.RRLOCK, fcntl.LOCK_UN)

    def rollrec_read(self):
        '''
        Read a DNSSEC-Tools rollrec file.
        '''
        if os.path.exists(self.rollrecfile) and os.path.isfile(self.rollrecfile):
            self.ROLLREC = RollRec()
            self.ROLLREC.read(self.rollrecfile)
            return True
        else:
            return False

    def rollrec_close(self):
        '''
        Save the roll record file and close the descriptor.
        '''
        self.rollrec_write()
        self.ROLLREC = None

    def rollrec_write(self, writecmds=False):
        '''
        Save the roll record file and leave the file handle open.
        We'll get an exclusive lock on the rollrec file in order
        to (try to) ensure we're the only ones writing the file.

        We'll make a (hopefully atomic) copy of the in-core rollrec
        lines prior to trying to write.  This is an attempt to
        keep the data from being mucked with while we're using it.
        '''
        self.ROLLREC.write(self.rollrecfile)

    def rollrec_names(self):
        '''
        Smoosh the rollrec names into an array and return the array.
        The name of the informational rollrec willnot be returned.

        @returns: tuple of rollrec names
        @rtype: tuple
        '''
        return tuple(zip(*filter(
            lambda x: x[1].name != 'info rollrec', self.ROLLREC.items())))[0]

    def rollrec_fullrec(self, rname):
        '''
        Return all entries in a given rollrec.

        @returns: rollrec
        @rtype: RollRec
        '''
        return self.ROLLREC[rname]
