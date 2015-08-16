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
    RRLOCK = None

    def rollrec_lock(self):
        '''
        Routine: rollrec_lock()
        Purpose: Lock rollrec processing so that only one process reads a
                 rollrec file at a time.

                 The actual rollrec file is not locked; rather, a synch-
                 ronization file is locked.  We lock in this manner due to
                 the way the rollrec module's functionality is spread over
                 a set of routines.
        rrf - rollrec file.
        '''
        # Open (and create?) our lock file.
        if not self.RRLOCK:
            self.RRLOCK = open('/run/dnssec-tools/rollrec.lock', 'w+')
        # Lock the lock file.
        fcntl.flock(self.RRLOCK, fcntl.LOCK_EX)

    def rollrec_unlock(self):
        '''
        Routine: rollrec_unlock()
        Purpose: Unlock rollrec processing so that other processes may read
                 a rollrec file.
        '''
        # Unlock the lock file.
        fcntl.flock(self.RRLOCK, fcntl.LOCK_UN)

    def rollrec_read(self, rrf):
        if os.path.exists(rrf) and os.path.isfile(rrf):
            self.rollrec = RollRec()
            self.rollrec.read(rrf)
            return True
        else:
            return False

    def rollrec_write(self, rrf):
        self.rollrec.write(rrf)

    def rollrec_close(self):
        pass

    def rollrec_names(self):
        return self.rollrec.keys()

    def rollrec_fullrec(self, rname):
        return self.rollrec[rname]
