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
import calendar

from .defs import *
from .rolllog import *
from .parsers.keyrec import KeySet


class KSKMixin(object):
    def ksk_expired(self, rname, rrr, keyset):
        '''
        This routine determines if the specified zone has an expired
        KSK and returns a boolean indicating this.  The given KSK
        type is checked for expiration.

        The zone's keyrec file name is taken from the given rollrec
        entry.  The keyrec file is read and the zone's entry found.
        The key keyrec of the specified key type (currently, just
        "kskcur") is pulled from the keyrec file.  Each key in the
        named signing set will be checked.

        Key expiration is determined by comparing the key keyrec's
        gensecs field to the current time.  The key hasn't expired
        if the current time is less than the gensecs; the key has
        expired if the current time is greater than the gensecs.

        @param rname - Name of rollrec rec.
        @param rrr - Reference to rollrec.
        @param keyset - Key to check.
        '''
        expired = False  # Expired-zone flag.

        # If this zone is in the middle of ZSK rollover, we'll stop
        # working on KSK rollover.
        if int(rrr['zskphase']) > 0:
            self.rolllog_log(
                LOG_TMI, rname,
                'in ZSK rollover (phase %s); not attempting KSK rollover' %
                rrr['zskphase'])
            return False

        # If this zone is in the middle of rollover processing, we'll
        # immediately assume the key has expired.
        if int(rrr['kskphase']) > 0:
            return True

        # Get the rollin' key's keyrec for our zone.
        krec = rrr.keyrec()
        if not krec:
            self.rolllog_log(
                LOG_ERR, rname,
                'unable to find a KSK keyrec for "%s" in "%s"' %
                (rname, rrr.keyrec_path))
            return False

        # Make sure we've got an actual set keyrec and keys.
        if not (krec[rname].kskcur and isinstance(krec[rname].kskcur, KeySet)):
            self.rolllog_log(
                LOG_ERR, rname, '"%s" keyrec is not a set keyrec' %
                krec[rname].kskcur)
            return False
        if not krec[rname].kskcur.keys:
            self.rolllog_log(
                LOG_ERR, rname, '"%s" has no keys; unable to check expiration"' %
                krec[rname].kskcur.name);
            self.zoneerr(rname, rrr)
            return False

        # Check each key in the signing set to find the one with the shortest
        # lifespan.  We'll calculate rollover times based on that.
        minhr = next(iter(sorted(
            krec[rname].kskcur.keys, key=lambda x: x['ksklife'])), None)
        minlife = int(minhr['ksklife'])

        if not minhr:
            self.rolllog_log(
                LOG_ALWAYS, rname,
                '--------> zsk_expired:  couldn\'t find minimum key keyrec')
            return False

        # Get the start time on which the expiration time is based.
        if self.krollmethod == RM_ENDROLL:
            # Ensure that required rollrec field exists.
            if not rrr.get('ksk_rollsecs'):
                self.rolllog_log(
                    LOG_INFO, rname,
                    'creating new ksk_rollsecs record and forcing KSK rollover')
                self.rollstamp(rname, 'ksk')
                return False
            starter = int(rrr['ksk_rollsecs'])
        elif self.krollmethod == RM_KEYGEN:
            # Ensure that required keyrec field exists.
            if minkh.get('keyrec_gensecs'):
                self.rolllog_log(
                    LOG_ERR, rname,
                    'keyrec does not contain a keyrec_gensecs record')
                return False
            starter = int(minkh.get('keyrec_gensecs'))
        elif self.krollmethod == RM_STARTROLL:
            self.rolllog_log(
                LOG_ERR, rname, 'RM_STARTROLL not yet implemented')
            return False

        # Don't roll immediately if the rollrec file was newly created.
        if starter == 0:
            rollstamp(rname, 'ksk')
            return False

        # Get the key's expiration time.
        rolltime = starter + minlife

        # Get the current time.
        cronus = time.gmtime()
        cronus = calendar.timegm(cronus)

        # Figure out the log message we should give.
        waitsecs = rolltime - cronus
        if waitsecs >= 0:
            self.rolllog_log(
                LOG_EXPIRE, rname, '        expiration in %d secs' % waitsecs)
        else:
            waitsecs = cronus - rolltime
            self.rolllog_log(
                LOG_EXPIRE, rname, '        expired %d secs ago' % waitsecs)

        # The key has expired if the current time has passed the key's lifespan.
        # The key has not expired if the key's lifespan has yet to reach the
        # current time.
        if cronus > rolltime:
            expired = True

        # If the keyset has not expired and the zone file has been modified,
        # we'll sign the zone file.  We won't created any new keys or take
        # any other rollover actions.
        if not expired:
            self.zonemodified(rrr, rname)

        # Return the success/failure indication.
        return expired
