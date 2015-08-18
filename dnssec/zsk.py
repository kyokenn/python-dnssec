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


class ZSKMixin(object):
    def zsk_expired(self, rname, rrr, keyset):
        '''
        This routine returns a boolean indicating if the specified
        zone has an expired ZSK key of the given type.

        The zone's keyrec file name is taken from the given rollrec
        entry.  The keyrec file is read and the zone's entry found.
        The key keyrec of the specified key type (currently, just
        "zskcur") is pulled from the keyrec file.  Each key in the
        named signing set will be checked.

        Key expiration is determined by comparing the key keyrec's
        gensecs field to the current time.  The key hasn't expired
        if the current time is less than the gensecs; the key has
        expired if the current time is greater than the gensecs.

        @param rname: Name of rollrec rec.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll
        @param keyset: Key to check.
        @type keyset: str

        @returns: True if ZSK expired
        @rtype: bool
        '''
        expired = False  # Expired-zone flag.
        starter = 0  # Time 0 for calc'ing rolltime.

        # If this zone is in the middle of KSK rollover, we'll stop
        # working on ZSK rollover.
        if rrr.kskphase > 0:
            self.rolllog_log(
                LOG_TMI, rname,
                'in KSK rollover (phase %d); not attempting ZSK rollover' %
                rrr.kskphase)
            return False

        # If this zone is in the middle of rollover processing, we'll
        # immediately assume the key has expired.
        if rrr.zskphase > 0:
            return True

        # Get the rollin' key's keyrec for our zone.
        krec = getattr(rrr.keyrec()[rname], keyset)
        if not krec:
            self.rolllog_log(
                LOG_ERR, rname,
                'unable to find a keyrec for ZSK "%s" in "%s"' %
                (keyset, rrr.keyrec_path))
            return False

        # Make sure we've got an actual set keyrec and keys.
        if not isinstance(krec, KeySet):
            self.rolllog_log(
                LOG_ERR, rname, '"%s"\'s keyrec is not a set keyrec' %
                keyset)
            return False
        if not krec.keys:
            self.rolllog_log(
                LOG_ERR, rname, '"%s" has no keys; unable to check expiration"' %
                rrr.keyrec_path);
            return False

        # Check each key in the signing set to find the one with the shortest
        # lifespan.  We'll calculate rollover times based on that.
        minhr = krec.minlife_key()
        minlife = minhr.life

        if not minhr:
            self.rolllog_log(
                LOG_ALWAYS, rname,
                '--------> zsk_expired:  couldn\'t find minimum key keyrec')
            return False

        # Get the start time on which the expiration time is based.
        if self.zrollmethod == RM_ENDROLL:
            # Ensure that required rollrec field exists.
            if 'zsk_rollsecs' not in rrr:
                self.rolllog_log(
                    LOG_INFO, rname,
                    'creating new zsk_rollsecs record and forcing ZSK rollover')
                rrr.rollstamp('zsk')
                return False
            starter = int(rrr['zsk_rollsecs'])
        elif self.zrollmethod == RM_KEYGEN:
            # Ensure that required keyrec field exists.
            if 'keyrec_gensecs' not in minkh:
                self.rolllog_log(
                    LOG_ERR, rname,
                    'keyrec does not contain a keyrec_gensecs record')
                return False
            starter = int(minkh['keyrec_gensecs'])
        elif self.zrollmethod == RM_STARTROLL:
            self.rolllog_log(
                LOG_ERR, rname, 'RM_STARTROLL not yet implemented')
            return False

        # Don't roll immediately if the rollrec file was newly created.
        if starter == 0:
            rrr.rollstamp('zsk')
            return False

        # Get the key's expiration time.
        rolltime = starter + minlife

        # Get the current time.
        cronus = time.time()

        # Figure out the log message we should give.
        waitsecs = rolltime - cronus
        if waitsecs >= 0:
            self.rolllog_log(
                LOG_EXPIRE, rname, '        ZSK expiration in %s' %
                datetime.timedelta(seconds=waitsecs))
        else:
            waitsecs = cronus - rolltime
            self.rolllog_log(
                LOG_EXPIRE, rname, '        ZSK expired %s ago' %
                datetime.timedelta(seconds=waitsecs))

        # The keyset has expired if the current time has passed the keyset's
        # lifespan.
        # The keyset has not expired if the keyset's lifespan has yet to reach
        # the current time.
        if cronus > rolltime:
            expired = True

        # If the keyset has not expired and the zone file has been modified,
        # we'll sign the zone file.  We won't created any new keys or take
        # any other rollover actions.
        if not expired:
            self.zonemodified(rrr, rname)

        # Return the success/failure indication.
        return expired

    def zsk_phaser(self, rname, rrr):
        '''
        Move the specified zone's ZSKs through the appropriate phases.

        @param rname: Zone name.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll
        '''
        # Get this rollrec record's current phase.
        ph = rrr.zskphase

        # Work on this rollrec's phase.
        {
            0: lambda: self.phasecmd(self.nextphase, rname, rrr, 'normal', 'zsk'),
            1: lambda: self.phasecmd(self.phasewait, rname, rrr, 'zsk1'),
            2: lambda: self.phasecmd(self.zsk_phase2, rname, rrr, 'zsk2'),
            3: lambda: self.phasecmd(self.phasewait, rname, rrr, 'zsk3'),
            4: lambda: self.phasecmd(self.zsk_phase4, rname, rrr, 'zsk4'),
        }[ph]()
