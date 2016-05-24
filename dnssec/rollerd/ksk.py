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

import calendar
import datetime
import time
import smtplib

from email.mime.text import MIMEText

from ..defs import *
from ..rolllog import LOG
from ..parsers.keyrec import KeySet


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

        @param rname: Name of rollrec rec.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll
        @param keyset: Key to check.
        @type keyset: str

        @returns: True if KSK expired
        @rtype: bool
        '''
        expired = False  # Expired-zone flag.
        starter = 0  # Time 0 for calc'ing rolltime.

        # If this zone is in the middle of ZSK rollover, we'll stop
        # working on KSK rollover.
        if rrr.zskphase > 0:
            self.rolllog_log(
                LOG.TMI, rname,
                'in ZSK rollover (phase %d); not attempting KSK rollover' %
                rrr.zskphase)
            return False

        # If this zone is in the middle of rollover processing, we'll
        # immediately assume the key has expired.
        if rrr.kskphase > 0:
            return True

        # Get the rollin' key's keyrec for our zone.
        krec = getattr(rrr.keyrec()[rname], keyset)
        if not krec:
            self.rolllog_log(
                LOG.ERR, rname,
                'unable to find a KSK keyrec for "%s" in "%s"' %
                (keyset, rrr.keyrec_path))
            return False

        # Make sure we've got an actual set keyrec and keys.
        if not isinstance(krec, KeySet):
            self.rolllog_log(
                LOG.ERR, rname, '"%s" keyrec is not a set keyrec' %
                keyset)
            return False
        if not krec.keys:
            self.rolllog_log(
                LOG.ERR, rname, '"%s" has no keys; unable to check expiration"' %
                rrr.keyrec_path);
            rrr.zoneerr()
            self.rollrec_write()
            return False

        # Check each key in the signing set to find the one with the shortest
        # lifespan.  We'll calculate rollover times based on that.
        minhr = krec.minlife_key()
        minlife = minhr.life

        # Get the start time on which the expiration time is based.
        if self.krollmethod == RM_ENDROLL:
            # Ensure that required rollrec field exists.
            if 'ksk_rollsecs' not in rrr:
                self.rolllog_log(
                    LOG.INFO, rname,
                    'creating new ksk_rollsecs record and forcing KSK rollover')
                rrr.rollstamp('ksk')
                return False
            starter = int(rrr['ksk_rollsecs'])
        elif self.krollmethod == RM_KEYGEN:
            # Ensure that required keyrec field exists.
            if 'keyrec_gensecs' not in minkh:
                self.rolllog_log(
                    LOG.ERR, rname,
                    'keyrec does not contain a keyrec_gensecs record')
                return False
            starter = int(minkh['keyrec_gensecs'])
        elif self.krollmethod == RM_STARTROLL:
            self.rolllog_log(
                LOG.ERR, rname, 'RM_STARTROLL not yet implemented')
            return False

        # Don't roll immediately if the rollrec file was newly created.
        if starter == 0:
            rrr.rollstamp('ksk')
            return False

        # Get the key's expiration time.
        rolltime = starter + minlife

        # Get the current time.
        cronus = time.time()

        # Figure out the log message we should give.
        waitsecs = rolltime - cronus
        if waitsecs >= 0:
            self.rolllog_log(
                LOG.EXPIRE, rname, '        KSK expiration in %s' %
                datetime.timedelta(seconds=waitsecs))
        else:
            waitsecs = cronus - rolltime
            self.rolllog_log(
                LOG.EXPIRE, rname, '        KSK expired %s ago' %
                datetime.timedelta(seconds=waitsecs))

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

    def ksk_phaser(self, rname, rrr):
        '''
        Move the specified zone's KSKs through the appropriate phases.

            Phases in rollover:
                1 - wait for cache data to expire
                2 - generate a new (published) KSK and load zone
                3 - wait for the old DNSKEY RRset to expire from caches
                4 - transfer new keyset to the parent
                5 - wait for parent to publish DS record
                6 - wait for cache data to expire
                7 - roll the KSKs and load the zone

        @param rname: Zone name.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll
        '''
        # Get this rollrec record's current phase.
        ph = rrr.kskphase

        # Work on this rollrec's phase.
        {
            0: lambda: self.phasecmd(self.nextphase, rname, rrr, 'normal', 'ksk'),
            1: lambda: self.phasecmd(self.phasewait, rname, rrr, 'ksk1'),
            2: lambda: self.phasecmd(self.ksk_phase2, rname, rrr, 'ksk2'),
            3: lambda: self.phasecmd(self.phasewait, rname, rrr, 'ksk3'),
            4: lambda: self.phasecmd(self.ksk_phase4, rname, rrr, 'ksk4'),
            5: lambda: self.phasecmd(self.ksk_phase5, rname, rrr, 'ksk5'),
            6: lambda: self.phasecmd(self.phasewait, rname, rrr, 'ksk6'),
            7: lambda: self.phasecmd(self.ksk_phase7, rname, rrr, 'ksk7'),
        }[ph]()

    def ksk_phase2(self, rname, rrr, *skipargs):
        '''
        Perform the phase 2 steps of the KSK rollover.  These are:
            - generate a new KSK to be the Published KSK
            - add the new Published KSK to the zone file
            - re-sign the zone file with the Current KSK, the (new)
              Published KSK, and the Current ZSK
            - reload the zone file
        The first three steps are handled by zonesigner.

        @param rname: Name of rollrec.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll
        '''
        # Get the rollrec's associated keyrec file and ensure that it exists.
        krf = rrr.keyrec()
        if not rrr['keyrec']:
            self.rolllog_log(
                LOG.ERR, rname, 'KSK phase 2:  no keyrec for zone specified')
            return -1
        if not rrr.keyrec():
            self.rolllog_log(
                LOG.ERR, rname,
                'KSK phase 2:  keyrec "%s" for zone does not exist' %
                rrr.keyrec_path)
            return -1

        # Sign the zone with a new Published KSK.
        if not self.signer(rname, 'KSK phase 2', krf):
            self.rolllog_log(
                LOG.ERR, rname,
                'KSK phase 2:  unable to sign zone with the Published KSK')
            return -1

        # Reload the zone.
        if not self.loadzone(rname, rrr, 'KSK phase 2'):
            self.rolllog_log(
                LOG.ERR, rname,
                'KSK phase 2:  unable to reload zone')

        # On to the phase 3.
        return 3

    def ksk_phase4(self, rname, rrr, *skipargs):
        '''
        Perform the phase 4 steps of the KSK rollover.  These are:
            - notify the admin that the new keyset should be
              transferred to the parent zone

        @param rname: Name of rollrec.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll

        @returns: Next phase number or -1 on error
        @rtype: int
        '''
        if self.auto and self.provider and self.provider_key:
            self.rolllog_log(
                LOG.ERR, rname,
                'KSK phase 4:  transfer new keyset to the parent')
            ret = rrr.dspub(self.provider, self.provider_key)
            if not ret:
                self.rolllog_log(
                    LOG.ERR, rname,
                    'KSK phase 4:  automatic keyset transfer failed')
                return -1
        elif (self.dtconf.get('admin-email') == 'nomail' or
                rrr.get('administrator') == 'nomail'):
            self.rolllog_log(
                LOG.INFO, rname,
                'KSK phase 4:  admin must transfer keyset')
        else:
            msg = MIMEText('The zone \"$rname\" is in the middle of KSK rollover.  '
                'In order for rollover to continue, its keyset must be '
                'transferred to its parent.')
            msg['Subject'] = 'PyRollerd: assistance needed with KSK rollover of zone %s' % rname
            msg['From'] = 'pyrollerd@localhost'
            # If this zone has its own administrator listed, we won't use
            # the default.
            msg['To'] = self.dtconf.get('admin-email') or rrr.get('administrator')

            # Send the message via our own SMTP server.
            try:
                smtp = smtplib.SMTP('localhost')
                smtp.send_message(msg)
                smtp.quit()
            except ConnectionRefusedError:
                self.rolllog_log(
                    LOG.INFO, rname,
                    'KSK phase 4:  admin must transfer keyset')
                self.rolllog_log(
                    LOG.ERR, rname,
                    'KSK phase 4:  invalid admin; unable to notify about '
                    'transferring keyset')
            else:
                self.rolllog_log(
                    LOG.INFO, rname,
                    'KSK phase 4:  admin notified to transfer keyset')

        # Pressing on to phase 5.
        return 5

    def ksk_phase5(self, rname, rrr, *skipargs):
        '''
        Perform the phase 5 steps of the KSK rollover.  These are:
            - wait for the parent to publish the DS record

        @param rname: Name of rollrec.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll

        @returns: Next phase number or -1 on error
        @rtype: int
        '''
        if self.auto and self.provider and self.provider_key:
            self.rolllog_log(
                LOG.INFO, rname,
                'KSK phase 5:  automatic keyset transfer is enabled, skipping phase')
            return 6
        else:
            self.rolllog_log(
                LOG.INFO, rname,
                'KSK phase 5:  waiting for parental publication of DS record')

        return 5

    def ksk_phase7(self, rname, rrr, *skipargs):
        '''
        Perform the phase 7 steps of the KSK rollover.  These are:
            - delete the Current KSK from the zone file
            - move the Published KSK to be the Current KSK
            - sign the zone file with the (new) Current KSK
            - load the zone
            - archive keys that need to be archived
            - move to phase 0
            - save a timestamp for rollover completion

        These first three steps are handled by zonesigner.

        @param rname: Name of rollrec.
        @type rname: str
        @param rrr: Reference to rollrec.
        @type rrr: Roll

        @returns: Next phase number or -1 on error
        @rtype: int
        '''
        # Get the rollrec's associated keyrec file and ensure that it exists.
        krr = rrr.keyrec()
        if not rrr.get('keyrec'):
            self.rolllog_log(
                LOG.ERR, rname, 'KSK phase 7:  no keyrec for zone specified')
            return -1
        if not krr:
            self.rolllog_log(
                LOG.ERR, rname,
                'KSK phase 7:  keyrec "%s" for zone does not exist' %
                rrr.keyrec_path)
            return -1

        # Roll the Published KSK to the Current KSK.
        ret = self.signer(rname, 'KSK phase 7', krr)
        if not ret:
            self.rolllog_log(
                LOG.ERR, rname,
                'KSK phase 7:  unable to roll the Published KSK to the '
                'Current KSK')
            return -1

        # Reload the zone.
        ret = self.loadzone(rname, rrr, 'KSK phase 7')
        if not ret:
            self.rolllog_log(
                LOG.ERR, rname,
                'KSK phase 7:  unable to reload zone')

        # Set up the keyarch command we'll be executing.
        keyarch_cmd = (
            '%(keyarch)s -dtconf %(dtcf)s -zone %(zname)s %(krf)s -verbose' % {
            'keyarch': self.keyarch,
            'dtcf': self.dtcf,
            'zname': rrr['zonename'],
            'krf': rrr.keyrec_path,
        })
        self.rolllog_log(LOG.TMI, rname, 'keyarch:  running <%s>' % keyarch_cmd)
        ret = self.runner(rname, keyarch_cmd, krr, True)
        if not ret:
            self.rolllog_log(
                LOG.ERR, rname, 'KSK phase 7:  unable to archive KSK keys')
            rrr.zoneerr()
            return -1
        else:
            self.rolllog_log(
                LOG.INFO, rname, 'KSK phase 7:  zone, key files archived')
            rrr.clearzoneerr()

        # Set a timestamp for the completion of the KSK roll.
        rrr.rollstamp('ksk')

        # Returning to normal rollover state.
        return 8
