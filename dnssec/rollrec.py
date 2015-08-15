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

import collections
import fcntl
import os
import re

from .abstract import TabbedConf
from .keyrec import KeyRec


class Roll(TabbedConf):
    _name = None
    _is_active = True
    _keyrec = None
    _zone = None
    _keys = None

    zg_commands = (
        'rollcmd_dspub',
        'rollcmd_rollksk',
        'rollcmd_rollzone',
        'rollcmd_rollzsk',
        'rollcmd_skipzone',
    )

    name = property(
        lambda self: self._name,
        lambda self, name: setattr(self, '_name', name))
    is_active = property(
        lambda self: self._is_active,
        lambda self, is_active: setattr(self, '_is_active', is_active))

    def _format(self, key, value):
        r = super()._format(key, value)
        if key == 'istrustanchor':
            r = '\t# optional records for RFC5011 rolling:\n' + r
        return r

    def __str__(self):
        return '%s\t"%s"\n%s' % (
            'roll' if self.is_active else 'skip',
            self.name, ''.join(map(lambda x: self._format(*x), self.items())))

    def _full_path(self, key):
        if 'directory' in self:
            return os.path.join(self['directory'], self[key])
        else:
            return self[key]

    @property
    def zonefile_path(self):
        return self._full_path('zonefile')

    @property
    def keyrec_path(self):
        return self._full_path('keyrec')

    def keyrec(self):
        keyrec = KeyRec()
        keyrec.read(self.keyrec_path)
        return keyrec

    def zone(self):
        if not self._zone:
            zones = self.keyrec().zones(
                filter_=lambda x: x.name() == self.name())
            if len(zones) == 1:
                self._zone = zones[0]
        return self._zone

    def keys(self, filter_=None):
        if not self._keys:
#            self._keys = self.keyrec().keys(
#                filter_=lambda x: x[1].zone().name() == self.zone().name())
            self._keys = self.keyrec().keys()
        if filter_:
            return filter(lambda x: filter_(x[1]), self._keys)
        return self._keys

    @property
    def phasetype(self):
        if self['kskphase'] != '0':
            return 'ksk'
        elif self['zskphase'] != '0':
            return 'zsk'

    @property
    def phase(self):
        if self.phasetype():
            return int(self['%sphase' % self.phasetype()])

    @property
    def phase_description(self):
        if self.phasetype() == 'zsk':
            return {
                1: 'wait for old zone data to expire from caches',
                2: 'sign the zone with the KSK and Published ZSK',
                3: 'wait for old zone data to expire from caches',
                4: 'adjust keys in keyrec and sign the zone with new Current ZSK',
            }.get(self.phase(), None)
        elif self.phasetype() == 'ksk':
            return {
                1: 'wait for cache data to expire',
                2: 'generate a new (published) KSK and load zone',
                3: 'wait for the old DNSKEY RRset to expire from caches',
                4: 'transfer new keyset to the parent',
                5: 'wait for parent to publish DS record',
                6: 'wait for cache data to expire',
                7: 'roll the KSKs and load the zone',
            }.get(self.phase(), None)

    @property
    def phasestart_date(self):
        return datetime.datetime.strptime(self['phasestart'], '%a %b %d %H:%M:%S %Y')
        # return datetime.datetime.strptime(self['phasestart'], '%c')

    @property
    def holddowntime_duration(self):
        holddowntime = int(self.get('holddowntime', '0D').replace('D', ''))
        if self.get('holddowntime', '0D').endswith('D'):
            holddowntime = holddowntime * 24 * 60 * 60

    @property
    def _get_ksk_phase3_length(self):
        length = int(self['maxttl']) * 2
        if self.get('istrustanchor', 'no') in ('yes', '1'):
            # we should do a proper RFC5011 waiting period
            # use either their defined value or a default of 60 days
            # The 60 days comes from the rollerd 60 day default
            length += self.holddowntime_duration() or (60 * 24 * 60 * 60)
        return length

    @property
    def phaseend_date(self):
        timedelta = None
        if self.phasetype() == 'zsk':
            timedelta = {
                1: datetime.timedelta(seconds=int(self['maxttl']) * 2),
                2: datetime.timedelta(),
                3: datetime.timedelta(seconds=int(self['maxttl']) * 2),
                4: datetime.timedelta(),
            }.get(self.phase(), None)
        elif self.phasetype() == 'ksk':
            timedelta = {
                1: datetime.timedelta(seconds=int(self['maxttl']) * 2),
                2: datetime.timedelta(),
                3: datetime.timedelta(seconds=self._get_ksk_phase3_length()),
                4: datetime.timedelta(),
                5: datetime.timedelta(),
                6: datetime.timedelta(),
                7: datetime.timedelta(),
            }.get(self.phase(), None)
        if timedelta:
            return self.phasestart_date() + timedelta

    @property
    def phase_progress(self):
        if not self.phaseend_date():
            return 0
        if datetime.datetime.now() > self.phaseend_date():
            return 100
        min = time.mktime(self.phasestart_date().timetuple())
        max = time.mktime(self.phaseend_date().timetuple())
        now = time.mktime(datetime.datetime.now().timetuple())
        return int((now-min) * 100.0 / (max-min))

    @property
    def phase_left(self):
        if self.phaseend_date():
            if datetime.datetime.now() > self.phaseend_date():
                return TimeDelta()
            td = self.phaseend_date() - datetime.datetime.now()
            return TimeDelta(seconds=int(td.total_seconds()))


class RollRec(TabbedConf):
    def __str__(self):
        return '\n'.join('%s' % roll for roll in self.values())

    def read(self, path):
        self._path = path
        f = open(path, 'r')
        roll = None
        for i in f.readlines():
            if not i.strip().startswith('#'):
                match = re.match(r'(\S+)\s+"([^"]+)"', i.strip())
                if match:
                    key, value = match.group(1), match.group(2)
                    if key in ('roll', 'skip'):
                        roll = Roll()
                        roll.name = value
                        roll.is_active = key == 'roll'
                        self[value] = roll
                    elif roll is not None:
                        roll[key] = value
        f.close()

    def rolls(self):
        return filter(lambda x: x[1].is_active, self.items())


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

    def rollrec_unlock(self, rrf):
        '''
        Routine: rollrec_unlock()
        Purpose: Unlock rollrec processing so that other processes may read
                 a rollrec file.
        rrf - rollrec file.
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
