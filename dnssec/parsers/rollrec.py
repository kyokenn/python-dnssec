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
import datetime
import itertools
import os
import re
import shlex
import subprocess
import time

import dns
import dns.zone

from . import DATETIME_FORMAT
from .abstract import TabbedConf
from .keyrec import KeyRec


class Roll(TabbedConf):
    _name = None
    _is_active = True
    _keyrec = None
    _zone = None
    _keys = None

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
            self.rollrec_type, self.name,
            ''.join(map(lambda x: self._format(*x), self.items())))

    def _full_path(self, key):
        directory = self.get('directory', self._directory)
        if directory:
            return os.path.join(directory, self[key])
        else:
            return self[key]

    @property
    def zonefile_path(self):
        return self._full_path('zonefile')

    @property
    def keyrec_path(self):
        return self._full_path('keyrec')

    @property
    def kskphase(self):
        return int(self['kskphase'])

    @property
    def zskphase(self):
        return int(self['zskphase'])

    @property
    def phasetype(self):
        if self.kskphase != 0:
            return 'ksk'
        elif self.zskphase != 0:
            return 'zsk'

    @property
    def rollrec_type(self):
        return 'roll' if self.is_active else 'skip'

    @property
    def phase(self):
        if self.phasetype:
            return int(self['%sphase' % self.phasetype])

    @property
    def phaseargs(self):
        if self.kskphase != 0:
            return 'KSK phase %d -signonly' % self.kskphase
        elif self.zskphase != 0:
            return 'ZSK phase %d -signonly' % self.zskphase
        else:
            return ' -signonly'

    def keyrec(self):
        path = self.keyrec_path
        if os.path.exists(path) and os.path.isfile(path):
            keyrec = KeyRec()
            keyrec.read(path)
            return keyrec

    def zoneerr(self):
        # Get the zone's maximum error count.
        maxerrs = int(self.get('maxerrors', '0'))

        # If there's a maximum error count set for this zone, we'll increase
        # the count and see if we need to stop worrying about this zone.
        if maxerrs > 0:
            # Increment the zone's maximum error count.
            curerrs = int(self.get('curerrors', '0')) + 1

            # Save the new value.
            self['curerrors'] = str(curerrs)

            # If we've exceeded the maximum error count, change the zone
            # to a skip zone.
            if curerrs > maxerrs:
                self.is_active = False

    def clearzoneerr(self):
        self['curerrors'] = '0'

    def rollstamp(self, prefix):
        t = int(time.time())
        self['%s_rolldate' % prefix] = (
            datetime.datetime.fromtimestamp(t).strftime(DATETIME_FORMAT))
        self['%s_rollsecs' % prefix] = str(t)

    def settime(self):
        t = int(time.time())
        self['phasestart'] = (
            datetime.datetime.fromtimestamp(t).strftime(DATETIME_FORMAT))

    def dnszone(self):
        '''
        Parse zone file
        '''
        return dns.zone.from_file(
            self.zonefile_path,
            origin=self['zonename'], check_origin=False)

    def maxttl(self):
        rdatasets = reversed(sorted(itertools.chain(
            *tuple(map(lambda node: node.rdatasets, self.dnszone().values()))),
            key=lambda node: node.ttl))
        rdataset = next(iter(rdatasets), None)
        ttl = rdataset and rdataset.ttl or 0
        self['maxttl'] = str(ttl)
        return ttl * 2

    def ttlexpire(self):
        return datetime.datetime.now() >= self.phaseend_date

    def ttlleft(self):
        ''' Seconds left to expire '''
        left = self.phaseend_date - datetime.datetime.now()
        if left.total_seconds() < 0:  # date in future
            left = datetime.timedelta()
        return left

    def holddownleft(self):
        ''' hold-down timer of RFC5011 '''
        holddowntime = 2 * 30 * 24 * 60 * 60
        blob = re.match(r'(\d+)D', self['holddowntime'])
        if blob:
            holddowntime = int(blob.group(1)) * 24 * 60 * 60
        left = (
            self.phasestart_date + datetime.timedelta(seconds=holddowntime) -
            datetime.datetime.now())
        if left.total_seconds() < 0:  # date in future
            left = datetime.timedelta()
        return left

    def loadzone(self, rndc, rndcopts):
        ''' Reload the zone '''
        cmd = '%s %s reload %s' % (rndc, rndcopts, self['zonename'])
        p = subprocess.Popen(
            shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        rcode = p.wait()
        out = p.stdout.read().decode('utf8')
        return rcode

    def dspub(self, provider, api_key):
        keyrec = self.keyrec()
        keys = []
        zskcur = keyrec[self['zonename']]._zskcur
        zskpub = keyrec[self['zonename']]._zskpub
        kskcur = keyrec[self['zonename']]._kskcur
        kskpub = keyrec[self['zonename']]._kskpub
        if zskcur:
            keys += zskcur.keys
        if zskpub:
            keys += zskpub.keys
        if kskcur:
            keys += kskcur.keys
        if kskpub:
            keys += kskpub.keys

        if provider == 'gandi.net':
            from ..api.gandi import APIClient
        elif provider == 'dummy':
            from ..api.dummy import APIClient
        else:
            return False

        apiclient = APIClient(api_key)
        return apiclient.dspub(self['zonename'], keys)

    @property
    def phase_description(self):
        if self.phasetype == 'zsk':
            return {
                1: 'wait for old zone data to expire from caches',
                2: 'sign the zone with the KSK and Published ZSK',
                3: 'wait for old zone data to expire from caches',
                4: 'adjust keys in keyrec and sign the zone with new Current ZSK',
            }.get(self.phase, None)
        elif self.phasetype == 'ksk':
            return {
                1: 'wait for cache data to expire',
                2: 'generate a new (published) KSK and load zone',
                3: 'wait for the old DNSKEY RRset to expire from caches',
                4: 'transfer new keyset to the parent',
                5: 'wait for parent to publish DS record',
                6: 'wait for cache data to expire',
                7: 'roll the KSKs and load the zone',
            }.get(self.phase, None)

    @property
    def phasestart_date(self):
        if self['phasestart'] != 'new':
            return datetime.datetime.strptime(
                self['phasestart'], DATETIME_FORMAT)

    @property
    def phaseend_date(self):
        timedelta = None
        if self.phasetype == 'zsk':
            timedelta = {
                1: datetime.timedelta(seconds=self.maxttl()),
                2: datetime.timedelta(),
                3: datetime.timedelta(seconds=self.maxttl()),
                4: datetime.timedelta(),
            }.get(self.phase, None)
        elif self.phasetype == 'ksk':
            timedelta = {
                1: datetime.timedelta(seconds=self.maxttl()),
                2: datetime.timedelta(),
                3: datetime.timedelta(seconds=self._get_ksk_phase3_length()),
                4: datetime.timedelta(),
                5: datetime.timedelta(),
                6: datetime.timedelta(),
                7: datetime.timedelta(),
            }.get(self.phase, None)
        if timedelta:
            return self.phasestart_date + timedelta

    @property
    def holddowntime_duration(self):
        holddowntime = int(self.get('holddowntime', '0D').replace('D', ''))
        if self.get('holddowntime', '0D').endswith('D'):
            holddowntime = holddowntime * 24 * 60 * 60

    def _get_ksk_phase3_length(self):
        length = int(self['maxttl']) * 2
        if self.get('istrustanchor', 'no') in ('yes', '1'):
            # we should do a proper RFC5011 waiting period
            # use either their defined value or a default of 60 days
            # The 60 days comes from the rollerd 60 day default
            length += self.holddowntime_duration or (60 * 24 * 60 * 60)
        return length

    @property
    def phase_progress(self):
        if not self.phaseend_date:
            return 0
        if datetime.datetime.now() > self.phaseend_date:
            return 100
        min = time.mktime(self.phasestart_date.timetuple())
        max = time.mktime(self.phaseend_date.timetuple())
        now = time.mktime(datetime.datetime.now().timetuple())
        return int((now-min) * 100.0 / (max-min))

    @property
    def phase_left(self):
        if self.phaseend_date:
            if datetime.datetime.now() > self.phaseend_date:
                return datetime.timedelta()
            td = self.phaseend_date - datetime.datetime.now()
            return datetime.timedelta(seconds=int(td.total_seconds()))


class RollRec(TabbedConf):
    '''
    RRF .rollrec (roll record file) parser
    '''
    def __str__(self):
        return '\n'.join('%s' % roll for roll in self.values())

    def read(self, path, directory=None):
        self._path = path
        self._directory = directory
        f = open(path, 'r')
        roll = None
        for i in f.readlines():
            if not i.strip().startswith('#'):
                match = re.match(r'(\S+)\s+"([^"]+)"', i.strip())
                if match:
                    key, value = match.group(1), match.group(2)
                    if key in ('roll', 'skip'):
                        roll = Roll()
                        roll._parent = self
                        roll.name = value
                        roll.is_active = key == 'roll'
                        self[value] = roll
                    elif roll is not None:
                        roll[key] = value
        f.close()

    def rolls(self, active_only=True):
        if active_only:
            return filter(lambda x: x[1].is_active, self.items())
        else:
            return self.items()
