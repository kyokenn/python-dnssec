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

import dns
import dns.rdatatype
import dns.zone

import base64
import collections
import datetime
import os
import re
import time

from . import DATETIME_FORMAT
from .abstract import TabbedConf


class Section(TabbedConf):
    _TYPE = None
    _name = None
    _directory = None

    name = property(
        lambda self: self._name,
        lambda self, name: setattr(self, '_name', name))
    directory = property(
        lambda self: self._directory,
        lambda self, directory: setattr(self, '_directory', directory))

    def __str__(self):
        return '%s\t"%s"\n%s' % (
            self._TYPE, self.name,
            ''.join(map(lambda x: self._format(*x), self.items())))


class Zone(Section):
    ''' Zone section '''

    _TYPE = 'zone'
    _zskcur = None
    _zskpub = None
    _kskcur = None
    _kskpub = None

    def _full_path(self, key):
        return os.path.join(self._directory, self[key])

    @property
    def zonefile_path(self):
        return self._full_path('zonefile')

    @property
    def signedzone_path(self):
        return self._full_path('signedzone')

    @property
    def zskcur(self):
        '''
        ZSK current
        @returns: current key set
        @rtype: KeySet
        '''
        return self._zskcur

    @property
    def zskpub(self):
        '''
        ZSK published
        @returns: published key set
        @rtype: KeySet
        '''
        return self._zskpub

    @property
    def kskcur(self):
        '''
        KSK current
        @returns: current key set
        @rtype: KeySet
        '''
        return self._kskcur

    def settime(self):
        t = int(time.time())
        self['keyrec_signsecs'] = t
        self['keyrec_signdate'] = (
            datetime.datetime.utcfromtimestamp(t).strftime(DATETIME_FORMAT))


class KeySet(Section):
    _TYPE = 'set'
    _zone = None
    _keys = tuple()

    @property
    def keys(self):
        '''
        Keys in set
        @returns: keys
        @rtype: list
        '''
        return self._keys

    def minlife_key(self):
        '''
        Get key with the shortest lifespan
        @returns: key
        @rtype: Key
        '''
        return next(iter(sorted(self.keys, key=lambda x: x.life)), None)

    def settime(self):
        t = int(time.time())
        self['keyrec_setsecs'] = t
        self['keyrec_setdate'] = (
            datetime.datetime.utcfromtimestamp(t).strftime(DATETIME_FORMAT))


class Key(Section):
    _TYPE = 'key'
    _zone = None
    _contents = None

    def definition(self):
        return '%s %s' % (
            self.keytype, self.gendate().strftime('%Y-%m-%d %H:%M'))

    def _full_path(self, key):
        if os.path.isabs(self[key]):
            return self[key]
        else:
            return os.path.join(self._directory, self[key])

    @property
    def key_path(self):
        return self._full_path('keypath')

    def _get_contents(self):
        if not self._contents:
            f = open(self.key_path)
            self._contents = ''.join(
                x.strip('\n ')
                for x in f.readlines()
                if not x.strip().startswith(';'))
        return self._contents

    def _dnskey_data(self, i):
        dnskey = self._get_contents().split().index('DNSKEY')
        if dnskey >= 0:
            return self._get_contents().split()[dnskey + i]

    @property
    def zone(self):
        return self._zone

    def set_zone(self, zone):
        self._zone = zone

    @property
    def flags(self):
        '''
        256 (ZSK) or 257 (KSK)
        '''
        # return int(self._dnskey_data(1))
        return {
            'zsk': 256,
            'ksk': 257,
        }.get(self.keytype, 0)

    @property
    def protocol(self):
        return int(self._dnskey_data(2))

    @property
    def algorithm(self):
        '''
        Algorithm number, see IANA Assignments:
        http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml
        '''
        return int(self._dnskey_data(3))

    def public_key(self):
        dnskey = self._get_contents().split().index('DNSKEY')
        if dnskey >= 0:
            return ' '.join(self._get_contents().split()[dnskey + 4:])

    def public_key_source(self):
        return base64.b64decode(self.public_key())

    def private_key(self):
        raise NotImplemented()

    @property
    def keytype(self):
        return self['keyrec_type'][:3]

    @property
    def pubtype(self):
        return self['keyrec_type'][3:]

    @property
    def life(self):
        return int(self['%slife' % self.keytype])

    @property
    def length(self):
        return int(self['%slength' % self.keytype])

    @property
    def keytag(self):
        return int(re.match(r'.+\+(\d+)\+(\d+)', self.name).group(2))

    def gendate(self):
        return datetime.datetime.utcfromtimestamp(
            int(self['keyrec_gensecs']))

    def valid_until(self):
        return datetime.datetime.utcfromtimestamp(
            int(self['keyrec_gensecs']) + self.life)

    def is_valid(self):
        return datetime.datetime.utcnow() < self.valid_until()

    def is_signed(self):
        '''
        is zone signed with this key
        '''
        zonedata = dns.zone.from_file(
            self.zone.signedzone_path, self.zone.name)
        dnskeys = zonedata.get_rdataset(zonedata.origin, dns.rdatatype.DNSKEY)
        return len(list(filter(
            lambda x: x.key == self.public_key_source(), dnskeys))) > 0

    def settime(self):
        t = int(time.time())
        self['keyrec_gensecs'] = t
        self['keyrec_gendate'] = (
            datetime.datetime.utcfromtimestamp(t).strftime(DATETIME_FORMAT))


class KeyRec(TabbedConf):
    '''
    KRF .krf (key record file) parser
    '''
    def __str__(self):
        return (
            '\n' +
            '\n'.join('%s' % section for section in self.values()) +
            '\n')

    def read(self, path):
        self._path = path
        f = open(path, 'r')
        self._directory = os.path.dirname(path)
        section = None
        for i in f.readlines():
            if not i.strip().startswith('#'):
                match = re.match(r'(\S+)\s+"([^"]+)"', i.strip())
                if match:
                    key, value = match.group(1), match.group(2)
                    if key in ('zone', 'set', 'key'):
                        section_class = {
                            'zone': Zone,
                            'set': KeySet,
                            'key': Key,
                        }[key]
                        section = section_class()
                        section.name = value
                        section.directory = self._directory
                        self[value] = section
                    elif section is not None:
                        section[key] = value
        # link objects together
        for name, section in self.items():
            if type(section) == KeySet:
                # link set with zone
                if 'zonename' in section:
                    section._zone = self[section['zonename']]
                # link set with key
                if 'keys' in section:
                    section._keys = []
                    for key in section['keys'].split(' '):
                        section._keys.append(self[key])
                # link zone with set
                if section['set_type'] == 'zskcur':
                    self[section['zonename']]._zskcur = section
                if section['set_type'] == 'zskpub':
                    self[section['zonename']]._zskpub = section
                if section['set_type'] == 'zsknew':
                    self[section['zonename']]._zsknew = section
                if section['set_type'] == 'kskcur':
                    self[section['zonename']]._kskcur = section
                if section['set_type'] == 'kskpub':
                    self[section['zonename']]._kskpub = section
            elif type(section) == Key:
                # link key with zone
                if 'zonename' in section:
                    section._zone = self[section['zonename']]
        f.close()
