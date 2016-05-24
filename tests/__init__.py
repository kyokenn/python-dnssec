#!/usr/bin/env python3
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

import os
import subprocess
import time
import sys


HOME_DIR = '/tmp'
DTCF = os.path.join(HOME_DIR, 'dnssec-tools.conf')
RRF = os.path.join(HOME_DIR, 'dnssec-tools.rollrec')
ZF = os.path.join(HOME_DIR, 'fuzetsu.info')
PID = os.path.join(HOME_DIR, 'rollerd.pid')
LOCK = os.path.join(HOME_DIR, 'rollrec.lock')
SOCK = os.path.join(HOME_DIR, 'rollmgr.socket')


def generate_conf(**kwargs):
    dtconfig = {
        # Settings for DNSSEC-Tools administration.
        'admin-email': 'root@localhost',
        # Paths to needed programs.  These may need adjusting for individual hosts.
        'keyarch': '/usr/sbin/keyarch',
        'rollchk': '/usr/sbin/rollchk',
        'zonesigner': '/usr/sbin/zonesigner',
        'keygen': '/usr/sbin/dnssec-keygen',
        'rndc': '/usr/sbin/rndc',
        'zonecheck': '/usr/sbin/named-checkzone',
        'zonesign': '/usr/sbin/dnssec-signzone',
        # Key-related values.
        'algorithm': 'rsasha256',
        'ksklength': 2048,
        'zsklength': 1024,
        'random': '/dev/urandom',
        # NSEC3 functionality
        'usensec3': 'no',
        'nsec3iter': 100,
        'nsec3salt': 'random:64',
        'nsec3optout': 'no',
        # Settings for dnssec-signzone.
        'endtime': '+2592000',
        # Life-times for keys.  These defaults indicate how long a key has
        # between rollovers.  The values are measured in seconds.
        'lifespan-max': 94608000,
        'lifespan-min': 3600,
        'ksklife': 15768000,
        'zsklife': 604800,
        # Settings for zonesigner.
        'archivedir': '/var/lib/dnssec-tools/archive',
        'entropy_msg': 1,
        'savekeys': 1,
        'kskcount': 1,
        'zskcount': 1,
        # Settings for rollerd.
        'roll_loadzone': 1,
        'roll_logfile': '/var/log/dnssec-tools/rollerd.log',
        'roll_loglevel': 'phase',
        'roll_phasemsg': 'long',
        'roll_sleeptime': 3600,
        'zone_errors': 5,
        'log_tz': 'gmt',
        'roll_auto': 1,
        'roll_provider': 'dummy',
        'roll_provider_key': 'DUMMY_API_KEY',
    }
    dtconfig.update(kwargs)
    if os.path.exists(DTCF):
        os.remove(DTCF)
    f = open(DTCF, 'w')
    for i in dtconfig.items():
        print('%s %s' % i, file=f)
    f.close()
    return True


def generate_zone():
    if os.path.exists(ZF):
        os.remove(ZF)
    if os.path.exists(ZF + '.krf'):
        os.remove(ZF + '.krf')
    f = open(ZF, 'w')
    f.write('''
$ORIGIN fuzetsu.info.
$TTL 1

@ IN SOA ns6.gandi.net. okami.fuzetsu.info. (
    2015010106
    43200
    3600
    1209600
    1
)

@ IN NS ns6.gandi.net.
@ IN A 8.8.8.8
_443._tcp.gnome.org IN TLSA 1 0 1 36CDC83056FE85D0BC3292FECD53214236B232D929862A3C1B90FE1E9DE5B737
''')
    f.close()
    return True


def rollinit():
    if os.path.exists(RRF):
        os.remove(RRF)
    cmd = (
        'rollinit',
        '-directory', HOME_DIR,
        '-out', RRF,
        'fuzetsu.info'
    )
    p = subprocess.Popen(cmd, cwd=HOME_DIR)
    rcode = p.wait()
    return rcode == 0


def rollerd(args):
    p = subprocess.Popen(('python', 'rollerd') + args, cwd=os.getcwd())
    rcode = p.wait()
    return rcode == 0


def ksk():
    assert generate_conf(ksklife=1)
    assert generate_zone()
    assert rollinit()
    args = (
        '-rrfile', RRF,
        '-dtconfig', DTCF,
        '-pidfile', PID,
        '-lockfile', LOCK,
        '-sockfile', SOCK,
        '-logfile', '-',
        '-loglevel', '1',
        '-singlerun',
        '-autosign',
    )
    rollerd(args)  # initial
    rollerd(args)  # KSK phase: 0 -> 1
    rollerd(args)  # KSK phase: 1 -> 2
    time.sleep(2)  # wait for TTL*2 to expire
    rollerd(args)  # KSK phase: 2 -> 3
    time.sleep(2)  # wait for TTL*2 to expire
    rollerd(args)  # KSK phase: 3 -> 4
    rollerd(args)  # KSK phase: 4 -> 5
    rollerd(args)  # KSK phase: 5 -> 6
    rollerd(args)  # KSK phase: 6 -> 7
    rollerd(args)  # KSK phase: 7 -> 0


def zsk():
    assert generate_conf(zsklife=1)
    assert generate_zone()
    assert rollinit()
    args = (
        '-rrfile', RRF,
        '-dtconfig', DTCF,
        '-pidfile', PID,
        '-lockfile', LOCK,
        '-sockfile', SOCK,
        '-logfile', '-',
        '-loglevel', '1',
        '-singlerun',
        '-autosign',
    )
    rollerd(args)  # initial
    rollerd(args)  # ZSK phase: 0 -> 1
    rollerd(args)  # ZSK phase: 1 -> 2
    time.sleep(2)  # wait for TTL*2 to expire
    rollerd(args)  # ZSK phase: 2 -> 3
    time.sleep(2)  # wait for TTL*2 to expire
    rollerd(args)  # ZSK phase: 3 -> 4
    rollerd(args)  # ZSK phase: 4 -> 0


if __name__ == '__main__':
    '''
    dnssec-tools has to be installed
    '''
    if 'ksk' in sys.argv:
        ksk()
    if 'zsk' in sys.argv:
        zsk()
