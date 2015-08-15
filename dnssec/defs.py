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

LOG_DEFAULT = '/var/log/dnssec-tools/pyrollerd.log'

ME = 'pyrollerd'

DEFAULT_NAP = 60

# Method selected for calculating rollover times.
RM_ENDROLL = 1  # Calculate from end of last roll.
RM_KEYGEN = 2  # Calculate from last key generation.
RM_STARTROLL = 3  # Calculate from start of last roll.  (NYI)

DT_LOADZONE = 'roll_loadzone'
DT_LOGFILE = 'roll_logfile'
DT_LOGLEVEL = 'roll_loglevel'
DT_LOGTZ = 'log_tz'
DT_RNDCOPTS = 'rndc-opts'
DT_SLEEP = 'roll_sleeptime'
DT_USERNAME = 'roll_username'

OPT_ALWAYSSIGN = 'alwayssign'
OPT_AUTOSIGN = 'autosign'
OPT_DIR = 'directory'
OPT_DISPLAY = 'display'
OPT_DTCONF = 'dtconfig'
OPT_FOREGROUND = 'foreground'
OPT_HELP = 'help'
OPT_LOGFILE = 'logfile'
OPT_LOGLEVEL = 'loglevel'
OPT_LOGTZ = 'logtz'
OPT_NORELOAD = 'noreload'
OPT_PARAMS = 'parameters'
OPT_PIDFILE = 'pidfile'
OPT_REALM = 'realm'
OPT_RRFILE = 'rrfile'
OPT_SINGLERUN = 'singlerun'
OPT_SLEEP = 'sleep'
OPT_USERNAME = 'username'
OPT_VERBOSE = 'verbose'
OPT_VERSION = 'Version'
OPT_ZONESIGNER = 'zonesigner'
OPT_ZSARGS = 'zsargs'

MIN_SLEEP = 10  # Minimum time rollerd will sleep.

EVT_FULLLIST = 1  # Full list is run every N seconds.
EVT_QUEUE_SOON = 2  # Queues, with "soon" events.

QUEUE_ERRTIME = 60  # Time to sleep on rollrec error.

# QUEUE_SOONLIMIT defines the length of "soon".  When building the soon
# queue, any zone with an event between now and (now + QUEUE_SOONLIMIT)
# will be added to the soon queue.  This is a seconds count.
#
# This value will depend on the number of managed zones and their lifespans.
# The default value is for a day, which means the soon queue will hold all
# events that will occur within the next 24 hours.
QUEUE_SOONLIMIT = 86400
QUEUE_RUNSCAN = '<<< run full scan >>>'  # Fake rollrec name to trigger a full scan.

# If we find the rollrec file is empty, we'll give an error message
# only on an occasional pass through the zone list.
MAXRRFERRS = 5  # Number of list passes to stay quiet.

# The remaining ROLLCMD_ entities are the rollmgr_sendcmd() commands
# recognized by rollerd.  %roll_commands is a hash table of valid commands.
ROLLCMD_DISPLAY = 'rollcmd_display'
ROLLCMD_DSPUB = 'rollcmd_dspub'
ROLLCMD_DSPUBALL = 'rollcmd_dspuball'
ROLLCMD_GETSTATUS = 'rollcmd_getstatus'
ROLLCMD_LOGFILE = 'rollcmd_logfile'
ROLLCMD_LOGLEVEL = 'rollcmd_loglevel'
ROLLCMD_LOGMSG = 'rollcmd_logmsg'
ROLLCMD_LOGTZ = 'rollcmd_logtz'
ROLLCMD_MERGERRFS = 'rollcmd_mergerrfs'
ROLLCMD_PHASEMSG = 'rollcmd_phasemsg'
ROLLCMD_ROLLALL = 'rollcmd_rollall'
ROLLCMD_ROLLALLKSKS = 'rollcmd_rollallksks'
ROLLCMD_ROLLALLZSKS = 'rollcmd_rollallzsks'
ROLLCMD_ROLLKSK = 'rollcmd_rollksk'
ROLLCMD_ROLLREC = 'rollcmd_rollrec'
ROLLCMD_ROLLZONE = 'rollcmd_rollzone'
ROLLCMD_ROLLZSK = 'rollcmd_rollzsk'
ROLLCMD_RUNQUEUE = 'rollcmd_runqueue'
ROLLCMD_QUEUELIST = 'rollcmd_queuelist'
ROLLCMD_QUEUESTATUS = 'rollcmd_queuestatus'
ROLLCMD_SHUTDOWN = 'rollcmd_shutdown'
ROLLCMD_SIGNZONE = 'rollcmd_signzone'
ROLLCMD_SIGNZONES = 'rollcmd_signzones'
ROLLCMD_SKIPALL = 'rollcmd_skipall'
ROLLCMD_SKIPZONE = 'rollcmd_skipzone'
ROLLCMD_SLEEPTIME = 'rollcmd_sleeptime'
ROLLCMD_SPLITRRF = 'rollcmd_splitrrf'
ROLLCMD_STATUS = 'rollcmd_status'
ROLLCMD_ZONEGROUP = 'rollcmd_zonegroup'
ROLLCMD_ZONELOG = 'rollcmd_zonelog'
ROLLCMD_ZONESTATUS = 'rollcmd_zonestatus'
ROLLCMD_ZSARGS = 'rollcmd_zsargs'

# The ROLLCMD_RC_ entities are return codes sent from rollerd and received
# by client programs from rollmgr_getresp().
ROLLCMD_RC_OKAY = 0
ROLLCMD_RC_BADLEVEL = 1
ROLLCMD_RC_BADFILE = 2
ROLLCMD_RC_BADSLEEP = 3
ROLLCMD_RC_BADROLLREC = 4
ROLLCMD_RC_BADTZ = 5
ROLLCMD_RC_RRFOPEN = 6
ROLLCMD_RC_NOZONES = 7
ROLLCMD_RC_BADZONE = 8
ROLLCMD_RC_BADZONEDATA = 9
ROLLCMD_RC_DISPLAY = 10
ROLLCMD_RC_KSKROLL = 11
ROLLCMD_RC_ZSKROLL = 12
ROLLCMD_RC_NOARGS = 13
ROLLCMD_RC_BADEVENT = 14
ROLLCMD_RC_BADZONEGROUP = 15
