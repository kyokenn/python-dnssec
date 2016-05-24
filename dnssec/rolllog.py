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

import datetime
import logging
import os
import sys


# Log levels. The first and last aren't selectable by a user.
class LOG(object):
    NEVER = 0  # Do not log this message.
    TMI = 1  # Overly verbose informational message.
    EXPIRE = 3  # Time-to-expiration given.
    INFO = 4  # Informational message.
    PHASE = 6  # Give current state of zone.
    ERR = 8  # Non-fatal error message.
    FATAL = 9  # Fatal error.
    ALWAYS = 10  # Messages that should always be given.

    MIN = NEVER  # Minimum log level.
    MAX = ALWAYS  # Maximum log level.


DEFAULT_LOGLEVEL = LOG.INFO  # Default log level.

DEFAULT_LOGTZ = 'gmt'  # Default timezone.


class RollLogMixin(object):
    LOG = None

    logstrs = (  # Valid strings for levels.
        'never',
        'tmi',
        None,
        'expire',
        'info',
        None,
        'phase',
        None,
        'err',
        'fatal',
        'always',
    )
    usetz = DEFAULT_LOGTZ  # Timezone selector to use.

    def rolllog_log(self, lvl, fld, msg):
        '''
        Routine: rolllog_log()
        lvl - Message log level.
        fld - Message field.
        msg - Message to log.
        '''

        kronos = None  # Current time.
        outstr = ''  # Output string.

        # Don't give the message unless it's at or above the log level.
        if lvl < self.loglevel:
            return

        # Add an administrative field specifier if the field wasn't given.
        if fld:
            fld = '%s: ' % fld

        # Get the timestamp.
        if self.usetz == 'local':
            kronos = datetime.datetime.now()
        else:
            kronos = datetime.datetime.utcnow()

        # Build the output string.
        outstr = '%(kronos)s: %(fld)s%(msg)s' % {
            'kronos': kronos.strftime('%b %d %H:%M:%S'),
            'fld': fld,
            'msg': msg,
        }

        # Write the message.
        if self.LOG:
            # print(outstr, file=self.LOG)
            # self.LOG.flush()
            self.LOG.info(outstr)

    def rolllog_num(self, level):
        if type(level) == int:
            return level
        elif type(level) == str:
            if level.isdigit():
                return int(level)
            else:
                try:
                    i = self.logstrs.index(level)
                except ValueError:
                    return -1
                else:
                    return i
        return -1


    def rolllog_level(self, newlevel, useflag):
        '''
        Get/set the logging level.  If no arguments are given, then
        the current logging level is returned.  If a valid new level
        is given, that will become the new level.

        If a problem occurs (invalid log level), then -1 will be
        returned, unless a non-zero argument was passed for the
        second argument.  In this case, a usage message is given and
        the process exits.

        @param newloglevel: Name of new loglevel.
        @type newloglevel: str or int
        @param useflag: Usage-on-error flag.
        @type useflag: bool
        '''
        # Return the current log level if that's all they want.
        if not newlevel:
            return self.loglevel

        # Translate the logging level to its numeric form.
        loglevel = self.rolllog_num(newlevel)

        # If there was a problem, give usage messages and exit.
        if loglevel == -1:
            if useflag:
                print('''unknown logging level "%s"
valid logging levels (text and numeric forms):
\ttmi    1
\texpire 3
\tinfo   4
\tphase  6
\terr    8
\tfatal  9''' % newlevel, file=sys.stderr)
            return DEFAULT_LOGLEVEL

        return loglevel

    def rolllog_file(self, newlogfile, useflag):
        '''
        Routine: rolllog_file()
        Purpose: Get/set the log file.  If no arguments are given, then
                 the current log file is returned.  If a valid new file
                 is given, that will become the new log file.

                 If a problem occurs (invalid log file), then -1 will be
                 returned, unless a non-zero argument was passed for the
                 second argument.  In this case, a usage message is given
                 and the process exits.
        newlogfile - Name of new logfile.
        useflag - Usage-on-error flag.
        '''
        # Return the current log file if a log file wasn't given.
        if not newlogfile:
            return self.logfile

        # Allow "-" to represent stdout.
        if newlogfile == '-':
            newlogfile = '/dev/stdout'
            if not os.path.exists(newlogfile):
                if useflag:
                    print('logfile "%s" does not exist' % newlogfile, file=sys.stderr)
                return ''

        # If a log file was specified, ensure it's a writable regular file.
        # If it isn't a regular file, ensure that it's one of the standard
        # process-output files.
        if os.path.exists(newlogfile):
            if (not os.path.isfile(newlogfile) and
                    newlogfile != '/dev/stdout' and
                    newlogfile != '/dev/tty'):
                if useflag:
                    print('logfile "%s" is not a regular file' % newlogfile, file=sys.stderr)
                return ''
            try:
                f = open(newlogfile, 'w')
                f.close()
            except PermissionError:
                if useflag:
                    print('logfile "%s" is not writable' % newlogfile, file=sys.stderr)
                return ''

        # Open up the log file (after closing any open logs.)
        logfile = newlogfile
        # if self.LOG:
        #     self.LOG.close()
        try:
            # self.LOG = open(logfile, 'w+')
            self.LOG = logging.getLogger('rollerd')
            self.LOG.setLevel(logging.INFO)
            handler = logging.FileHandler(logfile)
            handler.setLevel(logging.INFO)
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.LOG.addHandler(handler)
        except IOError:
            print('unable to open "%s"' % logfile, file=sys.stderr)

        return logfile

    def rolllog_settz(self, newtz):
        '''
        Routine: rolllog_settz()
        Purpose: Set the timezone selector to use for timestamps in log
                 messages.  'local' and 'gmt' are the acceptable values.
        newtz - New timezone.
        '''
        # Ensure a valid timezone selector was given. If no selector
        # was given, then we'll use the default.
        if newtz:
            if newtz in ('gmt', 'local'):
                return newtz
            else:
                return ''
        else:
            return DEFAULT_LOGTZ
