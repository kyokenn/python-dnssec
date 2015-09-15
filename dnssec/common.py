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


import copy
import re
import sys


class CommonMixin(object):
    NAME = ''
    VERS = ''
    DTVERS = ''

    def version(self):
        '''
        Routine: version()
        Purpose: Print the version number(s) and exit.
        '''
        print(self.VERS)
        print(self.DTVERS)

    def get_options(self, opts, args):
        '''
        @param opts: options with default values
        @type opts: dict
        @param args: command line arguments
        @type args: list
        @returns: parsed options
        @rtype: dict
        '''
        opts = copy.copy(opts)
        skip = False
        for i, key in enumerate(args):
            if skip:
                skip = False
                continue
            if key == '-':
                continue
            if i < len(args) - 1:
                value = args[i + 1]
            else:
                value = None
            if re.match(r'\-{1,2}[^\-]+', key):
                key = key.lstrip('-')
            else:
                return None
            if key in opts:
                if type(opts[key]) == str:
                    if value:
                        opts[key] = value
                        skip = True
                    else:
                        return None
                elif type(opts[key]) == bool:
                    opts[key] = True
                elif type(opts[key]) == int:
                    if value:
                        try:
                            opts[key] = int(value)
                            skip = True
                        except ValueError:
                            return None
                    else:
                        return None
        return opts
