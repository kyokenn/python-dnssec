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


class TabbedConf(collections.OrderedDict):
    _parent = None
    _directory = None

    def _format(self, key, value):
        tabs = 1  # minimum tabs count
        if len(key) < 8:  # extra tab to short key name
            tabs += 1
        return ('\t%s' + ('\t' * tabs) + '"%s"\n') % (key, value)

    def write(self, path):
        f = open(path, 'w')
        f.write(str(self))
        f.close()

    def save(self):
        if self._parent:
            self._parent.save()
        else:  # root
            self.write(self._path)
