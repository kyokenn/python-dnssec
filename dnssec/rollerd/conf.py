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


class ConfMixin(object):
    def parseconfig(self, path):
        config = {}
        for line in open(path, 'r').readlines():
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith(';'):
                key, sep, value = line.replace('\t', ' ').partition(' ')
                if key and value:
                    config[key.strip()] = value.strip()
        return config
