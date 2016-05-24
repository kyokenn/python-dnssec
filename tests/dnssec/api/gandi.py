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

import operator
import time

from xmlrpc import client


class APIClient(object):
    '''
    Gandi RPC API client
    http://doc.rpc.gandi.net/
    '''
    API = None
    API_KEY = ''

    # Operational Test and Evaluation (OT&E) Mode
    OTE = False
    OTE_ENDPOINT = 'https://rpc.ote.gandi.net/xmlrpc/'
    ENDPOINT = 'https://rpc.gandi.net/xmlrpc/'

    def __init__(self, API_KEY):
        self.API_KEY = API_KEY
        endpoint = self.OTE_ENDPOINT if self.OTE else self.ENDPOINT
        self.API = client.ServerProxy(endpoint)

    def _api_call(self, function, *args):
        response = function(self.API_KEY, *args)
        time.sleep(2)
        return response

    def domain_list(self):
        return self._api_call(self.API.domain.list)

    def domain_dnssec_list(self, domain):
        return self._api_call(self.API.domain.dnssec.list, domain)

    def domain_dnssec_delete(self, key_id):
        return self._api_call(self.API.domain.dnssec.delete, key_id)

    def domain_dnssec_create(self, domain, algorithm, flags, public_key):
        dnssec = self.domain_dnssec_list(domain)
        # key limit
        if len(dnssec) >= 4:
            return
        params = {
            'algorithm': algorithm,
            'flags': flags,
            'public_key': public_key,
        }
        return self._api_call(self.API.domain.dnssec.create, domain, params)

    def dspub(self, domain, keys):
        # check domain
        domains = self.domain_list()
        domain_names = map(operator.itemgetter('fqdn'), domains)
        if not domain in domain_names:
            return False

        # check remote keys
        remote_keys = self.domain_dnssec_list(domain)
        remote_keytags = tuple(map(operator.itemgetter('keytag'), remote_keys))
        local_keytags = tuple(map(operator.attrgetter('keytag'), keys))

        for remote_key in remote_keys:
            # remove obsolete keys
            if remote_key['keytag'] not in local_keytags:
                self.domain_dnssec_delete(remote_key['id'])

        for key in keys:
            # add missing keys
            if key.keytag not in remote_keytags:
                self.domain_dnssec_create(
                    domain=domain,
                    algorithm=key.algorithm,
                    flags=key.flags,
                    public_key=key.public_key())

        return True
