import copy
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
            if key.startswith('-'):
                key = key[1:]
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
