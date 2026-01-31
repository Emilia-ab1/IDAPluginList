import collections
import json
import re
#
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Not Done')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        func_name = ida_shims.get_func_name(func_addr)
        if not '_done' in func_name and not func_name.startswith('_') and not 'unknown_libname' in func_name and not 'codec' in func_name:
            report['data']['missing'].append(func_addr)
            report['stat']['missing'] += 1

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
