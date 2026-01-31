import collections
import json
import re
#
import idautils
import idaapi
#
from idaclu import ida_shims
from idaclu import ida_utils
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Ctors and Dtors')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = [(
    'checkbox', 'tor_calls',
    [
        'Constructors',
        'Destructors'
    ]
)]

def order_item_len(input_dict):
    def get_len(val):
        fs = val[1]
        if isinstance(fs, int):
            return fs
        elif isinstance(fs, list):
            return len(fs)

    return collections.OrderedDict(sorted(input_dict.items(), key=get_len, reverse=True))

def get_psdo_list(func_ea):
    func_pseudocode = []
    decomp_str = ""
    try:
       decomp_str = idaapi.decompile(func_ea)
    except idaapi.DecompilationFailure:
       return []
    for line in str(decomp_str).split('\n'):
        if '//' in line:
            code = line.split('//')[0]
            if code != '':
                func_pseudocode.append(code.lstrip())
        else:
            if line != '':
                func_pseudocode.append(line.lstrip())
    return func_pseudocode
    
def get_psdo_body(func_ea):
    psdo_list = get_psdo_list(func_ea)
    return "\n".join(psdo_list[2:-1])
 
def get_data(func_gen=None, env_desc=None, plug_params=None):

    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }
    
    is_ctor_add = plug_params['tor_calls'][0][1]
    is_dtor_add = plug_params['tor_calls'][1][1]

    for func_addr in func_gen():
        psdo_line = get_psdo_body(func_addr)

        if re.search(r".*::`vftable'.*", psdo_line):  # 
            tor_typ = ''
            if re.search(r".*\(a2 & 1\)\s.= 0.*", psdo_line):
                tor_typ = 'dtor'
            else:
                tor_typ = 'ctor'
            
            if ((is_ctor_add and tor_typ == 'ctor')
                or (is_dtor_add and tor_typ == 'dtor')
               ):
                report['data'][tor_typ].append(func_addr)
                report['stat'][tor_typ] += 1

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
