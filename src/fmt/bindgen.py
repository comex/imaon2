import sys, subprocess, re, tempfile, os
from collections import OrderedDict

# TODO enum2str


all_args = sys.argv[1:]
matches = []
clang_args = []
bg_args = []
e2ss = []
force_types = []
hfile = None
i = 0
while i < len(all_args):
    if all_args[i] == '-match':
        matches.append(all_args[i+1])
        bg_args.extend(all_args[i:i+2])
        i += 2
    elif all_args[i] == '-include':
        clang_args.extend(all_args[i:i+2])
        bg_args.extend(all_args[i:i+2])
        i += 2
    elif all_args[i] == '-enum2string':
        assert len(all_args) >= i + 4
        e2s = dict(zip(('prefix', 'fname', 'transform'), all_args[i+1:i+4]))
        e2s['transform'] = e2s['transform'].lower().strip().split()
        e2ss.append(e2s)
        i += 4
    elif all_args[i] == '-force-type':
        assert len(all_args) >= i + 3
        regex, ty = all_args[i+1:i+3]
        force_types.append((regex, ty))
        i += 3
    elif all_args[i].endswith('.h'):
        assert hfile is None
        bg_args.append('-include')
        bg_args.append(all_args[i])
        hfile = all_args[i]
        i += 1
    else:
        clang_args.append(all_args[i])
        bg_args.append(all_args[i])
        i += 1
assert hfile
print open('fmt/bind_defs.rs').read()

clang = subprocess.check_output(['clang', '-dD', '-E', hfile] + clang_args)

enums = ''
on = False
seen = set()
for line in clang.split('\n'):
    m = re.match('^# [0-9]* "([^"]*)"', line)
    if m:
        on = any(match in m.group(1) for match in matches)
        continue
    if not on: continue
    m = re.match('#define\s+([a-zA-Z0-9_]+)\s+(.*)', line)
    if m:
        name, val = m.groups()
        val = val.rstrip()
        if val.endswith('\\') or not val: continue
        if name in seen: continue
        enums += ' xxxenum%s = %s \n' % (name, val)
        seen.add(name)

        continue
enums_pp, stde = subprocess.Popen(['clang', '-E', '-include', hfile, '-x', 'c', '-'] + clang_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate(enums)
if stde:
    print >> sys.stderr, stde
    assert 0
enums_final = ''
for line in enums_pp.split('\n'):
    if re.match(' xxxenum[^ ]* = \(*[^"]', line):
        enums_final += 'enum { ' + line + ' };\n'
tf = tempfile.NamedTemporaryFile(suffix='_enums.h', delete=False)
tf.write(enums_final)
tf.close()

match = ['-match', 'enums.h'] if matches else []

bg = subprocess.check_output(['bindgen', '-allow-bitfields'] + match + bg_args + [tf.name])

os.unlink(tf.name)

bg = bg.replace('Struct_', '').replace('use libc::*;', '')

bg = re.sub(re.compile('(#\[repr\(C\)\]\n#\[derive\(Copy\)\]\npub struct.*?\n})', re.S), 'deriving_swap!(\n\\1\n);', bg)

consts = OrderedDict()
def f(m):
    name, ty, val = m.groups()
    if ty == '':
        for regex, _ty in force_types:
            if re.match(regex, name):
                ty = _ty
                break
        else:
            ty = 'i32' if val.startswith('-') else 'u32'
    val = int(val)
    if val < 0 and (ty.startswith('::libc::c_u') or ty.startswith('u')):
        # xxx bindgen bug?
        val = {'::libc::c_uint': 2**32, '::libc::c_ulong': 2**64, 'u32': 2**32, 'u64': 2**64}[ty] + val
    consts[name] = val
    return 'pub const %s: %s = %s;' % (name, ty, val)
bg = re.sub(re.compile('^pub const xxxenum([^ ]*):\s+(::libc::c_u?(?:int|long))\s+=\s+(-?[0-9]+);', re.S | re.M), f, bg)
bg = re.sub(re.compile('(?:^#\[[^\]]*\]\n)*^pub enum\s+[^ ]*\s+{\s+xxxenum([^ ]*)\s+=\s+()(-?[0-9]+),?\s+}', re.S | re.M), f, bg)
print bg
assert 'xxxenum' not in bg



for e2s in e2ss:
    print "pub fn %s(val: u32) -> Option<&'static str> {" % (e2s['fname'],)
    print "    match val {"
    rmap = {}
    for name, val in consts.items():
        if name.startswith(e2s['prefix']):
            rmap.setdefault(val, name) # first wins
    for val, name in sorted(rmap.items()):
        oname = name
        for trans in e2s['transform']:
            if trans == 'lower':
                oname = oname.lower()
            elif trans == 'strip_prefix':
                oname = oname[len(e2s['prefix']):]
            else:
                raise Exception('what is trans %r?' % (trans,))
        print "        %s => Some(\"%s\")," % (val, oname)
    print "        _ => None"
    print "    }"
    print "}"
