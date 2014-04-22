import sys, subprocess, re, tempfile
infile = sys.argv[1]
all_args = sys.argv[2:]
matches = []
args = []
i = 0
while i < len(all_args):
    if all_args[i] == '-match':
        matches.append(all_args[i+1])
        i += 2
    else:
        args.append(all_args[i])
        i += 1

print open('fmt/bind_defs.rs').read()
bg = subprocess.check_output(['externals/rust-bindgen/bindgen', '-allow-bitfields', infile] + all_args)
bg = bg.replace('Struct_', '').replace('use libc::*;', '')
def f(m):
    # shouldn't have to do it here, ew
    decl, name = m.groups()
    if name.endswith('_64'):
        twin = name[:-3]
    elif 'Elf64_' in name:
        twin = name.replace('Elf64_', 'Elf32_')
    else:
        twin = None
    return 'deriving_swap!(\n' + ('twin %s\n' % twin if twin else '') + decl + ')\n'
bg = re.sub(re.compile('(pub struct ([^ ]+).*?\n})', re.S), f, bg)

print bg
print '// start of macros'

clang = subprocess.check_output(['clang', '-dD', '-E', infile] + args)

to_compile = ''

on = False
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
        to_compile += 'pub static xxx%s: uint = %s;\n' % (name, val)


        continue

# one more run through
final, stde = subprocess.Popen(['clang', '-E', '-include', infile, '-x', 'c', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate(to_compile)
if stde:
    print >> sys.stderr, stde
    assert 0
for line in final.split('\n'):
    if 'static xxx' in line and not ('"' in line or 'sizeof' in line or '*' in line or '{' in line):
        # remove casts
        line = re.sub('\([a-z][a-zA-Z0-9_]+\)', '', line)
        line = line.replace('0X', '0x')
        print line.replace('xxx', '')
