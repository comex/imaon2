import sys, re
import pyparsing as p
p.ParserElement.enablePackrat()

# p.delimitedList expects one or more
def delimited(e):
  e = p.Group(e)
  return p.Group(p.Optional(e + p.ZeroOrMore(',' + e)))

ochars = '_<>$'
word = p.Word(p.alphas + ochars, p.alphanums + ochars)

expr = p.Forward()
expr_int = p.Word(p.nums + '-')
expr_dag = '(' + word('func') + delimited(expr) + ')'
expr_list = '[' + delimited(expr) + ']'
expr_string = p.QuotedString('"')
bit = p.Literal('0') | p.Literal('1') | p.Literal('?') | (word('field') + '{' + expr_int('bit') + '}')
expr_bits = '{' + delimited(bit) + '}'
expr_tagged = word('tag') + ':' + word('val')
expr_unk = p.Literal('?')
expr_etc = word

expr << (expr_list('list') | expr_dag('dag') | expr_string('str') | expr_int('int') | expr_bits('bits') | expr_unk('unk') | expr_tagged('tagged') | expr_etc('etc'))

prop = p.Optional('field') + word('type') - (p.Optional(word('namecls') + ':') + word('name')) - '=' - p.Group(expr)('value') - ';'
def_ =  'def ' - word('defname') - '{' - p.Regex('\/\/.*')('supers') - p.ZeroOrMore(p.Group(prop)('props')) - '}'

main = p.OneOrMore(p.Group(def_))

data = open(sys.argv[1]).read()
data = re.split('--- Defs ---.*', data)[1] # skipto is slow for some reason?

result = main.parseString(data)
print result.asXML()
