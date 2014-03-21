var fs = require('fs');

var stuff = fs.readFileSync(process.argv[2], 'utf-8');
var idx = 0;

stuff = stuff.substr(stuff.indexOf('------------- Defs -----------------\n') + 37);

the_line = '<not yet>';

function assert(x) {
    if(!x) {
        console.trace('Parse error on <' + the_line + '> [' + stuff.substr(idx, 5) + ']');
        throw '!';
    }
}

function until(re) {
    var o = idx;
    while(idx != stuff.length && stuff[idx].match(re) === null)
        idx++;
    var s = stuff.substring(o, idx);
    skipwhite();
    return s;
}

function sym() {
    var s = until(/^[^a-zA-Z0-9_<>\$]$/);
    assert(s.length != 0);
    return s;
}

function lit(s) {
    var actual = stuff.substr(idx, s.length);
    assert(actual == s);
    idx += s.length;
    skipwhite();
}

function peek() {
    assert(idx != stuff.length);
    return stuff[idx];
}

function skip() {
    var c = peek();
    idx++;
    skipwhite();
    return c;
}

function try_skip(c) {
    if(peek() != c)
        return false;
    return skip();
}

function nl() {
    assert(try_skip('\n'));
    the_line = stuff.substring(idx, stuff.indexOf('\n', idx));
}

function skipwhite() {
    while(peek().match(/^[ \t]$/)) idx++;
}

function delimited(cb, end) {
    var r = [];
    while(!try_skip(end)) {
        r.push(cb());
        if(try_skip(end)) break;
        assert(try_skip(','));
    }
    return r;
}

function bit() {
    switch(peek()) {
        case '0':
            skip(); return 0;
        case '1':
            skip(); return 1;
        case '?':
            skip(); return -1;
        default:
            var field = sym();
            assert(try_skip('{'));
            var bit = parseInt(sym());
            assert(try_skip('}'));
            return {field: field, bit: bit};
    }
}

function expr() {
    var c = peek();
    switch(c) {
        case '(':
            idx++;
            return {type: 'dag', head: sym(), tail: delimited(expr, ')')};
        case '[':
            idx++;
            return {type: 'list', vals: delimited(expr, ']')};
        case '{':
            skip();
            return {type: 'bits', vals: delimited(bit, '}')};
        case '"':
            idx++;
            var s = until('"');
            idx++;
            return {type: 'str', str: s};
        case '?':
            idx++;
            return {type: 'unk'}
    }
    if(c.match(/^[0-9-]$/))
        return {type: 'int', int: parseInt(until(/[^0-9-]/))};
    var s = sym();
    if(try_skip(':'))
        return {type: 'tagged', tag: s, sym: sym()};
    return {type: 'sym', sym: s};
}

while(idx != stuff.length) {
    lit('def');
    var name = sym();
    lit('{');
    var supers = [];
    if(peek() != '\n') {
        lit('//');
        while(peek() != '\n')
            supers.push(sym());
    }
    nl();
    var fields = [];
    while(1) {
        if(try_skip('}')) { nl(); break; }
        var type = sym();
        if(type == 'field') type = sym();
        var varname = sym(), varcls = '';
        if(try_skip(':')) {
            varcls = varname;
            varname = sym();
        }
        lit('=');
        var val = expr();
        fields.push({type: type, name: varname, cls: varcls, val: val});
        lit(';');
        nl();
    }
    console.log(fields);

}
