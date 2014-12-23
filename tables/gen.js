var fs = require('fs');
// this isn't a very efficient module, replace/
var HashMap = require('hashmap').HashMap;
// (node stable is really old and doesn't support Harmony iteration :()

function hex(n, len) {
    var s = '';
    for(var pos = len - 4; pos >= 0; pos -= 4) {
        s += '0123456789abcdef'[(n >> pos) & 0xf];
    }
    return s;
}

function pad(s, len) {
    s = String(s);
    while(s.length < len)
        s += ' ';
    return s;
}

function setdefault(obj, key, def) {
    var o = obj[key];
    if(typeof o === 'undefined')
        obj[key] = o = def;
    return o;
}

// tblgen already generates disassemblers, but:
// - They seem to be very inefficient; the fixed-length version has giant
// tables including *uleb128* run through an *interpreter* that branches one at
// a time (even though it's not a binary tree; the switch just gets generated
// as multiple compares!).  Ideally I only want a single indirect branch...
// Dolphin is actually a good model here.
// - I want to detect jumps very quickly.

function fillBuckets(buckets, insn, instKnown, start, end, n, builtUp) {
    if(n == end) {
        buckets[builtUp].push(insn);
        return;
    }
    var bit = instKnown[n];
    if(bit != 1) // 0 or 2
        fillBuckets(buckets, insn, instKnown, start, end, n+1, builtUp);
    if(bit != 0) // 1 or 2
        fillBuckets(buckets, insn, instKnown, start, end, n+1, builtUp | (1 << (n - start)));
}

function mask2bits(mask, bitLength) {
    var kb = [];
    for(var i = 0; i < bitLength; i++)
        kb.push((mask >> i) & 1);
    return kb;
}

var nullInstruction = {
    name: 'undefined',
    instKnownMask: 0,
    instKnownValue: 0,
    inst: [],
};


function takesPrecedence(insn, insn2) {
    return insn.instSpecificity >= insn2.instSpecificity;
}

function knocksOut(insn, insn2, bucketKnownMask, bucketKnownValue) {
    // Suppose insn2's mask matches.
    var hypotheticalKnownMask = bucketKnownMask | insn2.instKnownMask;
    var hypotheticalKnownValue = bucketKnownValue | (insn2.instKnownValue & hypotheticalKnownMask);
    return (
        insn != insn2 &&
        // If no possibility of narrowing it down with other bits...
        !(insn.instKnownMask & ~hypotheticalKnownMask) &&
        // And it implies insn matches...
        (hypotheticalKnownValue & insn.instKnownMask) == insn.instKnownValue &&
        // And insn takes precedence
        takesPrecedence(insn, insn2)
    );
}

var gdCache = {};
var choiceOverrides = {
    'PPC/*:00000000': [26, 6],
};

function genDisassemblerRec(insns, bitLength, knownMask, knownValue, useCache, name, depth, options) {
    //console.log(indent + insns.length);
    if(insns.length == 0)
        return {insn: nullInstruction};
    if(insns.length == 1) {
        return {
            insn: insns[0],
            knownMask: knownMask | insns[0].instKnownMask,
            knownValue: knownValue | insns[0].instKnownValue
        };
    }

    if(useCache) {
        var names = [];
        insns.forEach(function(insn) {
            names.push(insn.name);
            knownMask &= insn.instKnownMask;
            knownValue &= insn.instKnownMask;
        });
        names.push(knownMask);
        names.push(knownValue);
        var cacheKey = names.join(',');
        //console.log(cacheKey);
        var result = gdCache[cacheKey];
        if(typeof result !== 'undefined') {
            //console.log('cache hit');
            return result;
        }
    }
    var bestBuckets, bestStart, bestLength, bestMax = 10000;
    var maxLength = options.maxLength;
    var cacheCutoff = 4;

    function tryFilter(start, length) {
        var mask = ((1 << length) - 1) << start;
        if(length != 0 && (knownMask & mask) == mask) {
            // Useless, we know all these bits already.
            return;
        }
        var buckets = [];
        for(var i = 0; i < (1 << length); i++)
            buckets.push([]);
        insns.forEach(function(insn) {
            fillBuckets(buckets, insn, insn.instKnown, start, start + length, start, 0);
        });

        if(length <= cacheCutoff || insns.length < 10) {
            // There are sometimes instances of a general case and special
            // cases.  Deal with them as follows: if, assuming the bits known
            // in a bucket, one instruction is implied by another and also
            // takes precedence by being more specific, then remove the second.

            // More specific is not necessarily well defined, e.g. in Thumb,
            // 'add sp, sp' (0x44ed) could be match the general tADDhirr, but
            // also the equally specific tADDrSP or tADDspr.  Luckily, in those
            // cases, it comes out the same; in other conflicts, it does not,
            // and only the most specific is acceptable.

            // There's got to be a better way to do this, but I'm not sure what.

            var bucketKnownMask = knownMask | (((1 << length) - 1) << start);
            for(var i = 0; i < buckets.length; i++) {
                var bucket = buckets[i];
                if(bucket.length == 0)
                    continue;
                var bucketKnownValue = knownValue | (i << start);
                var cgs = {};
                bucket.forEach(function(insn) {
                    if(insn.conflictGroup != -1) {
                        setdefault(cgs, insn.conflictGroup, []).push(insn);
                    }
                });
                for(var cg in cgs) {
                    var conflictingInsns = cgs[cg];
                    conflictingInsns.forEach(function(insn) {
                        conflictingInsns.forEach(function(insn2) {
                            if(knocksOut(insn, insn2, bucketKnownMask, bucketKnownValue)) {
                                conflictingInsns.splice(conflictingInsns.indexOf(insn2), 1);
                                bucket.splice(bucket.indexOf(insn2), 1);
                                //console.log('Removing', insn.name, 'because of', insn2.name);
                            }
                        });
                    });
                }
            }
        }

        var max = 0; // maximum size of any of the buckets
        buckets.forEach(function(bucket) {
            if(bucket.length > max) max = bucket.length;
        });
        if(max < bestMax || (max == bestMax && length < bestLength)) {
            bestMax = max;
            bestBuckets = buckets;
            bestStart = start;
            bestLength = length;
        }
    }

    var override;
    // not currently used, but...
    if(depth <= 3 && (override = choiceOverrides[name + ':' + hex(knownMask, bitLength)])) {
        tryFilter(override[0], override[1]);
    } else {
        for(var length = 0; length <= maxLength; length++) {
            for(var start = 0; start <= (length == 0 ? 0 : bitLength - length); start++) {
                tryFilter(start, length);
            }
        }
    }

    if(bestMax == insns.length) {
        if(insns.length <= 3 && 1) {
            // Probably a case of one more specific, but too many
            // distinguishing bits for a regular mask to find.  At least
            // try to find one that takes precedence over all the others.
            // (Sigh...)
            outer:
            for(var i = 0, insn; insn = insns[i]; i++) {
                for(var j = 0, insn2; insn2 = insns[j]; j++) {
                    if(insn != insn2 && !takesPrecedence(insn, insn2)) {
                        continue outer;
                    }
                }
                var newInsns = insns.slice(0);
                newInsns.splice(i, 1);
                return gdCache[cacheKey] = {
                    isBinary: 1,
                    buckets: [
                        genDisassemblerRec(
                            newInsns,
                            bitLength,
                            knownMask,
                            knownValue,
                            false,
                            name,
                            depth + 1,
                            options
                        ),
                        genDisassemblerRec(
                            [insn],
                            bitLength,
                            knownMask,
                            knownValue,
                            false,
                            name,
                            depth + 1,
                            options
                        )
                    ],
                    possibilities: insns,
                    knownMask: knownMask,
                    knownValue: knownValue
                };

            }
        }
        console.log('Found conflict (' + insns.length + ' insns):');
        insns.forEach(function(insn) {
            console.log(pad(insn.name, 20), insn.instKnown.join(','));
        });
        console.log('');
        console.log(pad('(known?)', 20), mask2bits(knownMask, bitLength).join(','));
        return gdCache[cacheKey] = {insn: nullInstruction};
        throw '?';
    }

    var resultBuckets = [];
    for(var i = 0; i < bestBuckets.length; i++) {
        var bucket = bestBuckets[i];
        var bucketKnownMask = knownMask | (((1 << bestLength) - 1) << bestStart);
        var bucketKnownValue = knownValue | (i << bestStart);
        var useCache = bestLength > cacheCutoff && depth > 0;
        resultBuckets.push(genDisassemblerRec(
            bucket,
            bitLength,
            bucketKnownMask,
            bucketKnownValue,
            useCache,
            name,
            depth + 1,
            options
        ));
    }

    if(bestLength == 0) {
        return gdCache[cacheKey] = resultBuckets[0];
    }

    return gdCache[cacheKey] = {
        start: bestStart,
        length: bestLength,
        max: bestMax,
        buckets: resultBuckets,
        possibilities: insns,
        knownMask: knownMask,
        knownValue: knownValue
    };
}

function addConflictGroups(insns) {
    insns.forEach(function(insn) {
        insn.conflictGroup = -1;
    });
    var nextConflictGroup = 0;
    var seen = [];
    var cgs = {};
    insns.forEach(function(insn) {
        seen.forEach(function(insn2) {
            var bothKnown = insn.instKnownMask & insn2.instKnownMask;
            if(insn != insn2 && (insn.instKnownValue & bothKnown) == (insn2.instKnownValue & bothKnown)) {
                if(insn2.conflictGroup == -1) {
                    insn2.conflictGroup = nextConflictGroup++;
                    cgs[insn2.conflictGroup] = [insn2];
                }
                var cg1 = insn.conflictGroup, cg2 = insn2.conflictGroup;
                //console.log(insn.name, insn2.name, cg1, cg2);
                if(cg1 == cg2)
                    return;
                if(cg1 != -1) {
                    cgs[cg1].forEach(function(insn3) {
                        insn3.conflictGroup = insn2.conflictGroup;
                    });
                    cgs[cg2] = cgs[cg2].concat(cgs[cg1]);
                    cgs[cg1] = 123;
                } else {
                    insn.conflictGroup = insn2.conflictGroup;
                    cgs[cg2].push(insn);
                }
            }
        });
        seen.push(insn);
    });
}

function printConflictGroups(insns) {
    console.log('Total insns: ' + insns.length);
    var cgs = {};
    insns.forEach(function(insn) {
        if(insn.conflictGroup != -1) {
            setdefault(cgs, insn.conflictGroup, []).push(insn);
        }
    });
    for(var cg in cgs) {
        console.log(cg + ': (' + cgs[cg].length + ')');
        cgs[cg].forEach(function(insn) {
            console.log('  ', pad(insn.name, 20), 'spec:' + pad(insn.instSpecificity, 2), insn.instKnown.join(','));
        });
    }
}

function visitDag(pat, visitor) {
    if(Array.isArray(pat)) {
        visitor(pat);
        for(var i = 1; i < pat.length; i++)
            visitDag(pat[i], visitor);
    }
}

function printHeads(insns) {
    seen = {};
    insns.forEach(function(insn) {
        if(insn.pattern != '?' && insn.pattern.length) {
            visitDag(insn.pattern, function(tuple) {
                if(tuple[0].replace && tuple[0] !== ':')
                    seen[tuple[0]] = (seen[tuple[0]] || 0) + 1;
            });
            insn.pattern.forEach(add);
        } else {
            console.log('nopat ' + insn.name);
        }
    });
    var seen_l = [];
    for(var head in seen)
        seen_l.push([head, seen[head]]);
    seen_l.sort();
    seen_l.forEach(function(l) {
        console.log('head ' + l[0] + ' (' + l[1] + ')');
    });
}

function ppTable(node, indent, depth) {
    indent = (indent || '') + '  ';
    depth = (depth || 0) + 1;
    if(node.insn)
        return '<' + hex(node.knownValue, node.insn.inst.length) + '> insn:' + node.insn.name;
    var s = '{' + depth + '} ';
    if(typeof node.start !== 'undefined') {
        s += 'test ' + node.start + '..' + (node.start + node.length - 1);
    } else {
        s += 'test for second insn';
    }
    s += ' (' + node.possibilities.length + ' total insns - ';
    s += node.possibilities.map(function(i) { return i.name; }).join(',');
    s += '):\n';
    for(var i = 0; i < node.buckets.length; i++) {
        s += indent + pad(i, 4) + ': ' + ppTable(node.buckets[i], indent, depth) + '\n';
    }
    return s;
}

function tableToRust(node) {
    function depth(n) {
        return n.insn ? 0 : (1 + Math.max.apply(Math, n.buckets.map(depth)));
    }
    console.log('max depth: ' + depth(node));
    console.log(ppTable(node));
}

function checkTableMissingInsns(node, insns) {
    var used = {};
    function collect(node) {
        if(node.insn)
            used[node.insn.name] = 1;
        else
            node.buckets.map(collect);
    }
    collect(node);
    insns.forEach(function(insn) {
        if(!used[insn.name]) {
            console.log('** Table never decodes ' + insn.name);
        }
    });
}

function genDisassembler(insns, ns, options) {
    options.maxLength = options.maxLength || 11;

    var bitLength = insns[0].inst.length;
    var name = insns[0].namespace + '/' + ns;
    console.log(name, bitLength);
    // find potential conflicts (by brute force)
    addConflictGroups(insns);
    //console.log(insns.length);
    var node = genDisassemblerRec(insns, bitLength, 0, 0, false, name, 0, options);
    checkTableMissingInsns(node, insns);
    return node;
    //console.log(stuff);
}

function genSema(insns, ns) {
    var s = 'trait Sema' + ns + ' {\n';

}

function coalesceInsnsWithMap(insns, func) {
    var byGroup = new HashMap();
    insns.forEach(function(insn) {
        var key = func(insn);
        if(key === null)
            return;
        var ginsns = byGroup.get(key);
        if(!ginsns)
            byGroup.set(key, ginsns = []);
        ginsns.push(insn);
    });
    // for each group, continually coalesce instructions which are the same but for one bit, until we can do no more.  probably slooow
    // actually, not enough insns to be slow
    var out = [];
    var coalid = 0;
    byGroup.forEach(function(ginsns, key) {
        // inst -> null
        var byPat = new HashMap();
        ginsns.map(function(insn) {
            var instMinusVars = insn.inst.map(function(b) {
                return Array.isArray(b) ? '?' : b;
            });
            //console.log('**>', instMinusVars+'');
            byPat.set(instMinusVars, insn.inst);
        });
        do {
            var didSomething = false;
            //console.log('pass');
            // merge combinations that together take up the whole space
            byPat.forEach(function(_, inst) {
                for(var i = 0; i < inst.length; i++) {
                    var old = inst[i];
                    if(old == '?')
                        continue;
                    inst[i] = old == '1' ? '0' : '1';
                    if(byPat.has(inst)) {
                        byPat.remove(inst);
                        inst[i] = old;
                        byPat.remove(inst);
                        inst[i] = '?';
                        byPat.set(inst, null);
                        didSomething = true;
                        break;
                    }
                    inst[i] = old;
                }
            });

            //console.log('MD');
            // merge dominators; could be optimized
            byPat.forEach(function(_, inst) {
                byPat.forEach(function(_, inst2) {
                    if(inst2 === inst)
                        return;
                    for(var i = 0; i < inst.length; i++) {
                        var b1 = inst[i], b2 = inst2[i];
                        if(!(b1 == b2 || b1 == '?'))
                            return;
                    }
                    // ok, inst dominates inst2; we do not need to distinguish
                    byPat.remove(inst2);
                });
            });
            //console.log('MD+');
        } while(didSomething);

        var origLength = ginsns.length;
        var newLength = byPat.count();
        //console.log('collapsed', origLength, '-->', newLength);
        byPat.forEach(function(_, inst) {
            // make a fake insn
            var insn = {
                namespace: ns,
                inst: inst,
                name: 'coal' + (coalid++) + '_' + (origLength - newLength) + '*' + key,
            };
            fixInstruction(insn, /*noFlip*/ true);
            out.push(insn);
        });
    });
    return out;
}

function fixInstruction(insn, noFlip) {
    // Incoming goes from MSB to LSB, but we assume that inst[n] corresponds to
    // 1 << n, so reverse it.
    // But not on PPC...
    if(!noFlip && insn.namespace != 'PPC')
        insn.inst.reverse();

    insn.instKnownMask = 0;
    insn.instKnownValue = 0;
    insn.instSpecificity = 0;
    insn.instKnown = [];
    for(var i = 0; i < insn.inst.length; i++) {
        var bit = insn.inst[i];
        var res = bit === '0' ? 0 : bit === '1' ? 1 : 2;
        // filter out useless instructions
        if(res != 2) {
            insn.instKnownMask |= (1 << i);
            insn.instKnownValue |= (res << i);
            insn.instSpecificity++;
        }
        insn.instKnown.push(res);
    };
}

var getopt = require('node-getopt').create([
    ['n', 'namespace=ARG', 'Decoder namespace of instructions to use.'],
    ['',  'print-conflict-groups', 'Print potentially conflicting instructions.'],
    ['',  'print-heads', 'Print the DAG primitives that need to be implemented.'],
    ['d', 'gen-disassembler', 'Generate a full disassembler.'],
    //['',  'gen-branch-disassembler', 'Generate a branch-only disassembler.'],
    //['',  'gen-sema', 'Generate the step after the disassembler.'],
    ['',  'gen-hook-disassembler', 'Generate a disassembler that distinguishes address regs'],
    ['h', 'help', 'help'],
]).bindHelp();
getopt.setHelp(getopt.getHelp().replace('\n', ' input-file\n'));
function help() {
    getopt.showHelp();
    process.exit(0);
}
var opt = getopt.parseSystem();
if(opt.argv.length != 1) {
    help();
}

var input = JSON.parse(fs.readFileSync(opt.argv[0], 'utf-8'));
var inputInsns = input.instructions;

var insns = inputInsns.filter(function(insn) { return insn.instKnownMask != 0; });

var ns = '*';
if(typeof opt.options['namespace'] !== 'undefined') {
    ns = opt.options['namespace'];
    var dns;
    switch(ns) {
    case '_thumb':
        dns = ['Thumb', 'ThumbSBit'];
        break;
    case '_thumb2':
        dns = ['Thumb2', 'VFP'];
        break;
    case '_arm':
        dns = ['ARM', 'VFP'];
        break;
    default:
        dns = ns.split('|');
    }
    insns = insns.filter(function(insn) { return dns.indexOf(insn.decoderNamespace) != -1; });
}

inputInsns.forEach(function(insn) { fixInstruction(insn, false); });

addConflictGroups(insns);
if(opt.options['print-conflict-groups']) {
    printConflictGroups(insns);
}
if(opt.options['print-heads']) {
    printHeads(insns);
}
if(opt.options['gen-disassembler']) {
    genDisassembler(insns, ns, {});
    // tableToRust
}
if(opt.options['gen-hook-disassembler']) {
    var cantBePcModes = {
        // Thumb (most of the modes, for obvious reasons)
        't_addrmode_is4': true,
        't_addrmode_is2': true,
        't_addrmode_is1': true,
        't_addrmode_rr': true,
        't_addrmode_rrs1': true,
        't_addrmode_rrs2': true,
        't_addrmode_rrs4': true,
        't_addrmode_sp': true,

    };
    var insns2 = coalesceInsnsWithMap(insns, function(insn) {
        // This is not fully general.  But I don't think it's important to hook functions that do MUL PC, PC or crap like that...
        // This takes care of all load instructions, plus the first operand of ADD.
        var nbits = 0;
        var addrName;
        if(insn.name.match(/^PL/i))
            return null;
        var isAdd = !!insn.name.match(/^[^A-Z]*ADD/);
        var isMov = !!insn.name.match(/^[^A-Z]*MOV/);
        var isBranch = insn.isBranch;
        // Is it any type of load instruction?
        var mapped = insn.inst.map(function(bit) {
            if(bit[0] == 'addr' || (isAdd && bit[0] == 'Rm') || (isMov && bit[0] == 'Rm') || (isBranch && bit[0] == 'target')) {
                if(nbits && addrName != bit[0])
                    throw 'conflict';
                nbits++;
                addrName = bit[0];
                return bit[1];
            } else {
                return null;
            }
        });
        if(nbits) {
            if(nbits < 4)
                return null;
            var name = '';
            visitDag(insn.inOperandList, function(tuple) {
                if(tuple[0] == ':' && tuple[2] == '$'+addrName)
                    name = tuple[1];
            });
            if(!name) throw '? ' + insn.name;
            if(cantBePcModes[name])
                return null;
            name += '*' + mapped;
            console.log('representing', insn.name);
            return name;
        }
        return null;
    });
    //console.log(insns2);
    var node = genDisassembler(insns2, ns, {maxLength: 5});
    console.log(ppTable(node));
}
if(opt.options['gen-sema']) {
    genSema(insns, ns);
}
