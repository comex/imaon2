var fs = require('fs');
var sh = require('execSync');
var path = require('path');

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
function hexnopad(n) {
    if(n == 0)
        return '0';
    if(n < 0)
        n += 0x100000000;
    var s = '';
    while(n) {
        s = '0123456789abcdef'[n & 0xf] + s;
        n = parseInt(n / 16);
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

function setdefault_hashmap(obj, key, def) {
    var o = obj.get(key);
    if(typeof o === 'undefined')
        obj.set(key, o = def);
    return o;
}

// tblgen already generates disassemblers, but:
// - They seem to be very inefficient; the fixed-length version has giant
// tables including *uleb128* run through an *interpreter* that branches one at
// a time (even though it's not a binary tree; the switch just gets generated
// as multiple compares!).  Ideally I only want a single indirect branch...
// Dolphin is actually a good model here.
// - I want to detect jumps very quickly.

// Optimization: Returns true if we can skip this whole iteration due to losing to bestMax already.

function fillBuckets(buckets, bestMax, insn, instKnown, start, end, n, builtUp) {
    if(n > 0) {
        var old = n - 1;
        var ceb = insn.instConstrainedEqualBits[old];
        if(ceb !== undefined) {
            // Rule it out if it would violate a constraint.  Uncommon, speed doesn't matter
            var thisBit = (builtUp >> old) & 1;
            for(var i = 0; i < ceb.length; i++) {
                var thatBit = (builtUp >> ceb[i]) & 1;
                if(thisBit != thatBit) {
                    //console.log('ruling out ' + insn.name);
                    return false;
                }
            }
        }
    }
    if(n == end) {
        var l = buckets[builtUp];
        if(l.length > bestMax) {
            return true;
        }
        l.push(insn);
        return false;
    }
    var bit = instKnown[n];
    if(bit != 1) { // 0 or 2
        if(fillBuckets(buckets, bestMax, insn, instKnown, start, end, n+1, builtUp))
            return true;
    }
    if(bit != 0) { // 1 or 2
        if(fillBuckets(buckets, bestMax, insn, instKnown, start, end, n+1, builtUp | (1 << (n - start))))
            return true;
    }
    return false;
}

function mask2bits(mask, bitLength) {
    var kb = [];
    for(var i = 0; i < bitLength; i++)
        kb.push((mask >> i) & 1);
    return kb;
}

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
        // (hopefully we don't have to care about equality constraints -
        //  returning false is safe)
        !insn.instHaveAnyConstrainedEqualBits &&
        // And insn takes precedence
        takesPrecedence(insn, insn2)
    );
}

var choiceOverrides = {
    'PPC/*:00000000': [26, 6],
};

function genDisassemblerRec(insns, bitLength, knownMask, knownValue, useCache, depth, data) {
    //console.log(indent + insns.length);
    if(insns.length == 0)
        return data.failNode;
    if(insns.length == 1) {
        var insn = insns[0];
        if ((insn.instKnownMask & ~knownMask) == 0) {
            return {
                insn: insn,
                knownMask: knownMask,
                knownValue: knownValue
            };
        } else {
            return {
                isBinary: 1,
                buckets: [
                    {insn: insn, knownMask: knownMask | insn.instKnownMask, knownValue: knownValue | insn.instKnownValue},
                    data.failNode
                ],
                possibilities: insns,
                knownMask: knownMask,
                knownValue: knownValue
            };
        }
    }

    if(useCache) {
        var names = [];
        var m = 0;
        insns.forEach(function(insn) {
            names.push(insn.name);
            m |= insn.instDependsMask;
        });
        names.push(knownMask & m);
        names.push(knownValue & m);
        var cacheKey = names.join(',');
        var result = data.cache[cacheKey];
        if(typeof result !== 'undefined') {
            //console.log('cache hit');
            return result;
        }
    }
    var bestBuckets, bestStart, bestLength, bestMax = 1000000;
    var maxLength = data.maxLength;
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
        for(var i = 0; i < insns.length; i++) {
            var insn = insns[i];
            if(fillBuckets(buckets, bestMax, insn, insn.instKnown, start, start + length, start, 0)) {
                //console.log('early return');
                return;
            }
        }

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
    if(depth <= 3 && (override = choiceOverrides[data.uid + ':' + hex(knownMask, bitLength)])) {
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
                return data.cache[cacheKey] = {
                    isBinary: 1,
                    buckets: [
                        {insn: insn, knownMask: knownMask | insn.instKnownMask, knownValue: knownValue | insn.instKnownValue},
                        genDisassemblerRec(
                            newInsns,
                            bitLength,
                            knownMask,
                            knownValue,
                            false,
                            depth + 1,
                            data
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
        return data.cache[cacheKey] = data.failNode;
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
            depth + 1,
            data
        ));
    }

    if(bestLength == 0) {
        return data.cache[cacheKey] = resultBuckets[0];
    }

    return data.cache[cacheKey] = {
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
    if(!node.isBinary) {
        s += 'test ' + node.start + '..' + (node.start + node.length - 1);
    } else {
        s += 'test for first insn';
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

// [(pos1, pos2)] -> [(pos1, pos2, len)]
function bitPairsToRuns(bits) {
    var mine = [];
    bits.forEach(function(bit) {
        var last = mine[mine.length - 1];
        if(last && last[0] + last[2] == bit[0] && last[1] + last[2] == bit[1])
            last[2]++;
        else
            mine.push([bit[0], bit[1], 1]);
    });
    return mine;
}

// returns name -> [(oppos_lo, instpos_lo, len)]
function instToOpRuns(inst, removeDupes) {
    // name -> [(oppos, instpos)]
    var ops = {};
    var seen = {};
    for(var i = 0; i < inst.length; i++) {
        var bit = inst[i];
        if(!Array.isArray(bit))
            continue;
        if(removeDupes) {
            if(seen[bit])
                continue;
            seen[bit] = true;
        }
        setdefault(ops, bit[0], []).push([i, bit[1]]);
    }
    var out = {};
    for(var op in ops) {
        out[op] = bitPairsToRuns(ops[op]);
    }
    return out;
}

function opRunsToExtractionFormula(runs, inExpr, reverse) {
    var parts = [];
    runs.forEach(function(run) {
        // make a reverse function if necessary
        var inpos = run[0], outpos = run[1], len = run[2];
        var diff = inpos - outpos;
        var mask = ((1 << len) - 1) << inpos;
        var x = '(' + inExpr + ' & 0x' + hexnopad(mask) + ')';
        if(outpos < inpos)
            x = '(' + x + ' >> ' + (inpos - outpos) + ')';
        else if(outpos > inpos)
            x = '(' + x + ' << ' + (outpos - inpos) + ')';
        parts.push(x);
    });
    return parts.join(' | ');
}

function opRunsToBitsliceLiteral(runs, reverse) {
    var runLits = runs.map(function(run) { 
        return '{' + run + '}';
    });
    return '{.nruns = ' + runs.length + ', .runs = (struct bitslice_run[]) {' + runLits.join(', ') + '}}';
}

function genGeneratedWarning() {
    var describe = sh.exec('cd \'' + __dirname + '\'; git describe --abbrev=0 --dirty --always').stdout.trim();
    var cmdline = process.argv.slice(2).map(function(arg) {
        arg = arg.replace(/^.*imaon2\//, '');
        if(arg.indexOf(' ') !== -1)
            arg = "'" + arg + "'";
        return arg;
    }).join(' ');
    return ''+
'/* Generated code; do not edit!\n\
   generated by tables/gen.js from imaon2 \'DESCRIBE\';\n\
   https://github.com/comex/imaon2\n\
   arguments: CMDLINE\n\
   (fair warning: at present the main (Rust) code in that repository is barely\n\
    started, embarrassingly so; no need to look at it ;p)\n\
   In case it\'s copyrightable in any way, consider the generated code in the\n\
   public domain.\n\
*/\n'   .replace(/DESCRIBE/, describe).replace(/CMDLINE/, cmdline);
}

function genConstraintTest(insn, unknown, indent, andandFirstToo) {
    var ceb = insn.instConstrainedEqualBits;
    var pairs = [];
    for(var lo in ceb) {
        lo = parseInt(lo);
        ceb[lo].forEach(function(hi) {
            if(lo < hi)
                pairs.push([lo, hi]);
        });
    }
    var runs = bitPairsToRuns(pairs);
    var out = '';
    runs.forEach(function(run) {
        var mask = (1 << run[2]) - 1;
        var part = '((op >> ' + run[0] + ') & 0x' + hexnopad(mask) + ') == ' +
                   '((op >> ' + run[1] + ') & 0x' + hexnopad(mask) + ')';
        if(out || andandFirstToo)
            out += ' &&\n' + indent;
        out += part;
    });
    return out;
}

var indentStep = '    ';
function tableToSimpleCRec(node, pattern, extraArgs, prototypes, indent, skipConstraintTest) {
    var bits = [];
    var patternify = function(n) { return pattern.replace(/XXX/g, n); };
    var push = function(x) { bits.push(indent + x); };
    if(node.fail) {
        push('return ' + patternify('unidentified') + '(' + extraArgs + ');');
    } else if(node.insn) {
        var insn = node.insn;
        var unknown = insn.instDependsMask & ~node.knownMask;
        if(unknown && !skipConstraintTest) {
            push('if (!(' + genConstraintTest(insn, unknown, indent + '      ') + '))', false);
            push('    return ' + patternify('unidentified') + '(' + extraArgs + ');');
        }
        var runsByOp = instToOpRuns(insn.inst);
        var args = [extraArgs];
        var funcName = patternify(insn.groupName || insn.name);
        for(var op in runsByOp) {
            //push('unsigned ' + op + ' = ' + opRunsToExtractionFormula(runsByOp[op], 'op', false) + ';');
            push('struct bitslice ' + op + ' = ' + opRunsToBitsliceLiteral(runsByOp[op], 'op', false) + ';');
            args.push(op);
        }
        var hexComment = '0x'+hex(node.knownValue, insn.inst.length) + ' | 0x'+hex(~node.knownMask, insn.inst.length);
        push('return ' + funcName + '(' + args.join(', ') + '); /* ' + hexComment + ' */');
        // be helpful
        if(prototypes) {
            var prototype = 'static inline xxx ' + funcName + '(' + args.map(function(arg) { return 'struct bitslice ' + arg; }).join(', ') + ') {}';
            prototypes[prototype] = null;
        }
    } else if(node.isBinary) {
        var insn = node.buckets[0].insn;
        var unknown = insn.instDependsMask & ~node.knownMask;
        var test = 'if ((op & 0x' + hexnopad(insn.instKnownMask) + ') == 0x' + hexnopad(insn.instKnownValue);
        if(unknown) {
            test += genConstraintTest(insn, unknown, indent + '    ', true);
            test += ') { /* binary + constraints, yay */';
        } else {
            test += ') {';
        }
        push(test);
        bits.push(tableToSimpleCRec(node.buckets[0], pattern, extraArgs, prototypes, indent + indentStep, true));
        push('} else {');
        bits.push(tableToSimpleCRec(node.buckets[1], pattern, extraArgs, prototypes, indent + indentStep));
        push('}');
    } else {
        var buckets = node.buckets.slice(0);
        var cases = {};
        for(var i = 0; i < buckets.length; i++) {
            var subnode = buckets[i];
            if(subnode === null)
                continue;
            var myis = [i];
            for(var j = i + 1; j < buckets.length; j++) {
                if(buckets[j] === subnode) {
                    myis.push(j);
                    buckets[j] = null;
                }
            }
            var rec = tableToSimpleCRec(subnode, pattern, extraArgs, prototypes, indent + indentStep);
            var is = setdefault(cases, rec, []);
            is.push.apply(is, myis);
        }
        if((1 << node.length) != buckets.length)
            throw new Error('bad buckets length - ' + node.length + ' - ' + buckets.length);
        push('switch ((op >> ' + node.start + ') & 0x' + hexnopad((1 << node.length) - 1) + ') {');
        var ncases = 0;
        for(var rec in cases) {
            var is = cases[rec];
            is.forEach(function(i) {
                push('case ' + i + ':');
            });
            if(rec.indexOf('\n') !== -1) {
                bits[bits.length - 1] += ' {';
                bits.push(rec);
                push('}');
            } else {
                bits.push(rec);
            }
        }
        push('}');
    }
    return bits.join('\n');
}

function tableToSimpleC(node, pattern, extraArgs) {
    var prototypes = {};
    var ret = tableToSimpleCRec(node, pattern, extraArgs, prototypes, indentStep);
    var ps = '\n';
    var protoNames = [];
    for(var proto in prototypes)
        protoNames.push(proto);
    protoNames.sort();
    if(protoNames)
        ps += '/*\n' + protoNames.join('\n') + '\n*/\n';
    return ret + ps;
}

function checkTableMissingInsns(node, insns) {
    var used = {};
    function collect(node) {
        if(node.insn)
            used[node.insn.name] = 1;
        else if(node.buckets)
            node.buckets.map(collect);
    }
    collect(node);
    insns.forEach(function(insn) {
        if(!used[insn.name]) {
            console.log('** Table never decodes ' + insn.name);
        }
    });
}

// there are instructions that put, say, addr{12} in multiple locations in Inst to assert that the value is the same.

function genDisassembler(insns, ns, options) {
    options.maxLength = options.maxLength || 6;

    var bitLength = insns[0].inst.length;
    var uid = insns[0].namespace + '/' + ns;
    options.uid = uid;
    options.cache = {};
    options.insnNodeCache = {};
    options.failNode = {fail: true};
    //console.log('genDisassembler:', uid, bitLength);
    // find potential conflicts (by brute force)
    addConflictGroups(insns);
    //console.log(insns.length);
    var node = genDisassemblerRec(insns, bitLength, 0, 0, false, 0, options);
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
        var locs = '' + insn.inst.map(function(bit) { Array.isArray(bit) ? bit : '' });
        var realKey = [key, locs];
        var ginsns = setdefault_hashmap(byGroup, realKey, []);
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
            setdefault_hashmap(byPat, instMinusVars, []).push(insn);
        });
        do {
            var didSomething = false;
            //console.log('pass');
            // merge combinations that together take up the whole space
            // this ignores constraints; we can do that manually if necessary
            byPat.forEach(function(insns, inst) {
                for(var i = 0; i < inst.length; i++) {
                    var old = inst[i];
                    if(old == '?')
                        continue;
                    inst[i] = old == '1' ? '0' : '1';
                    var insns2;
                    if(insns2 = byPat.get(inst)) {
                        byPat.remove(inst);
                        inst[i] = old;
                        byPat.remove(inst);
                        inst[i] = '?';
                        byPat.set(inst, insns.concat(insns2));
                        didSomething = true;
                        break;
                    }
                    inst[i] = old;
                }
            });

            //console.log('MD');
            // merge dominators; could be optimized
            byPat.forEach(function(insns, inst) {
                byPat.forEach(function(insns2, inst2) {
                    if(inst2 === inst)
                        return;
                    for(var i = 0; i < inst.length; i++) {
                        var b1 = inst[i], b2 = inst2[i];
                        if(!(b1 == b2 || b1 == '?'))
                            return;
                    }
                    // ok, inst dominates inst2; we do not need to distinguish
                    insns.push.apply(insns, insns2);
                    byPat.remove(inst2);
                });
            });
            //console.log('MD+');
        } while(didSomething);

        var origLength = ginsns.length;
        var newLength = byPat.count();
        var groupName = key[0].replace(/[^a-zA-Z0-9_]+/g, '_') + '_' + + ginsns.length + '_' + ginsns[0].name;
        //console.log('collapsed', origLength, '-->', newLength);
        byPat.forEach(function(insns, inst) {
            insns.sort(); // get a consistent representative for the name
            // make a fake insn
            var oinst = insns[0].inst.slice(0);
            for(var i = 0; i < oinst.length; i++) {
                if(!Array.isArray(oinst[i]))
                    oinst[i] = inst[i];
            }
            var insn = {
                namespace: ns,
                inst: oinst,
                //name: 'coal' + (coalid++) + '_' + (origLength - newLength) + '*' + key,
                name: 'coal_' + insns.length + '_' + insns[0].name,
                groupName: groupName,
                groupInsns: ginsns,
            };
            //console.log(insn.name + ' >>>' + ginsns.map(function(i) { return i.name; }));
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
    insn.instDependsMask = 0;
    insn.instKnown = [];
    var bitEqualityConstraints = {};
    for(var i = 0; i < insn.inst.length; i++) {
        var bit = insn.inst[i];
        if(Array.isArray(bit))
            setdefault(bitEqualityConstraints, bit, []).push(i);
        var res = bit === '0' ? 0 : bit === '1' ? 1 : 2;

        // filter out useless instructions
        if(res != 2) {
            insn.instKnownMask |= (1 << i);
            insn.instKnownValue |= (res << i);
            insn.instSpecificity++;
        }
        insn.instKnown.push(res);
    };
    insn.instConstrainedEqualBits = {};
    insn.instHaveAnyConstrainedEqualBits = false;
    for(var k in bitEqualityConstraints) {
        var bits = bitEqualityConstraints[k];
        if(bits.length > 1) {
            bits.forEach(function(bit) {
                insn.instConstrainedEqualBits[bit] = bits.filter(function(bit2) { return bit2 != bit; });
                insn.instDependsMask |= (1 << i);
                insn.instHaveAnyConstrainedEqualBits = true;
            });
            //console.log('!', insn.name, insn.instConstrainedEqualBits);
        }
    }
}

var getopt = require('node-getopt').create([
    ['n', 'namespace=ARG', 'Decoder namespace of instructions to use.'],
    ['',  'print-conflict-groups', 'Print potentially conflicting instructions.'],
    ['',  'print-heads', 'Print the DAG primitives that need to be implemented.'],
    ['d', 'gen-disassembler', 'Generate a full disassembler.'],
    //['',  'gen-branch-disassembler', 'Generate a branch-only disassembler.'],
    //['',  'gen-sema', 'Generate the step after the disassembler.'],
    ['',  'gen-hook-disassembler', 'Generate a disassembler that distinguishes PC inputs and jumps'],
    ['',  'gen-hook-jump-disassembler', 'only jumps'],
    ['',  'extraction-formulas', 'Test extraction formulas'],
    ['',  'print-constrained-bits', 'Test constraints'],
    ['',  'dis-pattern=PATTERN', 'Pattern for function names from generated disassemblers, where XXX is replaced with our name'],
    ['',  'dis-extra-args=ARGS', 'More arguments to put in calls to user-implemented functions'],
    ['',  'print-insns', 'Just print them'],
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

insns.forEach(function(insn) { fixInstruction(insn, false); });

addConflictGroups(insns);
if(opt.options['print-conflict-groups']) {
    printConflictGroups(insns);
}
if(opt.options['print-heads']) {
    printHeads(insns);
}
if(opt.options['gen-disassembler']) {
    var node = genDisassembler(insns, ns, {});
    console.log(ppTable(node));
}
if(opt.options['gen-hook-disassembler']) {
    genHookDisassembler(true);
}
if(opt.options['gen-hook-jump-disassembler']) {
    genHookDisassembler(false);
}
function genHookDisassembler(includeNonJumps) {
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
        // This is not fully general.  But I don't think it's important to hook
        // functions that do MUL PC, PC or crap like that...  This takes care
        // of all load instructions (LLVM mashes both registers into one big
        // operand), plus ADD and MOV.
        if(insn.name.match(/^(t?2?PL|PRFM|LDNP|STNP)/i)) {
            return null;
        }
        var isBranch = insn.isBranch;
        /*
        if(includeNonJumps) {
            if(isBranch)
                ;
            else if(isInterestingLoad) {
                // force Rt to 15, xxx i'm not using this for now
            } else
                return null;
        }
        */
        if(!isBranch && !includeNonJumps)
            return null;
        var isAdd = !!insn.name.match(/^[^A-Z]*AD[DR]/);
        var isMov = !!insn.name.match(/^[^A-Z]*MOV/);
        var isLoad = !!insn.name.match(/^[^A-Z]*LD/);
        var isStore = !!insn.name.match(/^[^A-Z]*ST/);
        var isArmv8 = insn.namespace == 'AArch64';
        var interestingVars = {}; // vn -> num bits
        insn.inst.forEach(function(bit, i) {
            // this is currently ARM specific, obviously
            if(!Array.isArray(bit))
                return;
            var interesting;
            switch(insn.namespace) {
            case 'ARM':
                interesting =
                    bit[0] == 'addr' ||
                    bit[0] == 'offset' ||
                    bit[0] == 'label' ||
                    ((isAdd || isMov || isStore || isLoad) && (bit[0] == 'Rm' || bit[0] == 'Rn' || bit[0] == 'Rd' || bit[0] == 'shift')) ||
                    (isBranch && (bit[0] == 'target' || bit[0] == 'Rm')) ||
                    ((isStore || isLoad) && bit[0] == 'regs') ||
                    bit[0] == 'Rt';
                    // bit[0] == 'func'; /* get calls */
                break;
            case 'AArch64':
                // yay, highly restricted use of PC
                interesting = bit[0] == 'label' || bit[0] == 'addr' || (isBranch && bit[0] == 'target') ||
                    (insn.name.match(/^(LDR.*l|ADRP?)$/) && (bit[0] == 'Rt' || bit[0] == 'Xd')) || /* hack */
                    (insn.name == 'RET' && bit[0] == 'Rn');
                break;
            default:
                throw 'unknown namespace';
            }
            if(interesting)
                interestingVars[bit[0]] = (interestingVars[bit[0]] || 0) + 1;
        });
        visitDag(insn.inOperandList, function(tuple) {
            if(tuple[0] == ':' && tuple[2][0] == '$' && cantBePcModes[tuple[1]])
                delete interestingVars[tuple[2].substr(1)];
        });
        if(insn.namespace == 'ARM') {
            // pointless special case - yay thumb
            var someCouldBePc = false;
            for(var vn in interestingVars) {
                if(!(vn[0] == 'R' && interestingVars[vn] < 4)) {
                    someCouldBePc = true;
                    break;
                }
            }
            if(!someCouldBePc)
                return null;
        }
        insn.inst.forEach(function(bit, i) {
            if(Array.isArray(bit) && !interestingVars[bit[0]])
                insn.inst[i] = '?'; // redact
        });

        for(var haveAny in interestingVars) {
            /*
            happens sometimes
            if(nbits < opBitLocs.length)
                console.log('not all bit locs accounted for: ' + insn.name + ' : ' + JSON.stringify(insn.inst));
            */
            var nameBits = [];
            var seen = {};
            visitDag(insn.inOperandList, function(tuple) {
                var vn;
                if(tuple[0] == ':' && tuple[2][0] == '$' && interestingVars[vn = tuple[2].substr(1)]) {
                    seen[vn] = true;
                    nameBits.push(tuple[1] + ':' + tuple[2]);
                }
            });
            for(var vn in interestingVars) {
                if(!seen[vn])
                    nameBits.push('unk' + ':' + vn);
            }
            var name = nameBits.join(',');
            if(!name)
                return null;
            if(isBranch)
                name += ',B';
            if(isStore)
                name += ',S';
            //name += '*' + opBitLocs;
            //console.log('representing', insn.name, 'as', name);
            return name;
        }
        return null;
    });
    //insns2.forEach(function(insn) { console.log(insn); });
    //console.log(insns2);
    var node = genDisassembler(insns2, ns, {maxLength: 5});
    //console.log(ppTable(node));
    console.log(genGeneratedWarning());
    var xseen = {};
    insns2.forEach(function(insn) {
        if(xseen[insn.groupName])
            return;
        xseen[insn.groupName] = true;
        console.log('/* ' + insn.groupName + ': ' + insn.groupInsns.map(function(insn2) { return insn2.name; }).join(', ') + ' */');
    });
    console.log(tableToSimpleC(node, opt.options['dis-pattern'] || 'XXX', opt.options['dis-extra-args'] || 'ctx'));
}
if(opt.options['gen-sema']) {
    genSema(insns, ns);
}
if(opt.options['extraction-formulas']) {
    insns.forEach(function(insn) {
        console.log(insn.name);
        var runsByOp = instToOpRuns(insn.inst);
        for(var op in runsByOp)
            console.log('   ' + op + ': ' + opRunsToExtractionFormula(runsByOp[op], 'x', false));
    });
}
if(opt.options['print-constrained-bits']) {
    insns.forEach(function(insn) {
        if(insn.instHaveAnyConstrainedEqualBits) {
            console.log(insn.name);
            console.log(insn.instConstrainedEqualBits);
        }
    });
}
if(opt.options['print-insns']) {
    insns.forEach(function(insn) {
        console.log(insn);
    });
}
