var fs = require('fs');
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

function genDisassemblerRec(insns, bitLength, knownMask, knownValue, useCache, name, depth) {
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
    var maxLength = 11; //allowConflicts ? 8 : 4;
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
                            depth + 1
                        ),
                        genDisassemblerRec(
                            [insn],
                            bitLength,
                            knownMask,
                            knownValue,
                            false,
                            name,
                            depth + 1
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
            depth + 1
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

function printHeads(insns) {
    seen = {};
    function add(pat) {
        if(!Array.isArray(pat) || pat[0] == ':')
            return;
        if(pat[0].replace)
            seen[pat[0]] = (seen[pat[0]] || 0) + 1;
        for(var i = 1; i < pat.length; i++)
            add(pat[i]);
    }
    insns.forEach(function(insn) {
        if(insn.pattern != '?' && insn.pattern.length) {
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

function genDisassembler(insns, ns) {
    var bitLength = insns[0].inst.length;
    var name = insns[0].namespace + '/' + ns;
    console.log(name, bitLength);
    // find potential conflicts (by brute force)
    addConflictGroups(insns);
    //console.log(insns.length);
    var node = genDisassemblerRec(insns, bitLength, 0, 0, false, name, 0);
    checkTableMissingInsns(node, insns);
    return tableToRust(node);
    //console.log(stuff);
}

function genSema(insns, ns) {
    var s = 'trait Sema' + ns + ' {\n';

}

function fixInstruction(insn, patternOperators) {
    // Incoming goes from MSB to LSB, but we assume that inst[n] corresponds to
    // 1 << n, so reverse it.
    // But not on PPC...
    if(insn.namespace != 'PPC')
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

    patternOperators
}

var getopt = require('node-getopt').create([
    ['n', 'namespace=ARG', 'Decoder namespace of instructions to use.'],
    ['',  'print-conflict-groups', 'Print potentially conflicting instructions.'],
    ['',  'print-heads', 'Print what needs to be done.'],
    ['d', 'gen-disassembler', 'Generate a full disassembler.'],
    ['',  'gen-branch-disassembler', 'Generate a branch-only disassembler.'],
    ['',  'gen-sema', 'Generate the step after the disassembler.'],
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
    insns = insns.filter(function(insn) { return insn.decoderNamespace == opt.options['namespace']; });
    ns = opt.optons['namespace'];
}

inputInsns.forEach(function(insn) { fixInstruction(insn, input.patternOperators); });

addConflictGroups(insns);
if(opt.options['print-conflict-groups']) {
    printConflictGroups(insns);
}
if(opt.options['print-heads']) {
    printHeads(insns);
}
if(opt.options['gen-disassembler']) {
    genDisassembler(insns, ns);
}
if(opt.options['gen-sema']) {
    genSema(insns, ns);
}
