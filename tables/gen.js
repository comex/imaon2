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


function findDeferentialInstructions(conflictingInsns, bucketKnownMask, bucketKnownValue) {
    var toRemove = [];
    conflictingInsns.forEach(function(insn) {
        conflictingInsns.forEach(function(insn2) {
            // Suppose insn's mask matches.
            var hypotheticalKnownMask = bucketKnownMask | insn2.instKnownMask;
            var hypotheticalKnownValue = bucketKnownValue | (insn2.instKnownValue & hypotheticalKnownMask);
            if( insn != insn2 &&
                // If no possibility of narrowing it down with other bits...
                !(insn.instKnownMask & ~hypotheticalKnownMask) &&
                // And it implies insn2 matches...
                (hypotheticalKnownValue & insn.instKnownMask) == insn.instKnownValue &&
                // And insn takes precedence
                insn.instSpecificity >= insn2.instSpecificity) {
                conflictingInsns.splice(conflictingInsns.indexOf(insn2), 1);
                toRemove.push(insn2);
            }
        });
    });
    return toRemove;
}
function genDisassemblerRec(insns, bitLength, knownMask, knownValue) {
    if(insns.length == 0)
        return {insn: nullInstruction};
    if(insns.length == 1) {
        return {
            insn: insns[0],
            knownMask: knownMask | insns[0].instKnownMask,
            knownValue: knownValue | insns[0].instKnownValue
        };
    }

    var bestBuckets, bestStart, bestLength, bestMax = 10000;
    var maxLength = 5; //allowConflicts ? 8 : 4;
    for(var length = 0; length <= maxLength; length++) {
        for(var start = 0; start <= (length == 0 ? 0 : bitLength - length); start++) {
            var mask = ((1 << length) - 1) << start;
            if(length != 0 && (knownMask & mask) == mask) {
                // Useless, we know all these bits already.
                continue;
            }
            var buckets = [];
            for(var i = 0; i < (1 << length); i++)
                buckets.push([]);
            insns.forEach(function(insn) {
                fillBuckets(buckets, insn, insn.instKnown, start, start + length, start, 0);
            });

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
                    var toRemove = findDeferentialInstructions(conflictingInsns, bucketKnownMask, bucketKnownValue);
                    toRemove.forEach(function(insn2) {
                        bucket.splice(bucket.indexOf(insn2), 1);
                    });
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
    }

    if(bestMax == insns.length) {
        if(insns.length <= 3) {
            // Probably a case of one more specific, but too many
            // distinguishing bits for a regular mask to find.  Try to find one
            // that's strictly more specific than all others, and do a binary
            // test.  (Sigh...)
            outer:
            for(var i = 0, insn; insn = insns[i]; i++) {
                for(var j = 0, insn2; insn2 = insns[j]; j++) {
                    if(insn2.instKnownMask & ~insn.instKnownMask) {
                        // They know something we don't, we can't be the most specific
                        continue outer;
                    }
                }
                var newInsns = insns.slice(0);
                newInsns.splice(i, 1);
                return {
                    isBinary: 1,
                    buckets: [
                        genDisassemblerRec(
                            newInsns,
                            bitLength,
                            knownMask,
                            knownValue
                        ),
                        genDisassemblerRec(
                            [insn],
                            bitLength,
                            knownMask,
                            knownValue
                        )
                    ]
                };

            }
        }
        console.log('Found conflict (' + insns.length + ' insns):');
        insns.forEach(function(insn) {
            console.log(pad(insn.name, 20), insn.instKnown.join(','));
        });
        console.log('');
        console.log(pad('(known?)', 20), mask2bits(knownMask, bitLength).join(','));
        return {insn: nullInstruction};
        throw '?';
    }

    var resultBuckets = [];
    for(var i = 0; i < bestBuckets.length; i++) {
        var bucket = bestBuckets[i];
        resultBuckets.push(genDisassemblerRec(
            bucket,
            bitLength,
            knownMask | (((1 << bestLength) - 1) << bestStart),
            knownValue | (i << bestStart)));
    }

    if(bestLength == 0) {
        return resultBuckets[0];
    }

    return {
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
    var cgs = {};
    insns.forEach(function(insn) {
        if(insn.conflictGroup != -1) {
            setdefault(cgs, insn.conflictGroup, []).push(insn);
        }
    });
    for(var cg in cgs) {
        console.log(cg + ':');
        cgs[cg].forEach(function(insn) {
            console.log('  ', pad(insn.name, 20), 'spec:' + pad(insn.instSpecificity, 2), insn.instKnown.join(','));
        });
    }
}

function ppTable(node, indent) {
    if(node.insn)
        return '<' + hex(node.knownValue, node.insn.inst.length) + '> insn:' + node.insn.name;
    var s = 'test ' + node.start + '..' + (node.start + node.length - 1) + ' (' + node.possibilities.length + ' total insns - ';
    s += node.possibilities.map(function(i) { return i.name; }).join(',');
    s += '):\n';
    indent = (indent || '') + '  ';
    for(var i = 0; i < node.buckets.length; i++) {
        s += indent + pad(i, 4) + ': ' + ppTable(node.buckets[i], indent) + '\n';
    }
    return s;
}

function tableToRust(node) {
    function depth(n) {
        return 1 + ((!n || n.insn) ? 0 : Math.max.apply(Math, n.buckets.map(depth)));
    }
    console.log(depth(node));
    //console.log(ppTable(node));
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

function genDisassembler(insns, name) {
    var bitLength = insns[0].inst.length;
    // find potential conflicts (by brute force)
    addConflictGroups(insns);
    //console.log(insns.length);
    var node = genDisassemblerRec(insns, bitLength, 0, null);
    checkTableMissingInsns(node, insns);
    return tableToRust(node);
    //console.log(stuff);
}

function fixInstruction(insn) {
    // Incoming goes from MSB to LSB, but we assume that inst[n] corresponds to
    // 1 << n, so reverse it.
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
    ['',  'print-conflict-groups', 'Print potentially conflicting instructions.'],
    ['d', 'gen-disassembler', 'Generate a full disassembler.'],
    ['',  'gen-branch-disassembler', 'Generate a branch-only disassembler.'],
    ['n', 'namespace=ARG', 'Decoder namespace of instructions to use.'],
    // ...
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

var inputInsns = JSON.parse(fs.readFileSync(opt.argv[0], 'utf-8'));
inputInsns.forEach(fixInstruction);
var allInsns = inputInsns.filter(function(insn) { return insn.instKnownMask != 0; });

var insns = allInsns;
if(typeof opt.options['namespace'] !== 'undefined') {
    insns = insns.filter(function(insn) { return insn.namespace == opt.options['namespace']; });
}
addConflictGroups(insns);
if(opt.options['print-conflict-groups']) {
    printConflictGroups(insns);
}
if(opt.options['gen-disassembler']) {
    genDisassembler(insns, 'Thumb');
}
