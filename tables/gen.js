var fs = require('fs');
// (node stable is really old and doesn't support Harmony iteration :()

function pad(s, len) {
    while(s.length < len)
        s += ' ';
    return s;
}

// tblgen already generates disassemblers, but:
// - They seem to be very inefficient; the fixed-length version has giant
// tables including *uleb128* run through an *interpreter* that branches one at
// a time (even though it's not a binary tree; the switch just gets generated
// as multiple compares!).  Ideally I only want a single indirect branch...
// Dolphin is actually a good model here.
// - I want to detect jumps very quickly.

// Note: knownBits and builtUp are actually backwards.  Whatever.

function fillBuckets(buckets, insn, instKnown, start, end, n, builtUp) {
    if(n == end) {
        var l = buckets[builtUp];
        if(!l)
            buckets[builtUp] = l = [];
        l.push(insn);
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

function genDisassemblerRec(insns, bitLength, knownBits, allowConflicts) {
    if(!insns || !insns.length) {
        return null;
    }
    if(insns.length == 1) {
        return {insn: insns[0].name};
    }
    if(allowConflicts) {
        var knownBitsIfValidInsn = 0xffffffff;
        insns.forEach(function(insn) {
            knownBitsIfValidInsn &= insn.instKnownMask;
        });
    }
    var bestBuckets, bestStart, bestLength, bestMax = 10000;
    var maxLength = allowConflicts ? 8 : 4;
    for(var length = 1; length <= maxLength; length++) {
        for(var start = 0; start <= bitLength - length; start++) {
            var mask = ((1 << length) - 1) << start;
            if((knownBits & mask) == mask) {
                // Useless, we know all these bits already.
                continue;

            }
            var buckets = [];
            insns.forEach(function(insn) {
                fillBuckets(buckets, insn, insn.instKnown, start, start + length, start, 0, allowConflicts);
            });
            if(allowConflicts) {
                // In ARM, there are sometimes a general case and special
                // cases.  Deal with it as follows: if multiple instructions'
                // patterns are necessarily satisfied in a bucket, pick the
                // most specific one.
                // This is not necessarily well defined, e.g. in Thumb, 'add
                // sp, sp' (0x44ed) could be match the general tADDhirr, but
                // also the equally specific tADDrSP or tADDspr.  Luckily, in
                // those cases, it comes out the same... (in others, it does
                // not).
                // It may be possible to make the tree shorter by doing this in
                // another way.
                var bucketKnownBits = knownBitsIfValidInsn | (((1 << length) - 1) << start);
                console.log(pad('(considering)', 20), mask2bits(bucketKnownBits, bitLength).join(','));
                var k = 0;
                buckets.forEach(function(bucket) {
                    if(bucketKnownBits == -1)
                        console.log('*', mask2bits(knownBitsIfValidInsn | ((k++) << start), bitLength).join(','));
                    retry: while(1) {
                        var covering = bucket.filter(function(insn) { return !(insn.instKnownMask & ~bucketKnownBits); });
                        if(covering.length > 1) {
                            if(bucketKnownBits == -1)
                                console.log('<-', covering.map(function(insn) { return insn.name; }));
                            for(var i = 0; i < covering.length; i++) {
                                if(covering.every(function(insn) { return !(covering[i].instKnownMask & ~insn.instKnownMask); })) {
                                    if(bucketKnownBits == -1)
                                    console.log('Removing', covering[i].name);
                                    bucket.splice(bucket.indexOf(covering[i]), 1);
                                    continue retry;
                                }
                            }
                        }
                        break;
                    }
                });
            }
            var max = 0; // maximum size of any of the buckets
            buckets.forEach(function(bucket) {
                if(bucket.length > max) max = bucket.length;
            });
            if(allowConflicts && bucketKnownBits == -1)
                console.log('<<<<<<<', max);
            if(max < bestMax || (max == bestMax && length < bestLength)) {
                bestMax = max;
                bestBuckets = buckets;
                bestStart = start;
                bestLength = length;
            }
        }
    }

    if(bestMax == insns.length) {
        // Mirror tblgen's wacky special case (though not quite the same algorithm)
        if(insns.length == 42 && !allowConflicts) {
            return genDisassemblerRec(insns, bitLength, knownBits, true);
        }
        console.log('Found conflict:');
        insns.forEach(function(insn) {
            console.log(pad(insn.name, 20), insn.instKnown.join(','));
        });
        console.log('');
        console.log(pad('(known?)', 20), mask2bits(knownBits, bitLength).join(','));
        if(allowConflicts)
            console.log(pad('(known if valid?)', 20), mask2bits(knownBitsIfValidInsn, bitLength).join(','));
        return '';
        throw '?';
    }


    var resultBuckets = [];
    bestBuckets.forEach(function(bucket) {
        resultBuckets.push(genDisassemblerRec(bucket, bitLength, knownBits | (((1 << bestLength) - 1) << bestStart), null));
    });

    return {start: bestStart, length: bestLength, max: bestMax, buckets: resultBuckets};
}


function genDisassembler(insns, name) {
    var bitLength = insns[0].inst.length;
    //console.log(insns.length);
    var stuff = genDisassemblerRec(insns, bitLength, 0, null);
    //console.log(stuff);
}


var getopt = require('node-getopt').create([
    ['', 'gen-disassembler', 'Generate a full disassembler.'],
    ['', 'gen-branch-disassembler', 'Generate a branch-only disassembler.'],
    // ...
    ['h', 'help', 'help'],
]).bindHelp();
getopt.setHelp(getopt.getHelp().replace('\n', ' input-file\n'));
var opt = getopt.parseSystem();
if(opt.argv.length != 1) {
    getopt.showHelp();
    process.exit(0);
}

var inputInsns = JSON.parse(fs.readFileSync(opt.argv[0], 'utf-8'));
var allInsns = [];
inputInsns.forEach(function(insn) {
    insn.instKnownMask = 0;
    insn.instKnown = [];
    for(var i = 0; i < insn.inst.length; i++) {
        var bit = insn.inst[i];
        var res = bit === '0' ? 0 : bit === '1' ? 1 : 2;
        // filter out useless instructions
        if(res != 2)
            insn.instKnownMask |= (1 << i);
        insn.instKnown.push(res);
    };
    if(insn.instKnownMask != 0)
        allInsns.push(insn);
});
if(opt.options['gen-disassembler']) {
    var insns = allInsns.filter(function(insn) { return insn.namespace == 'Thumb2'; });
    genDisassembler(insns, 'Thumb');
}
