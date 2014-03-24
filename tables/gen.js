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

function genDisassemblerRec(insns, bitLength, knownBits, maverick) {
    if(!insns || !insns.length) {
        return null;
    }
    if(insns.length == 1) {
        return {insn: insns[0].name};
    }
    var bestBuckets, bestStart, bestLength, bestMax = 10000;
    for(var length = 1; length <= 4; length++) {
        for(var start = 0; start <= bitLength - length; start++) {
            if(knownBits & (((1 << length) - 1) << start)) {
                // Some of the bits we want to use are actually known already.  If the known bits are contiguous, a shorter discriminator will be just as good.  If not, it won't, but whatever
                continue;

            }
            var buckets = [];
            insns.forEach(function(insn) {
                fillBuckets(buckets, insn, insn.instKnown, start, start + length, start, 0);
            });
            var max = 0;
            buckets.forEach(function(b) {
                if(maverick) {
                    var z = b.indexOf(maverick);
                    if(z != -1)
                        b.shift(z);
                }
                if(b.length > max) max = b.length;
            });
            if(max < bestMax) {
                bestMax = max;
                bestBuckets = buckets;
                bestStart = start;
                bestLength = length;
            }
        }
    }

    if(bestMax == insns.length) {
        // Mirror tablegen's wacky special case
        if(insns.length == 3 && !maverick) {
            // In ARM, there are sometimes a general case and special cases.  Like tblgen (though not quite the same way), if we're stuck here, ignore the general case in buckets which have any special cases.
            outer:
            for(var i = 0; i < insns.length; i++) {
                for(var j = 0; j < insns.length; j++) {
                    // Do we know something they don't?
                    if(insns[i].instKnownMask & ~insns[j].instKnownMask) 
                        continue outer;
                }
                return genDisassemblerRec(insns, bitLength, knownBits, insns[i]);
            }
        }
        console.log('Found conflict:');
        insns.forEach(function(insn) {
            console.log(pad(insn.name, 20), insn.instKnown.join(','));
        });
        throw '?';
    }


    var resultBuckets = [];
    for(var i = 0; i < bestBuckets.length; i++) {
        resultBuckets.push(genDisassemblerRec(bestBuckets[i], bitLength, knownBits | (((1 << bestLength) - 1) << bestStart), null));
    }

    return {start: bestStart, length: bestLength, max: bestMax, buckets: resultBuckets};
}


function genDisassembler(insns, name) {
    var bitLength = insns[0].inst.length;
    //console.log(insns.length);
    var stuff = genDisassemblerRec(insns, bitLength, 0, null);
    console.log(stuff);
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
    var insns = allInsns.filter(function(insn) { return insn.namespace == 'Thumb'; });
    genDisassembler(insns, 'Thumb');
}
