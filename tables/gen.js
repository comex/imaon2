"use strict";
let fs = require('fs');
let path = require('path');

// this isn't a very efficient module,
//    (but ES6 Map is *less* efficient!?)
let HashMap = require('hashmap').HashMap;
let child_process = require('child_process');

function hex(n, len) {
    let s = '';
    for(let pos = len - 4; pos >= 0; pos -= 4) {
        s += '0123456789abcdef'[(n >> pos) & 0xf];
    }
    return s;
}
function hexnopad(n) {
    if(n == 0)
        return '0';
    if(n < 0)
        n += 0x100000000;
    let s = '';
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
    let o = obj[key];
    if(typeof o === 'undefined')
        obj[key] = o = def;
    return o;
}

function setdefault_hashmap(obj, key, def) {
    let o = obj.get(key);
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
        let old = n - 1;
        let ceb = insn.instConstrainedEqualBits[old];
        if(ceb !== undefined) {
            // Rule it out if it would violate a constraint.  Uncommon, speed doesn't matter
            let thisBit = (builtUp >> old) & 1;
            for(let i = 0; i < ceb.length; i++) {
                let thatBit = (builtUp >> ceb[i]) & 1;
                if(thisBit != thatBit) {
                    //console.log('ruling out ' + insn.name);
                    return false;
                }
            }
        }
    }
    if(n == end) {
        let l = buckets[builtUp];
        if(l.length > bestMax) {
            return true;
        }
        l.push(insn);
        return false;
    }
    let bit = instKnown[n];
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
    let kb = [];
    for(let i = 0; i < bitLength; i++)
        kb.push((mask >> i) & 1);
    return kb;
}

function takesPrecedence(insn, insn2) {
    return insn.instSpecificity >= insn2.instSpecificity;
}

function knocksOut(insn, insn2, bucketKnownMask, bucketKnownValue) {
    // Suppose insn2's mask matches.
    let hypotheticalKnownMask = bucketKnownMask | insn2.instKnownMask;
    let hypotheticalKnownValue = bucketKnownValue | (insn2.instKnownValue & hypotheticalKnownMask);
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

let choiceOverrides = {
    'PPC/*:00000000': [26, 6],
};

function genDisassemblerRec(insns, knownMask, knownValue, useCache, depth, data) {
    //console.log(depth + ' ' + insns.length + ' $ ' + useCache);
    if(insns.length == 0)
        return data.failNode;

    let cacheKey;
    if(useCache) {
        let names = [];
        let m = 0;
        for(let insn of insns) {
            names.push(insn.name);
            m |= insn.instDependsMask;
        }
        names.push(knownMask &= m);
        names.push(knownValue &= m);
        cacheKey = names.join(',');
        //console.log(cacheKey);
        let result = data.cache[cacheKey];
        if(typeof result !== 'undefined') {
            //console.log('cache hit');
            return result;
        }
    }

    if(insns.length == 1) {
        let insn = insns[0];
        if ((insn.instKnownMask & ~knownMask) == 0) {
            return data.cache[cacheKey] = {
                insn: insn,
                knownMask: knownMask,
                knownValue: knownValue
            };
        } else {
            return data.cache[cacheKey] = {
                isBinary: 1,
                buckets: [
                    genDisassemblerRec([insn], knownMask | insn.instKnownMask, knownValue | insn.instKnownValue, useCache, depth + 1, data),
                    data.failNode
                ],
                possibilities: insns,
                knownMask: knownMask,
                knownValue: knownValue
            };
        }
    }

    let bestBuckets, bestStart, bestLength, bestMax = 1000000;
    let maxLength = data.maxLength;
    let cacheCutoff = 4;

    function tryFilter(start, length) {
        let mask = ((1 << length) - 1) << start;
        if(length != 0 && (knownMask & mask) == mask) {
            // Useless, we know all these bits already.
            return;
        }
        let buckets = [];
        for(let i = 0; i < (1 << length); i++)
            buckets.push([]);
        for(let i = 0; i < insns.length; i++) {
            let insn = insns[i];
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

            let bucketKnownMask = knownMask | (((1 << length) - 1) << start);
            for(let i = 0; i < buckets.length; i++) {
                let bucket = buckets[i];
                if(bucket.length == 0)
                    continue;
                let bucketKnownValue = knownValue | (i << start);
                let cgs = {};
                for(let insn of bucket) {
                    if(insn.conflictGroup != -1) {
                        setdefault(cgs, insn.conflictGroup, []).push(insn);
                    }
                }
                for(let cg in cgs) {
                    let conflictingInsns = cgs[cg];
                    for(let insn of conflictingInsns) {
                        for(let insn2 of conflictingInsns) {
                            if(knocksOut(insn, insn2, bucketKnownMask, bucketKnownValue)) {
                                conflictingInsns.splice(conflictingInsns.indexOf(insn2), 1);
                                bucket.splice(bucket.indexOf(insn2), 1);
                                //console.log('Removing', insn.name, 'because of', insn2.name);
                            }
                        }
                    }
                }
            }
        }

        let max = 0; // maximum size of any of the buckets
        for(let bucket of buckets)
            if(bucket.length > max) max = bucket.length;
        if(max < bestMax || (max == bestMax && length < bestLength)) {
            bestMax = max;
            bestBuckets = buckets;
            bestStart = start;
            bestLength = length;
        }
    }

    let override;
    // not currently used, but...
    if(depth <= 3 && (override = choiceOverrides[data.uid + ':' + hex(knownMask, data.bitLength)])) {
        tryFilter(override[0], override[1]);
    } else {
        for(let length = 0; length <= maxLength; length++) {
            for(let start = 0; start <= (length == 0 ? 0 : data.bitLength - length); start++) {
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
            for(let i = 0, insn; insn = insns[i]; i++) {
                for(let j = 0, insn2; insn2 = insns[j]; j++) {
                    if(insn != insn2 && !takesPrecedence(insn, insn2)) {
                        continue outer;
                    }
                }
                let newInsns = insns.slice(0);
                newInsns.splice(i, 1);
                return data.cache[cacheKey] = {
                    isBinary: 1,
                    buckets: [
                        genDisassemblerRec([insn], knownMask | insn.instKnownMask, knownValue | insn.instKnownValue, useCache, depth + 1, data),
                        genDisassemblerRec(newInsns, knownMask, knownValue, false, depth + 1, data)
                    ],
                    possibilities: insns,
                    knownMask: knownMask,
                    knownValue: knownValue
                };

            }
        }
        console.log('Found conflict (' + insns.length + ' insns):');
        for(let insn of insns)
            console.log(pad(insn.name, 20), insn.instKnown.join(','));
        console.log('');
        console.log(pad('(known?)', 20), mask2bits(knownMask, data.bitLength).join(','));
        return data.cache[cacheKey] = data.failNode;
        throw '?';
    }

    let resultBuckets = [];
    for(let i = 0; i < bestBuckets.length; i++) {
        let bucket = bestBuckets[i];
        let bucketKnownMask = knownMask | (((1 << bestLength) - 1) << bestStart);
        let bucketKnownValue = knownValue | (i << bestStart);
        //let useCache = bestLength > cacheCutoff && depth > 0;
        // ^ this makes no sense?
        resultBuckets.push(genDisassemblerRec(bucket, bucketKnownMask, bucketKnownValue, useCache, depth + 1, data));
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

function genDisassembler(insns, ns, options) {
    options.maxLength = options.maxLength || 6;

    let uid = insns[0].namespace + '/' + ns;
    let data = options;
    data.uid = uid;
    data.cache = {};
    data.insnNodeCache = {};
    data.failNode = {fail: true};
    data.bitLength = insns[0].inst.length;
    //console.log('genDisassembler:', uid, bitLength);
    // find potential conflicts (by brute force)
    addConflictGroups(insns);
    //console.log(insns.length);
    let node = genDisassemblerRec(insns, 0, 0, true, 0, data);
    checkTableMissingInsns(node, insns);
    return node;
    //console.log(stuff);
}

function addConflictGroups(insns) {
    for(let insn of insns)
        insn.conflictGroup = -1;
    let nextConflictGroup = 0;
    let seen = [];
    let cgs = {};
    for(let insn of insns) {
        for(let insn2 of seen) {
            let bothKnown = insn.instKnownMask & insn2.instKnownMask;
            if(insn != insn2 && (insn.instKnownValue & bothKnown) == (insn2.instKnownValue & bothKnown)) {
                if(insn2.conflictGroup == -1) {
                    insn2.conflictGroup = nextConflictGroup++;
                    cgs[insn2.conflictGroup] = [insn2];
                }
                let cg1 = insn.conflictGroup, cg2 = insn2.conflictGroup;
                //console.log(insn.name, insn2.name, cg1, cg2);
                if(cg1 == cg2)
                    continue;
                if(cg1 != -1) {
                    for(let insn3 of cgs[cg1])
                        insn3.conflictGroup = insn2.conflictGroup;
                    cgs[cg2] = cgs[cg2].concat(cgs[cg1]);
                    cgs[cg1] = 123;
                } else {
                    insn.conflictGroup = insn2.conflictGroup;
                    cgs[cg2].push(insn);
                }
            }
        }
        seen.push(insn);
    }
}

function printConflictGroups(insns) {
    console.log('Total insns: ' + insns.length);
    let cgs = {};
    for(let insn of insns) {
        if(insn.conflictGroup != -1)
            setdefault(cgs, insn.conflictGroup, []).push(insn);
    }
    for(let cg in cgs) {
        console.log(cg + ': (' + cgs[cg].length + ')');
        for(let insn of cgs[cg])
            console.log('  ', pad(insn.name, 20), 'spec:' + pad(insn.instSpecificity, 2), insn.instKnown.join(','));
    }
}

function visitDag(pat, visitor) {
    if(Array.isArray(pat)) {
        visitor(pat);
        for(let i = 1; i < pat.length; i++)
            visitDag(pat[i], visitor);
    }
}

function printHeads(insns) {
    seen = {};
    for(let insn of insns) {
        if(insn.pattern != '?' && insn.pattern.length) {
            visitDag(insn.pattern, tuple => {
                if(tuple[0].replace && tuple[0] !== ':')
                    seen[tuple[0]] = (seen[tuple[0]] || 0) + 1;
            });
            insn.pattern.forEach(add);
        } else {
            console.log('nopat ' + insn.name);
        }
    }
    let seen_l = [];
    for(let head in seen)
        seen_l.push([head, seen[head]]);
    seen_l.sort();
    for(let l of seen_l)
        console.log('head ' + l[0] + ' (' + l[1] + ')');
}

function ppTable(node, indent, depth) {
    indent = (indent || '') + '  ';
    depth = (depth || 0) + 1;
    if(node.insn)
        return '<' + hex(node.knownValue, node.insn.inst.length) + '> insn:' + node.insn.name;
    let s = '{' + depth + '} ';
    if(!node.isBinary) {
        s += 'test ' + node.start + '..' + (node.start + node.length - 1);
    } else {
        s += 'test for first insn';
    }
    s += ' (' + node.possibilities.length + ' total insns - ';
    s += node.possibilities.map(i => i.name);
    s += '):\n';
    for(let i = 0; i < node.buckets.length; i++) {
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
    let mine = [];
    for(let bit of bits) {
        let last = mine[mine.length - 1];
        if(last && last[0] + last[2] == bit[0] && last[1] + last[2] == bit[1])
            last[2]++;
        else
            mine.push([bit[0], bit[1], 1]);
    }
    return mine;
}

// returns name -> [(oppos_lo, instpos_lo, len)]
function instToOpRuns(inst, removeDupes) {
    // name -> [(oppos, instpos)]
    let ops = {};
    let seen = {};
    for(let i = 0; i < inst.length; i++) {
        let bit = inst[i];
        if(!Array.isArray(bit))
            continue;
        if(removeDupes) {
            if(seen[bit])
                continue;
            seen[bit] = true;
        }
        setdefault(ops, bit[0], []).push([i, bit[1]]);
    }
    let out = {};
    for(let op in ops) {
        out[op] = bitPairsToRuns(ops[op]);
    }
    return out;
}

function opRunsToExtractionFormula(runs, inExpr, reverse) {
    let parts = [];
    for(let run of runs) {
        // make a reverse function if necessary
        let inpos = run[0], outpos = run[1], len = run[2];
        let diff = inpos - outpos;
        let mask = ((1 << len) - 1) << inpos;
        let x = '(' + inExpr + ' & 0x' + hexnopad(mask) + ')';
        if(outpos < inpos)
            x = '(' + x + ' >> ' + (inpos - outpos) + ')';
        else if(outpos > inpos)
            x = '(' + x + ' << ' + (outpos - inpos) + ')';
        parts.push(x);
    }
    return parts.join(' | ');
}

function opRunsToBitsliceLiteral(runs, reverse) {
    let runLits = runs.map(run => '{'+run+'}');
    return '{.nruns = ' + runs.length + ', .runs = (struct bitslice_run[]) {' + runLits.join(', ') + '}}';
}

function genGeneratedWarning() {
    let describe = child_process.execSync('git describe --abbrev=0 --dirty --always', {cwd: __dirname, encoding: 'utf-8'}).trim();
    let cmdline = process.argv.slice(2).map(arg => {
        arg = arg.replace(/^.*imaon2\//, '');
        if(arg.indexOf(' ') !== -1)
            arg = "'" + arg + "'";
        return arg;
    }).join(' ');
    return ''+
`/* Generated code; do not edit!
   generated by tables/gen.js from imaon2 '${describe}'
   https://github.com/comex/imaon2
   arguments: '${cmdline}'
   (fair warning: at present the main (Rust) code in that repository is barely
    started, embarrassingly so; no need to look at it ;p)
   In case it\'s copyrightable in any way, consider the generated code in the
   public domain.
*/
`;
}

function genConstraintTest(insn, unknown, indent, andandFirstToo) {
    let ceb = insn.instConstrainedEqualBits;
    let pairs = [];
    for(let lo in ceb) {
        lo = parseInt(lo);
        for(let hi of ceb[lo]) {
            if(lo < hi)
                pairs.push([lo, hi]);
        }
    }
    let runs = bitPairsToRuns(pairs);
    let out = '';
    for(let run of runs) {
        let mask = (1 << run[2]) - 1;
        let part = '((op >> ' + run[0] + ') & 0x' + hexnopad(mask) + ') == ' +
                   '((op >> ' + run[1] + ') & 0x' + hexnopad(mask) + ')';
        if(out || andandFirstToo)
            out += ' &&\n' + indent;
        out += part;
    }
    return out;
}

let indentStep = '    ';
function tableToSimpleCRec(node, data, indent, skipConstraintTest) {
    let bits = [];
    let patternify = n => data.pattern.replace(/XXX/g, n);
    let push = x => bits.push(indent + x);
    if(node.fail) {
        push('return ' + patternify('unidentified') + '(' + data.extraArgs + ');');
    } else if(node.insn) {
        let insn = node.insn;
        let unknown = insn.instDependsMask & ~node.knownMask;
        if(unknown && !skipConstraintTest) {
            push('if (!(' + genConstraintTest(insn, unknown, indent + '      ') + '))', false);
            push('    return ' + patternify('unidentified') + '(' + data.extraArgs + ');');
        }
        // ok, it's definitely this instruction
        let name = insn.groupName || insn.name;
        let label = 'insn_' + name;
        let hexComment = '0x'+hex(node.knownValue, insn.inst.length) + ' | 0x'+hex(~node.knownMask, insn.inst.length);
        if(data.seen[label]) {
            push('goto ' + label + '; /* ' + hexComment + ' */');
            data.seen[label]++;
        } else {
            let runsByOp = instToOpRuns(insn.inst);
            let args = [data.extraArgs];
            let funcName = patternify(name);
            push('LABEL ' + label + '');
            data.seen[label] = 1;
            for(let op in runsByOp) {
                //push('unsigned ' + op + ' = ' + opRunsToExtractionFormula(runsByOp[op], 'op', false) + ';');
                push('struct bitslice ' + op + ' = ' + opRunsToBitsliceLiteral(runsByOp[op], 'op', false) + ';');
                args.push(op);
            }
            push('return ' + funcName + '(' + args.join(', ') + '); /* ' + hexComment + ' */');
            // be helpful
            if(data.prototypes) {
                let prototype = 'static INLINE tdis_ret ' + funcName + '(' + args.map(arg => 'struct bitslice ' + arg).join(', ') + ') {}';
                data.prototypes[prototype] = null;
            }
        }
    } else if(node.isBinary) {
        let insn = node.buckets[0].insn;
        let unknown = insn.instConstrainedMask & ~node.knownMask;
        let test = 'if ((op & 0x' + hexnopad(insn.instKnownMask) + ') == 0x' + hexnopad(insn.instKnownValue);
        if(unknown) {
            test += genConstraintTest(insn, unknown, indent + '    ', true);
            test += ') { /* binary + constraints, yay */';
        } else {
            test += ') {';
        }
        push(test);
        bits.push(tableToSimpleCRec(node.buckets[0], data, indent + indentStep, true));
        push('} else {');
        bits.push(tableToSimpleCRec(node.buckets[1], data, indent + indentStep));
        push('}');
    } else {
        push('switch ((op >> ' + node.start + ') & 0x' + hexnopad((1 << node.length) - 1) + ') {');
        let buckets = node.buckets.slice(0);
        let ncases = 0;
        for(let i = 0; i < buckets.length; i++) {
            let subnode = buckets[i];
            if(subnode === null)
                continue;
            push('case ' + i + ':');
            ncases++;
            for(let j = i + 1; j < buckets.length; j++) {
                if(buckets[j] === subnode) {
                    push('case ' + j + ':');
                    ncases++;
                    buckets[j] = null;
                }
            }
            let rec = tableToSimpleCRec(subnode, data, indent + indentStep);
            if(rec.indexOf('\n') !== -1) {
                bits[bits.length - 1] += ' {';
                bits.push(rec);
                push('}');
            } else {
                bits.push(rec);
            }
        }
        if((1 << node.length) != ncases)
            throw new Error('bad buckets length'); // just to be sure
        push('}');
    }
    return bits.join('\n');
}

function tableToSimpleC(node, pattern, extraArgs) {
    let data = {
        pattern: pattern,
        extraArgs: extraArgs,
        prototypes: {},
        seen: {},
        useGoto: true,
    };
    let ret = tableToSimpleCRec(node, data, indentStep);
    ret = ret.replace(/\n[^\n]*LABEL ([^\n]+)/g, m => {
        let bits = m.split('LABEL ');
        let whitespace = bits[0], lbl = bits[1];
        if(data.seen[lbl] > 1)
            return whitespace + lbl + ':;';
        else
            return '';
    });
    let ps = '\n';
    let protoNames = [];
    for(let proto in data.prototypes)
        protoNames.push(proto);
    protoNames.sort();
    if(protoNames)
        ps += '/*\n' + protoNames.join('\n') + '\n*/\n';
    return ret + ps;
}

function checkTableMissingInsns(node, insns) {
    let used = {};
    function collect(node) {
        if(node.insn)
            used[node.insn.name] = 1;
        else if(node.buckets)
            node.buckets.map(collect);
    }
    collect(node);
    for(let insn of insns) {
        if(!used[insn.name]) {
            console.log('** Table never decodes ' + insn.name);
        }
    }
}

// there are instructions that put, say, addr{12} in multiple locations in Inst to assert that the value is the same.

function genSema(insns, ns) {
    let s = 'trait Sema' + ns + ' {\n';

}

function coalesceInsnsWithMap(insns, func) {
    let byGroup = new HashMap();
    for(let insn of insns) {
        let key = func(insn);
        if(key === null)
            continue;
        let locs = '' + insn.inst.map(bit => Array.isArray(bit) ? bit : '');
        let realKey = [key, locs];
        let ginsns = setdefault_hashmap(byGroup, realKey, []);
        ginsns.push(insn);
    }
    // for each group, continually coalesce instructions which are the same but for one bit, until we can do no more.  probably slooow
    // actually, not enough insns to be slow
    let out = [];
    let coalid = 0;
    byGroup.forEach((ginsns, key) => {
        // inst -> [insns]
        let byPat = new HashMap();
        for(let insn of ginsns) {
            let instMinusVars = insn.inst.map(b => Array.isArray(b) ? '?' : b);
            //console.log('**>', instMinusVars+'');
            setdefault_hashmap(byPat, instMinusVars, []).push(insn);
        }
        let didSomething;
        do {
            didSomething = false;
            //console.log('pass');
            // merge combinations that together take up the whole space
            // this ignores constraints; we can do that manually if necessary
            byPat.forEach((insns, inst) => {
                for(let i = 0; i < inst.length; i++) {
                    let old = inst[i];
                    if(old == '?')
                        continue;
                    inst[i] = old == '1' ? '0' : '1';
                    let insns2;
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
            byPat.forEach((insns, inst) => {
                byPat.forEach((insns2, inst2) => {
                    if(inst2 === inst)
                        return;
                    for(let i = 0; i < inst.length; i++) {
                        let b1 = inst[i], b2 = inst2[i];
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

        let origLength = ginsns.length;
        let newLength = byPat.count();
        let groupName = key[0].replace(/[^a-zA-Z0-9_]+/g, '_') + '_' + + ginsns.length + '_' + ginsns[0].name;
        //console.log('collapsed', origLength, '-->', newLength);
        byPat.forEach((insns, inst) => {
            insns.sort(); // get a consistent representative for the name
            // make a fake insn
            let oinst = insns[0].inst.slice(0);
            for(let i = 0; i < oinst.length; i++) {
                if(!Array.isArray(oinst[i]))
                    oinst[i] = inst[i];
            }
            let insn = {
                namespace: ns,
                inst: oinst,
                //name: 'coal' + (coalid++) + '_' + (origLength - newLength) + '*' + key,
                name: 'coal_' + insns.length + '_' + insns[0].name,
                groupName: groupName,
                groupInsns: ginsns,
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
    let bitEqualityConstraints = {};
    for(let i = 0; i < insn.inst.length; i++) {
        let bit = insn.inst[i];
        if(Array.isArray(bit))
            setdefault(bitEqualityConstraints, bit, []).push(i);
        let res = bit === '0' ? 0 : bit === '1' ? 1 : 2;

        // filter out useless instructions
        if(res != 2) {
            insn.instKnownMask |= (1 << i);
            insn.instKnownValue |= (res << i);
            insn.instSpecificity++;
        }
        insn.instKnown.push(res);
    };
    insn.instConstrainedMask = 0;
    insn.instConstrainedEqualBits = {};
    insn.instHaveAnyConstrainedEqualBits = false;
    for(let k in bitEqualityConstraints) {
        let bits = bitEqualityConstraints[k];
        if(bits.length > 1) {
            for(let bit of bits) {
                insn.instConstrainedEqualBits[bit] = bits.filter(bit2 => bit2 != bit);
                insn.instConstrainedMask |= (1 << bit);
                insn.instHaveAnyConstrainedEqualBits = true;
            }
            //console.log('!', insn.name, insn.instConstrainedEqualBits);
        }
    }
    insn.instDependsMask = insn.instKnownMask | insn.instConstrainedMask;
}

let getopt = require('node-getopt').create([
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
let opt = getopt.parseSystem();
if(opt.argv.length != 1) {
    help();
}

let input = JSON.parse(fs.readFileSync(opt.argv[0], 'utf-8'));
let inputInsns = input.instructions;

let insns = inputInsns.filter(insn => insn.instKnownMask != 0);

var specialCases = {
    t2IT: (insn) => {
        // For some dumb reason this is marked as 32-bit despite being 16-bit.
        insn.inst = insn.inst.slice(16);
        insn.decoderNamespace = 'Thumb';

    }
}
for(let insn of insns) {
    var sc;
    if(sc = specialCases[insn.name])
        sc(insn);
}

let ns = '*';
if(typeof opt.options['namespace'] !== 'undefined') {
    ns = opt.options['namespace'];
    let dns;
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
    insns = insns.filter(insn => dns.indexOf(insn.decoderNamespace) != -1);
}

for(let insn of insns) {
    fixInstruction(insn, false);
}

addConflictGroups(insns);
if(opt.options['print-conflict-groups']) {
    printConflictGroups(insns);
}
if(opt.options['print-heads']) {
    printHeads(insns);
}
if(opt.options['gen-disassembler']) {
    let node = genDisassembler(insns, ns, {});
    console.log(ppTable(node));
}
if(opt.options['gen-hook-disassembler']) {
    genHookDisassembler(true);
}
if(opt.options['gen-hook-jump-disassembler']) {
    genHookDisassembler(false);
}
function genHookDisassembler(includeNonJumps) {
    let cantBePcModes = {
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
    let insns2 = coalesceInsnsWithMap(insns, insn => {
        // This is not fully general.  But I don't think it's important to hook
        // functions that do MUL PC, PC or crap like that...  This takes care
        // of all load instructions (LLVM mashes both registers into one big
        // operand), plus ADD and MOV.
        if(insn.name.match(/^(t?2?PL|PRFM|LDNP|STNP)/i)) {
            return null;
        }
        let isBranch = insn.isBranch;
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
        let isAdd = !!insn.name.match(/^[^A-Z]*AD[DR]/);
        let isMov = !!insn.name.match(/^[^A-Z]*MOV/);
        let isLoad = !!insn.name.match(/^[^A-Z]*(LD|POP)/);
        let isStore = !!insn.name.match(/^[^A-Z]*(ST|PUSH)/);
        let isArmv8 = insn.namespace == 'AArch64';
        let interestingVars = {}; // vn -> num bits
        insn.inst.forEach((bit, i) => {
            // this is currently ARM specific, obviously
            if(!Array.isArray(bit))
                return;
            let interesting;
            switch(insn.namespace) {
            case 'ARM':
                interesting =
                    bit[0] == 'addr' ||
                    bit[0] == 'offset' ||
                    bit[0] == 'label' ||
                    ((isAdd || isMov || isStore || isLoad) && (bit[0].match(/^Rd?[nm]?$/) || bit[0] == 'shift')) ||
                    (isBranch && (bit[0] == 'target' || bit[0] == 'Rm' || bit[0] == 'dst')) ||
                    ((isStore || isLoad) && bit[0] == 'regs') ||
                    bit[0] == 'Rt' ||
                    insn.name == 't2IT';
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
        visitDag(insn.inOperandList, tuple => {
            if(tuple[0] == ':' && tuple[2][0] == '$' && cantBePcModes[tuple[1]])
                delete interestingVars[tuple[2].substr(1)];
        });
        if(insn.namespace == 'ARM') {
            // pointless special case - yay thumb
            let haveAnyNonR3s = false;
            for(let vn in interestingVars) {
                if(!(vn[0] == 'R' && interestingVars[vn] < 4)) {
                    haveAnyNonR3s = true;
                    break;
                }
            }
            if(!haveAnyNonR3s)
                return null;
        }
        insn.inst.forEach((bit, i) => {
            if(Array.isArray(bit) && !interestingVars[bit[0]])
                insn.inst[i] = '?'; // redact
        });

        for(let haveAny in interestingVars) {
            /*
            happens sometimes
            if(nbits < opBitLocs.length)
                console.log('not all bit locs accounted for: ' + insn.name + ' : ' + JSON.stringify(insn.inst));
            */
            let nameBits = [];
            let seen = {};
            visitDag(insn.inOperandList, tuple => {
                let vn;
                if(tuple[0] == ':' && tuple[2][0] == '$' && interestingVars[vn = tuple[2].substr(1)]) {
                    seen[vn] = true;
                    nameBits.push(tuple[1] + ':' + tuple[2]);
                }
            });
            for(let vn in interestingVars) {
                if(!seen[vn])
                    nameBits.push('unk' + ':' + vn);
            }
            let name = nameBits.join(',');
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
    //console.log(insns2);
    let node = genDisassembler(insns2, ns, {maxLength: 5});
    //console.log(ppTable(node));
    console.log(genGeneratedWarning());
    let xseen = {};
    for(let insn of insns2) {
        if(xseen[insn.groupName])
            continue;
        xseen[insn.groupName] = true;
        console.log('/* ' + insn.groupName + ': ' + insn.groupInsns.map(insn2 => insn2.name).join(', ') + ' */');
    }
    console.log(tableToSimpleC(node, opt.options['dis-pattern'] || 'XXX', opt.options['dis-extra-args'] || 'ctx'));
}
if(opt.options['gen-sema']) {
    genSema(insns, ns);
}
if(opt.options['extraction-formulas']) {
    for(let insn of insns) {
        console.log(insn.name);
        let runsByOp = instToOpRuns(insn.inst);
        for(let op in runsByOp)
            console.log('   ' + op + ': ' + opRunsToExtractionFormula(runsByOp[op], 'x', false));
    }
}
if(opt.options['print-constrained-bits']) {
    for(let insn of insns) {
        if(insn.instHaveAnyConstrainedEqualBits) {
            console.log(insn.name);
            console.log(insn.instConstrainedEqualBits);
        }
    }
}
if(opt.options['print-insns']) {
    for(let insn of insns) {
        console.log(insn);
    }
}
