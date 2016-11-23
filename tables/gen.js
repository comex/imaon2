"use strict";
let fs = require('fs');
let path = require('path');

// this isn't a very efficient module,
//    (but ES6 Map is *less* efficient!?)
let HashMap = require('hashmap').HashMap;
let child_process = require('child_process');

function writeFile(filename, data) {
    if(filename == '-' || filename == '/dev/stdout')
        process.stdout.write(data)
    else
        return fs.writeFileSync(filename, data);
}

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

function update(obj, obj2) {
    for(let key in obj2)
        obj[key] = obj2[key];
}

function setdefault_hashmap(obj, key, def) {
    let o = obj.get(key);
    if(typeof o === 'undefined')
        obj.set(key, o = def);
    return o;
}

function* items(obj) {
    for(let key in obj)
        yield [key, obj[key]];
}
function* keys(obj) {
    for(let key in obj)
        yield key;
}
function* filter(cb, it) {
    let i = 0;
    for(let val of it)
        if(cb(val, i++))
            yield val;
}
function groupBy(cb, it) {
    let byKey = {};
    for(let val of it) {
        let key = cb(val);
        setdefault(byKey, key, []).push(val);
    }
    return byKey;
}

function makeDefensive(obj) {
    return new Proxy(obj, {
        get: (target, name) => {
            if(!(name in target) && name !== 'inspect' && name.charCodeAt)
                throw 'undefined property ' + name;
            return target[name];
        },
    });
}

// tblgen already generates disassemblers, but:
// - They seem to be very inefficient; the fixed-length version has giant
// tables including *uleb128* run through an *interpreter* that branches one at
// a time (even though it's not a binary tree; the switch just gets generated
// as multiple compares!).  Ideally I only want a single indirect branch...
// Dolphin is actually a good model here.
// - I want to detect jumps very quickly.

// Optimization: Returns true if we can skip this whole iteration due to losing to bestMax already.

function fillBuckets(buckets, bestMax, insn, instKnown, knownMask, knownValue, start, end, n, builtUp) {
    if(n > start && insn.instHaveAnyConstrainedEqualBits) {
        let old = n - 1;
        let ceb = insn.instConstrainedEqualBits[old];
        if(ceb !== undefined) {
            // Rule it out if it would violate a constraint.  Uncommon, speed doesn't matter
            let thisBit = (builtUp >> old) & 1;
            for(let thatBitPos of ceb) {
                if(knownMask & (1 << thatBitPos)) {
                    let thatBit = (knownValue >> thatBitPos) & 1;
                    if(thisBit != thatBit) {
                        //console.log('ruling out ' + insn.name);
                        return false;
                    }
                }
            }
        }
    }
    if(n == end) {
        let l = buckets[builtUp];
        l.push(insn);
        if(l.length > bestMax)
            return true;
        return false;
    }
    let bit = instKnown[n];
    if(bit != 1) { // 0 or 2
        if(fillBuckets(buckets, bestMax, insn, instKnown,
                       knownMask | (1 << n), knownValue, start, end, n+1, builtUp))
            return true;
    }
    if(bit != 0) { // 1 or 2
        if(fillBuckets(buckets, bestMax, insn, instKnown,
                       knownMask | (1 << n),
                       knownValue | (1 << n),
                       start, end, n+1, builtUp | (1 << (n - start))))
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

function tryFilter(start, length, knownMask, knownValue, insns, best) {
    let mask = ((1 << length) - 1) << start;
    if(length != 0 && (knownMask & mask) == mask) {
        // Useless, we know all these bits already.
        return best;
    }
    let buckets = [];
    for(let i = 0; i < (1 << length); i++) {
        let x = [];
        buckets.push(x);
    }
    for(let i = 0; i < insns.length; i++) {
        let insn = insns[i];
        if(fillBuckets(buckets, best.max, insn, insn.instKnown, knownMask, knownValue, start, start + length, start, 0)) {
            //console.log('early return');
            return best;
        }
    }

    if(insns.length < 10) {
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

        // NOTE: this block is microoptimized because it was the source of a
        // huge amount of time spent.

        let bucketKnownMask = knownMask | (((1 << length) - 1) << start);
        for(let i = 0; i < buckets.length; i++) {
            let bucket = buckets[i];
            if(bucket.length <= 1)
                continue;
            let bucketKnownValue = knownValue | (i << start);
            //if(insns.length
            if(bucket.length == 2) {
                let insn1 = bucket[0], insn2 = bucket[1];
                if(insn1.conflictGroup != -1 &&
                   insn2.conflictGroup != -1 &&
                   insn1.conflictGroup == insn2.conflictGroup) {
                    if(knocksOut(insn1, insn2, bucketKnownMask, bucketKnownValue))
                        bucket = [insn1];
                    else if(knocksOut(insn2, insn1, bucketKnownMask, bucketKnownValue))
                        bucket = [insn2];
                }
                continue;
            }
            let xinsns = bucket.slice(0);
            for(let i = 0; i < xinsns.length; i++) {
                let nConflicts = 0;
                let cg = xinsns[i].conflictGroup;
                if(cg == -1)
                    continue;
                for(let j = i + 1; j < xinsns.length; j++) {
                    if(xinsns[j].conflictGroup == cg)
                        nConflicts++;
                }
                if(nConflicts == 1 || nConflicts > 5)
                    continue;
                let conflictingInsns = [];
                for(let j = i + 1; j < xinsns.length; j++) {
                    if(xinsns[j].conflictGroup == cg) {
                        conflictingInsns.push(xinsns[j]);
                        xinsns.splice(j, 1);
                        j--;
                    }
                }
                //console.log(conflictingInsns.length, nConflicts);
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
    if(max < best.max || (max == best.max && length < best.length))
        return {max: max, buckets: buckets, start: start, length: length};
    else
        return best;
}


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
        if((insn.instKnownMask & ~knownMask) == 0) {
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

    let best = {max: 1000000};
    let maxLength = data.maxLength;

    let override;
    // not currently used, but...
    if(depth <= 3 && (override = choiceOverrides[data.uid + ':' + hex(knownMask, data.bitLength)])) {
        best = tryFilter(override[0], override[1], knownMask, knownValue, insns, best);
    } else {
        for(let length = 0; length <= maxLength; length++) {
            let maxStart = length == 0 ? 0 : data.bitLength - length;
            for(let start = 0; start <= maxStart; start++)
                best = tryFilter(start, length, knownMask, knownValue, insns, best);
        }
    }

    if(best.max > insns.length) {
        throw '!?';
    } else if(best.max == insns.length) {
        if(insns.length <= 4 && 1) {
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
        for(let insn of insns) {
            console.log(pad(insn.name, 20), insn.instKnown.join(','));
            if(insn.instHaveAnyConstrainedEqualBits)
                console.log('     ', insn.instConstrainedEqualBits);
        }
        console.log('');
        console.log(pad('(known?)', 20), mask2bits(knownMask, data.bitLength).join(','));
        return data.cache[cacheKey] = data.failNode;
        throw '?';
    }

    let resultBuckets = [];
    for(let i = 0; i < best.buckets.length; i++) {
        let bucket = best.buckets[i];
        let bucketKnownMask = knownMask | (((1 << best.length) - 1) << best.start);
        let bucketKnownValue = knownValue | (i << best.start);

        //let useCache = bestLength > cacheCutoff && depth > 0;
        // ^ this makes no sense?
        resultBuckets.push(genDisassemblerRec(bucket, bucketKnownMask, bucketKnownValue, useCache, depth + 1, data));
    }

    if(best.length == 0) {
        return data.cache[cacheKey] = resultBuckets[0];
    }

    return data.cache[cacheKey] = {
        start: best.start,
        length: best.length,
        max: best.max,
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
    data.failNode = {fail: true};
    data.bitLength = insns[0].inst.length;
    //console.log('genDisassembler:', uid, bitLength);
    // find potential conflicts (by brute force)
    addConflictGroups(insns);
    //console.log(insns.length);
    let node = genDisassemblerRec(insns, 0, 0, true, 0, data);
    if(options.uniqueNodes) {
        uniqueTableNodes(node);
    }
    checkTableMissingInsns(node, insns);
    return node;
    //console.log(stuff);
}

function uniqueTableNodes(node) {
    let nextId = 0;
    let cache = {};
    let byId = [];
    function rec(node) {
        let minNode = {isBinary: node.isBinary,
                       insn: node.insn !== undefined ? node.insn.name : null,
                       buckets: node.buckets !== undefined ?
                        node.buckets.map(rec)
                        : null
                      };
        let cacheKey = JSON.stringify(minNode);
        let node2;
        if(node2 = cache[cacheKey])
            return node2.id;
        node.id = byId.length;
        byId.push(node);
        if(minNode.buckets)
            node.buckets = minNode.buckets.map(idx => byId[idx]);
        return node.id;
    }
    rec(node);
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
            if(insn !== insn2 && (insn.instKnownValue & bothKnown) == (insn2.instKnownValue & bothKnown)) {
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
    if(node.fail)
        return 'fail';
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

// [(posInA, posInB)] -> [(posinA, posInB, len)]
function pairsToRuns(bits) {
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
        out[op] = pairsToRuns(ops[op]);
    }
    return out;
}

function opRunsToExtractionFormula(runs, inExpr) {
    let parts = [];
    for(let run of runs) {
        // make a reverse function if necessary
        let inpos = run[0], outpos = run[1], len = run[2];
        let diff = inpos - outpos;
        let mask = ((1 << len) - 1) << inpos;
        let x = lang.bitand(inExpr, lang.u32HexLit(mask));
        if(outpos < inpos)
            x = lang.shr(x, lang.u32DecLit(inpos - outpos));
        else if(outpos > inpos)
            x = lang.shl(x, lang.u32DecLit(outpos - inpos));
        parts.push(x);
    }
    return parts.reduce((a, b) => lang.bitor(a, b));
}

function opRunsToBitsliceLiteral(name, runs) {
    if(lang.isRust) {
        while(runs.length < 5)
            runs.push([0,0,0]);
        let runLits = runs.map(run => `Run(${run})`);
        return `let ${name} = Bitslice { runs: [${runLits.join(', ')}] };`;
    } else {
        let runLits = runs.map(run => '{'+run+'}');
        return `struct bitslice ${name} = {.nruns = ${runs.length}, .runs = (struct bitslice_run[]) {${runLits.join(', ')}}};`;
    }
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
   In case it\'s copyrightable in any way, consider the generated code in the
   public domain.
*/
`;
}

function genConstraintTest(insn, unknown) {
    let ceb = insn.instConstrainedEqualBits;
    let pairs = [];
    for(let lo in ceb) {
        lo = parseInt(lo);
        for(let hi of ceb[lo]) {
            if(lo < hi)
                pairs.push([lo, hi]);
        }
    }
    let runs = pairsToRuns(pairs);
    let test = null;
    for(let run of runs) {
        let mask = (1 << run[2]) - 1;
        let part = '((op >> ' + lang.u32DecLit(run[0]) + ') & ' + lang.u32HexLit(mask) + ') == ' +
                   '((op >> ' + lang.u32DecLit(run[1]) + ') & ' + lang.u32HexLit(mask) + ')';
        if(test !== null)
            test = lang.and(test, part);
        else
            test = part;
    }
    return test;
}

function gotoOrGen(data, label, comment, gen) {
    if(data.opts.mode == 'subfn') {
        // xxx this doesn't really make sense in C (nested functions)
        let funcName = `sub_${label}`;
        if(1) {
            if(!data.seen[label]) {
                let decl = lang.funcDecl(funcName, data.passArgs, data.passRetTy, gen(), {inline: 'default'});
                data.extraFuncDecls.push(decl);
                data.seen[label] = true;
            }
            return lang.return(lang.call(funcName, data.passArgsPass));
        } else {
            // more complicated version that doesn't separate into a function if there's only one use
            let stmt = data.seen[label];
            if(!stmt) {
                stmt = lang.wrapStmtList(gen());
                data.seen[label] = stmt;
                return stmt;
            }
            if(!stmt.wrapsStmts)
                return stmt;
            // need to convert to function
            let decl = lang.funcDecl(funcName, data.passArgs, data.passRetTy, stmt.wrapsStmts, {inline: 'default'});
            data.extraFuncDecls.push(decl);
            let newStmt = lang.return(lang.call(funcName, data.passArgsPass));
            stmt.wrapsStmts = [newStmt];
            data.seen[label] = newStmt;
            return newStmt;
        }
    } else {
        if(data.seen[label]) {
            //data.seen[label]++;
            return [
                lang.comment(comment, /*hangingOnFollowing*/ true),
                lang.goto(label)
            ];
        } else {
            data.seen[label] = 1;
            return [lang.label(label)].concat(gen());
        }
    }
}

function* flattenStmtList(stmtList) {
    for(let stmt of stmtList)
        if(stmt.wrapsStmts)
            yield* flattenStmtList(stmt.wrapsStmts);
        else
            yield stmt;
}
class SuperLang {
    comment(comment, hanging) {
        return {'stmt': true, 'comment': true, 'text': comment, 'hangingOnFollowing': hanging || false};
    }

    render(x) { return this.renderEx(99, null, x); }
    renderEx(precedence, nextTo, expr) {
        if(expr.charCodeAt) {
            let prec = expr.match(/^[a-zA-Z0-9_\.]+$/) ? 1 : 98;
            expr = this.expr(prec, null, expr);
        }
        if(expr.precedence === undefined || expr.stmt)
            throw 'not expr or string';
        if(expr.precedence < precedence ||
           (expr.precedence == precedence &&
            nextTo !== null &&
            nextTo === expr.infixChainEndingIn))
            return expr.text;
        else
            return '(' + expr.text + ')';
    }
    // XXX check Rust precedence
    not(expr) { return this.unary('!', expr); }
    and(a, b) { return this.binary(13, '&&', a, b); }
    bitand(a, b) { return this.binary(10, '&', a, b); }
    bitor(a, b) { return this.binary(10, '|', a, b); } // actually 12 but Clang warns
    shl(a, b) { return this.binary(7, '<<', a, b); }
    shr(a, b) { return this.binary(7, '>>', a, b); }

    unary(prefix, expr) {
        return this.expr(3, null, prefix + this.renderEx(3, null, expr));
    }
    binary(precedence, infix, a, b) {
        return this.expr(precedence, infix,
            this.renderEx(precedence, null, a) + ' ' + infix + ' ' +
            this.renderEx(precedence, infix, b));
    }

    call(func, args) {
        return this.expr(1, null,
                         this.renderEx(1.1, null, func) + '(' + 
                         args.map(arg => this.renderEx(15, null, arg))
                         .join(', ') + ')');
    }
    expr(precedence, infixChainEndingIn, text) {
        return {precedence: precedence, infixChainEndingIn, text};
    }
    stmt(stmt) {
        if(Array.isArray(stmt))
            throw new Error("derp");
        if(stmt.charCodeAt)
            stmt = {text: stmt};
        else if(stmt.precedence !== undefined)
            stmt.text += ';';
        stmt.stmt = true;
        return stmt;
    }
    stmtList(stmts) {
        return Array.isArray(stmts) ? stmts : [stmts];
    }
    hangingBlockChain(chain) {
        return this.stmt({'hangingBlockChain': true, 'chain': chain});
    }
    label(name) { throw 'no label'; }
    goto(name, extra) { throw 'no goto'; }
    wrapStmtList(stmts) {
        return {wrapsStmts: this.stmtList(stmts)};
    }
    stringLit(s) {
        return this.expr(1, null, JSON.stringify(s)); // not quite right
    }
}

class CLang extends SuperLang {
    return(expr) { return this.stmt('return ' + this.render(expr) + ';') }
    switch(expr, cases) {
        let stmts = ['switch (' + this.render(expr) + ') {'];
        for(let [whens, what] of cases) {
            for(let when of whens)
                stmts.push('case ' + when + ':');
            let i = stmts.length-1;
            what = this.stmtList(what);
            /*
            if(what.length > 0 && !what[what.length-1].goto) // XXX
                what.push('break;');
                */
            stmts[i] = this.hangingBlockChain([[stmts[i], what]]);
        }
        stmts.push('}');
        return stmts;
    }
    if(cond, then, else_) {
        let chain = [['if (' + this.render(cond) + ')', then]];
        if(else_ !== undefined)
            chain.push(['else', else_]);
        return this.hangingBlockChain(chain);
    }
    label(name) {
        return {'stmt': true, 'label': name, 'text': name + ':;'};
    }
    goto(name, extra) {
        return {'stmt': true, 'goto': name, 'text': 'goto ' + name + ';' + (extra||'')};
    }
    let(varName, ty, expr) {
        return {'stmt': true,
                'text': `${ty} ${varName} = ${this.render(expr)};`};
    }
    funcDecl(name, args, retTy, body, opts) {
        let decl = `${retTy || 'void'} ${name}(`;
        decl += args.map(([name, ty]) => `${ty} ${name}`).join(', ');
        decl += ') {';
        return this.stmt({
            'justBlock': true,
            'start': [decl],
            'substmts': body,
            'end': ['}'],
        });
    }

    u32HexLit(n) { return '0x' + hexnopad(n) ; }
    u32DecLit(n) { return n + ''; }
    finalRender(indent, stmtList) {
        let lines = [];
        let neededLabels = {};
        this.scanLabels(stmtList, neededLabels);
        this.finalRenderEx(stmtList, indent, lines, neededLabels);
        return lines;
    }
    scanLabels(stmtList, neededLabels) {
        stmtList = this.stmtList(stmtList);
        for(let stmt of stmtList) {
            if(stmt.goto)
                neededLabels[stmt.goto] = true;
            else if(stmt.hangingBlockChain) {
                for(let [intro, substmts] of stmt.chain)
                    this.scanLabels(substmts, neededLabels);
            }
        }
    }
    finalRenderEx(stmtList, indent, lines, neededLabels) {
        stmtList = this.stmtList(stmtList);
        let hangingComment = null;
        for(let stmt of flattenStmtList(stmtList)) {
            let lastHangingComment = hangingComment;
            hangingComment = null;
            stmt = this.stmt(stmt);
            if(stmt.label !== undefined && !neededLabels[stmt.label])
                continue;
            let linesLength = lines.length;
            if(stmt.hangingBlockChain) {
                let lastWasCloseBrace = false;
                for(let [intro, substmts] of stmt.chain) {
                    if(!lastWasCloseBrace)
                        lines.push(indent);
                    else if(intro)
                        lines[lines.length-1] += ' ';
                    let introIdx = lines.length - 1;
                    lines[introIdx] += intro;
                    this.finalRenderEx(substmts, indent + '    ', lines, neededLabels);
                    if(lines.length > introIdx + 2) {
                        if(lines[introIdx])
                            lines[introIdx] += ' ';
                        lines[introIdx] += '{';
                        lines.push(indent + '}');
                        lastWasCloseBrace = true;
                    }
                }
            } else if(stmt.justBlock) {
                for(let start of stmt.start)
                    lines.push(indent + start);
                this.finalRenderEx(stmt.substmts, indent + '    ', lines, neededLabels);
                for(let end of stmt.end)
                    lines.push(indent + end);
            } else if(stmt.comment) {
                if(stmt.text) {
                    let text = '/* ' + stmt.text + ' */';
                    if(stmt.hangingOnFollowing)
                        hangingComment = text;
                    else
                        lines.push(indent + text);
                }
            } else {
                lines.push(indent + stmt.text);
            }
            if(lastHangingComment !== null)
                lines[lines.length-1] += ' ' + lastHangingComment;
        }
    }
}
class RustLang extends SuperLang {
    return(expr) {
        return {'stmt': 'true', 'isReturn': true,
                'text': this.render(expr)};
    }
    switch(expr, cases) {
        let stmts = ['match ' + expr + ' {'];
        for(let [whens, what] of cases) {
            let runs = pairsToRuns(whens.map(when => [when, when]));
            let pat = [];
            for(let [start, _, len] of runs)
                pat.push(len == 1 ?
                         this.u32DecLit(start) :
                         (this.u32DecLit(start) + '...' + this.u32DecLit(start+len-1)));
            let left = pat.join(' | ');
            what = this.stmtList(what);
            stmts.push({'stmt': 'true', 'matchCase': true,
                        'left': left, 'right': what});
        }
        // for now, Rust doesn't understand exhaustive integer alternatives
        stmts.push({'stmt': 'true', 'matchCase': true,
                    'left': '_', 'right': 'unreachable()'});
        stmts.push('}');
        return {'stmt': true, 'silentGroup': true, 'stmts': stmts};
    }
    if(cond, then, else_) {
        let inheritsReturn = else_ !== undefined;
        let chain = [['if ' + this.render(cond), then, inheritsReturn]];
        if(else_ !== undefined)
            chain.push(['else', else_, inheritsReturn]);
        return this.hangingBlockChain(chain);
    }
    let(varName, ty, expr) {
        return {'stmt': true,
                'text': `let ${varName}: ${ty} = ${this.render(expr)};`};
    }
    funcDecl(name, args, retTy, body, opts) {
        let decl = `fn ${name}(`;
        decl += args.map(([name, ty]) => `${name}: ${ty}`).join(', ');
        decl += ')';
        if(retTy)
            decl += ` -> ${retTy}`;
        decl += ' {';
        let start = [decl];
        switch(opts.inline) {
        case 'default':
            start = ['#[inline]', decl];
            break;
        case 'always':
            start = ['#[inline(always)]', decl];
            break;
        case undefined:
            break;
        default:
            throw '?inline';
        }
        return this.stmt({
            'justBlock': true,
            'start': start,
            'substmts': body,
            'end': ['}'],
            'isFunc': true,
        });
    }
    u32HexLit(n) { return '0x' + hexnopad(n) + 'u32'; }
    u32DecLit(n) { return n + 'u32'; }
    finalRender(indent, stmtList, mayImplicitlyReturn) {
        let lines = [];
        this.finalRenderEx(stmtList, indent, lines, mayImplicitlyReturn);
        return lines;
    }
    finalRenderEx(stmtList, indent, lines, mayImplicitlyReturn, isSilentGroupOfLast) {
        if(mayImplicitlyReturn === undefined) throw '!';
        stmtList = this.stmtList(stmtList);
        let hangingComment = null;
        stmtList = Array.from(flattenStmtList(stmtList));
        for(let i = 0; i < stmtList.length; i++) {
            let stmt = stmtList[i];
            stmt = this.stmt(stmt);
            let lastHangingComment = hangingComment;
            hangingComment = null;
            let isLast = i == stmtList.length - 1 || isSilentGroupOfLast;
            if(stmt.hangingBlockChain) {
                let lastWasCloseBrace = false;
                for(let [intro, substmts, inheritsReturn] of stmt.chain) {
                    if(inheritsReturn === undefined) throw '!';
                    if(!lastWasCloseBrace)
                        lines.push(indent);
                    else if(intro)
                        lines[lines.length-1] += ' ';
                    let introIdx = lines.length - 1;
                    lines[introIdx] += intro + ' {';
                    let subMIR = mayImplicitlyReturn && inheritsReturn && isLast;
                    this.finalRenderEx(substmts, indent + '    ', lines, subMIR, false);
                    lines.push(indent + '}');
                    lastWasCloseBrace = true;
                }
            } else if(stmt.matchCase) {
                let introIdx = lines.length;
                lines.push(indent + '    ' + stmt.left + ' =>');
                let subMIR = mayImplicitlyReturn && isLast;
                let xindent = indent + '        ';
                this.finalRenderEx(stmt.right, xindent, lines, subMIR, false);
                if(lines.length > introIdx + 2) {
                    lines[introIdx] += ' {';
                    lines.push(indent + '    }');
                } else if(lines.length == introIdx + 2) {
                    lines[introIdx] += ' ' + lines[introIdx+1].substr(xindent.length);
                    lines.splice(introIdx+1);
                }
                lines[lines.length - 1] += ',';
            } else if(stmt.justBlock) {
                for(let start of stmt.start)
                    lines.push(indent + start);
                this.finalRenderEx(stmt.substmts, indent + '    ', lines, mayImplicitlyReturn || !!stmt.isFunc, true);
                for(let end of stmt.end)
                    lines.push(indent + end);
            } else if(stmt.silentGroup) {
                this.finalRenderEx(stmt.stmts, indent, lines, mayImplicitlyReturn, isLast);
            } else if(stmt.isReturn) {
                if(mayImplicitlyReturn && isLast)
                    lines.push(indent + stmt.text);
                else
                    lines.push(indent + 'return ' + stmt.text + ';');
            } else if(stmt.comment) {
                let text = '// ' + stmt.text;
                if(stmt.hangingOnFollowing)
                    hangingComment = text;
                else
                    lines.push(indent + text);
            } else {
                lines.push(indent + stmt.text);
            }
            if(lastHangingComment !== null)
                lines[lines.length-1] += ' ' + lastHangingComment;
        }
    }
}

RustLang.prototype.isRust = true;
RustLang.prototype.canGoto = false;
RustLang.prototype.u32 = 'u32';
CLang.prototype.isRust = false;
CLang.prototype.canGoto = true;
CLang.prototype.u32 = 'uint32_t';

let lang = new CLang();

let indentStep = '    ';
function tableToSwitcherRec(node, data, indent, skipConstraintTest) {
    if(node.fail) {
        return gotoOrGen(data, '_unidentified', '', () =>
            data.opts.makeCallUnidentified());
    } else if(node.insn) {
        let insn = node.insn;
        let unknown = insn.instDependsMask & ~node.knownMask;
        let f = next => next;
        if(unknown && !skipConstraintTest) {
            f = next => [
                lang.if(lang.not(genConstraintTest(insn, unknown)),
                        gotoOrGen(data, '_unidentified', '', () =>
                           data.opts.makeCallUnidentified()))
            ].concat(next)
        }
        // ok, it's definitely this instruction
        let bitsName = insn.groupAndBitsName || insn.name;
        let nobitsName = insn.groupName || insn.name;
        let label = 'insn_' + bitsName;
        let hexComment = '0x'+hex(node.knownValue, insn.inst.length) + ' | 0x'+hex(~node.knownMask, insn.inst.length);
        return f(gotoOrGen(data, label, hexComment, () => {
            let runsByOp = instToOpRuns(insn.inst);
            let out = [];
            return data.opts.makeCall(nobitsName, runsByOp);
        }));
    } else {
        return gotoOrGen(data, 'node_' + node.id, '', () => {
            let r;
            if(node.isBinary) {
                let insn = node.buckets[0].insn;
                let unknown = insn.instConstrainedMask & ~node.knownMask;
                let test = '(op & ' + lang.u32HexLit(insn.instKnownMask & ~node.knownMask) + ') == ' + lang.u32HexLit(insn.instKnownValue & ~node.knownMask);
                if(unknown)
                    test = lang.and(test, genConstraintTest(insn, unknown));
                r = lang.if(test,
                    tableToSwitcherRec(node.buckets[0], data, indent + indentStep, true),
                    tableToSwitcherRec(node.buckets[1], data, indent + indentStep));
            } else {
                let switchOn = '(op >> ' + lang.u32DecLit(node.start) + ') & ' + lang.u32HexLit((1 << node.length) - 1);
                let cases = [];
                let ncases = 0;
                let buckets = node.buckets.slice(0);
                for(let i = 0; i < buckets.length; i++) {
                    let subnode = buckets[i];
                    if(subnode === null)
                        continue;
                    let thisCases = [i];
                    ncases++;
                    for(let j = i + 1; j < buckets.length; j++) {
                        if(buckets[j] === subnode) {
                            thisCases.push(j);
                            ncases++;
                            buckets[j] = null;
                        }
                    }
                    cases.push([thisCases, tableToSwitcherRec(subnode, data, indent + indentStep)]);
                }
                if((1 << node.length) != ncases)
                    throw new Error('bad buckets length'); // just to be sure
                r = lang.switch(switchOn, cases);
            }
            return r;
        });
    }
}

function tableToSwitcher(node, opts) {
    opts.mode = opts.mode || (lang.isRust ? 'subfn' : 'goto');
    let data = {
        seen: {},
        seenNodeId: {},
        prefixLines: [],
        suffixLines: [],
        extraFuncDecls: [],
        opts: opts,
    };
    switch(opts.mode) {
        case 'goto':
            if(!lang.canGoto)
                throw 'wrong mode';
            break;
        case 'subfn':
            let passArgs = opts.passArgs;
            let passRetTy = opts.passRetTy;
            if(passRetTy === undefined || passArgs === undefined)
                throw 'no args/retTy';
            data.passArgs = passArgs;
            data.passArgsPass = passArgs.map(([name, ty]) => name);
            data.passRetTy = passRetTy;
            break;

        default:
            throw '?';
    }
    let ret = tableToSwitcherRec(node, data, indentStep);
    switch(opts.mode) {
    case 'goto':
    case 'subfn':
        let extra = [];
        for(let decl of data.extraFuncDecls) {
            let action = lang.finalRender('    ', decl, /*mayImplicitlyReturn*/ false);
            extra = extra.concat(action);
        }
        ret = lang.finalRender('    ', ret, /*mayImplicitlyReturn*/ true);
        ret = [...extra, ...data.prefixLines, ...ret, ...data.suffixLines];
        break;
    }
    return ret.join('\n');
}

function tableToBitsliceOrValCaller(node, pattern, extraArgs, useBitslice) {
    let prototypes = {};
    let patternifyForDef = n => pattern.replace(/XXX/g, n);
    let patternifyForCall = lang.isRust ? (n => 'h.'+patternifyForDef(n)) : patternifyForDef;

    let opts = {};
    opts.makeCall = (nobitsName, runsByOp) => {
        let funcName = patternifyForCall(nobitsName);
        let out = [];
        let args = extraArgs ? [extraArgs] : [];
        for(let op in runsByOp) {
            if(useBitslice)
                out.push(opRunsToBitsliceLiteral(op, runsByOp[op]));
            else
                out.push(lang.let(op, lang.u32, opRunsToExtractionFormula(runsByOp[op], 'op')));
            args.push(op);
        }
        out.push(lang.return(lang.call(patternifyForCall(nobitsName), args)));

        // be helpful
        let prototype;
        if(lang.isRust)
            prototype = '    fn ' + patternifyForDef(nobitsName) + '(&mut self' + args.map(arg => `, ${arg}: Bitslice`).join('') + ') -> Res;';

        else
            prototype = 'static INLINE tdis_ret ' + patternifyForDef(nobitsName) + '(' + args.map(arg => 'struct bitslice ' + arg).join(', ') + ') {}';
        prototypes[prototype] = null;

        return out;
    };
    opts.makeCallUnidentified = () =>
        lang.return(lang.call(patternifyForCall('unidentified'), [extraArgs]));

    let ret = tableToSwitcher(node, opts);

    if(lang.isRust) {
        ret = 'use ::{Bitslice, Run};\n' +
              'fn unreachable() -> ! { unreachable!() }\n' +
              'pub fn decode<Res, H: Handler<Res>>(op: u32, h: &mut H) -> Res {\n' +
              ret +
              '\n}';

    }
    let protoNames = [];
    for(let proto in prototypes)
        protoNames.push(proto);
    protoNames.sort();
    let ps = '\n';
    if(protoNames || lang.isRust) {
        if(lang.isRust) {
            ps += 'pub trait Handler<Res> {\n' + protoNames.join('\n') + '\n' +
                '    fn unidentified(&mut self) -> Res;\n' +
                '}\n';

        } else {
            ps += '/*\n' + protoNames.join('\n') + '\n*/\n';
        }
    }
    return ret + ps;
}

function tableToDebugCaller(node, cbName, extraArgs) {
    let opts = {
        makeCall(nobitsName, runsByOp) {
            let out = [];
            for(let [op, runs] of items(runsByOp))
                out.push(lang.let(op, lang.u32, opRunsToExtractionFormula(runs, 'op')));
            if(1) {
                for(let op in runsByOp)
                    out.push(lang.call('PUSH_OPERAND', [lang.stringLit(op), op]));
                out.push(lang.call('RETURN_INSN', [lang.stringLit(nobitsName)]));
            }

            return out;
        },
        makeCallUnidentified() {
            return opts.makeCall('unidentified', []);
        },
    };
    opts.passArgs = [['op', lang.u32], [cbName, 'Callback']];
    opts.passRetTy = null;
    let ret = tableToSwitcher(node, opts);
    if(lang.isRust) {
        ret = 'use ::{Callback, Operand};\n' +
              'fn unreachable() -> ! { unreachable!() }\n' +
              `pub fn decode(op: u32, ${cbName}: Callback) {\n` +
              ret +
              '\n}';
    }
    return ret;
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

function printOpPositions(insns, name) {
    let set = new HashMap();
    for(let insn of insns) {
        let i = 0;
        let pos = insn.inst.map(op => [i++, op]).filter(eop => Array.isArray(eop[1]) && eop[1][0] == name).map(eop => eop[0]+':'+eop[1][1]);
        if(pos.length)
            set.set(pos, null);
    }
    set.forEach((_, pos) => {
        console.log(pos+'');
    });
}

function coalesceInsnsWithMap(insns, func) {
    let byGroupAndBits = new HashMap();
    let byGroup = new HashMap();
    for(let insn of insns) {
        let key = func(insn);
        if(key === null)
            continue;
        let locs = '' + insn.inst.map(bit => Array.isArray(bit) ? bit : '');
        let keyAndBits = [key, locs];
        let gbinsns = setdefault_hashmap(byGroupAndBits, keyAndBits, []);
        let ginsns = setdefault_hashmap(byGroup, key, []);
        gbinsns.push(insn);
        ginsns.push(insn);
    }
    // for each group, continually coalesce instructions which are the same but for one bit, until we can do no more.  probably slooow
    // actually, not enough insns to be slow
    let out = [];
    let coalid = 0;
    byGroupAndBits.forEach((gbinsns, keyAndBits) => {
        // inst -> [insns]
        let byPat = new HashMap();
        for(let insn of gbinsns) {
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

        let origLength = gbinsns.length;
        let newLength = byPat.count();

        let key = keyAndBits[0];
        let ginsns = byGroup.get(key);
        let mangledKey = key.replace(/[^a-zA-Z0-9_]+/g, '_');
        let groupName = mangledKey + '_' + + ginsns.length + '_' + ginsns[0].name;
        let groupAndBitsName = 'gb_' + mangledKey + '_' + gbinsns.length + '_' + gbinsns[0].name;
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
                groupAndBitsName: groupAndBitsName,
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

function checkLengths(insns) {
    let bad = false;
    for(let insn of insns) {
        let good;
        switch(insn.decoderNamespace) {
        case 'Thumb':
        case 'ThumbSBit':
            good = insn.inst.length == 32 &&
                   insn.inst.slice(0, 16).every(x => x === '0');
            break;
        case 'Thumb2':
        case 'ARM':
        case 'VFP':
            good = insn.inst.length = 32;
        default:
            continue;
        }

        if(!good) {
            console.log('checkLengths: Strange instruction ' + insn.name + '(' + insn.inst.length + ';' + insn.decoderNamespace + ')');
            bad = true;
        }
    }
    if(bad)
        throw 'bad';
}

let getopt = require('node-getopt').create([
    ['n', 'namespace=ARG', 'Decoder namespace of instructions to use.'],
    ['',  'print-conflict-groups', 'Print potentially conflicting instructions.'],
    ['',  'print-heads', 'Print the DAG primitives that need to be implemented.'],
    ['d', 'gen-disassembler', 'Generate a full disassembler.'],
    //['',  'gen-branch-disassembler', 'Generate a branch-only disassembler.'],
    //['',  'gen-sema', 'Generate the step after the disassembler.'],
    ['',  'gen-hook-disassembler=OUTFILE', 'Generate a disassembler that distinguishes PC inputs and jumps'],
    ['',  'gen-jump-disassembler=OUTFILE', 'only jumps'],
    ['',  'gen-debug-disassembler=OUTFILE', 'symbolic'],
    ['',  'extraction-formulas', 'Test extraction formulas'],
    ['',  'print-constrained-bits', 'Test constraints'],
    ['',  'print-op-positions=OP', 'Print all positions this op appears in'],
    ['',  'dis-pattern=PATTERN', 'Pattern for function names from generated disassemblers, where XXX is replaced with our name'],
    ['',  'dis-extra-args=ARGS', 'More arguments to put in calls to user-implemented functions'],
    ['',  'print-insns', 'Just print them'],
    ['l', 'out-lang=LANG', 'Output language (C, Rust)'],
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

let specialCases = {
    t2IT: (insn) => {
        // For some dumb reason this is marked as 32-bit despite being 16-bit.
        insn.decoderNamespace = 'Thumb';
    },
    // vice versa
    tBL: (insn) => insn.decoderNamespace = 'Thumb2',
    tBLXi: (insn) => insn.decoderNamespace = 'Thumb2',
}
for(let insn of insns) {
    let sc;
    if(sc = specialCases[insn.name])
        sc(insn);
}

checkLengths(insns);


if(opt.options['out-lang']) {
    switch(opt.options['out-lang']) {
        case 'c': lang = new CLang(); break;
        case 'rust': lang = new RustLang(); break;
        default: throw 'invalid out-lang';
    }
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
    genHookishDisassembler('hook', opt.options['gen-hook-disassembler']);
}
if(opt.options['gen-jump-disassembler']) {
    genHookishDisassembler('jump', opt.options['gen-jump-disassembler']);
}
if(opt.options['gen-debug-disassembler']) {
    genDebugDisassembler(opt.options['gen-debug-disassembler']);
}
function genHookishDisassembler(submode, outfile) {
    switch(submode) {
    case 'hook':
    case 'jump':
        break;
    default:
        throw 'bad mode';
    }
    let separateUndefined = true;
    let uninterestingReturn = insn => {
        if(!separateUndefined)
            return null;
        insn.inst = insn.inst.map((bit, i) => Array.isArray(bit) ? '?' : bit);
        return 'uninteresting';
    };
    let insns2 = coalesceInsnsWithMap(insns, insn => {
        // This is not fully general.  But I don't think it's important to hook
        // functions that do MUL PC, PC or crap like that...  This takes care
        // of all load instructions (LLVM mashes both registers into one big
        // operand), plus ADD and MOV.
        if(insn.name.match(/^(t?2?PL|PRFM|LDNP|STNP)/i)) {
            return uninterestingReturn(insn);
        }

        let varInfo = {};
        {
            insn.inst.forEach((bit, i) => {
                if(Array.isArray(bit))
                    varInfo[bit[0]] = {
                        'out': true, 'type': '?',
                        'size': Math.max(bit[1]+1, varInfo[bit[0]] ? varInfo[bit[0]].size : 0),
                    };
            });
            let out;
            let cb = tuple => {
                if(tuple[0] == ':' && tuple[2][0] == '$') {
                    let varr = tuple[2].substr(1);
                    let mode = tuple[1];
                    let old = varInfo[varr];
                    if(old && old.type != '?')
                        throw `multiple modes? for ${insn.name} new=${mode} old=${old}`;
                    varInfo[varr] = {out: out, type: mode, size: old ? old.size : 0};
                }
            };
            out = false;
            visitDag(insn.inOperandList, cb);
            out = true;
            visitDag(insn.outOperandList, cb);
            for(let varr in varInfo) {
                if(varInfo[varr].type == '?') {
                    if(insn.namespace == 'AArch64' && insn.decoderMethod == 'DecodeThreeAddrSRegInstruction' && varr.match(/^(src|dst|shift)/))
                        varInfo[varr].type = 'foo';
                    else if(insn.namespace == 'AArch64' && insn.decoderMethod == 'DecodeAddSubERegInstruction' && varr.match(/^(R.|ext)$/))
                        varInfo[varr].type = 'bar';
                    else if(insn.name.match(/^t2TB[BH]$/))
                        ;
                    else
                        throw `unknown type for ${insn.name} var ${varr}`;
                }
            }
        }

        // special insns that need to be recognized even if they don't have interesting ops
        {
            let fakeVarName = null;
            switch(insn.namespace) {
            case 'ARM':
                if(insn.name.match(/^t2TB[BH]$/))
                    fakeVarName = 'xTB';
                break;
            case 'AArch64':
                if(submode == 'jump' && insn.isBranchy && !insn.isCall)
                    fakeVarName = insn.name.match(/^Bcc|TB/) ? 'condbranchy' : 'branchy';
            }
            if(fakeVarName !== null)
                varInfo[fakeVarName] = {out: false, type: 'fake', size: 0};
        }


        let anyWritesGPR = false;
        let anyInteresting = false;
        for(let varr in varInfo) {
            let info = varInfo[varr];
            let type = info.type;
            update(info, {
                writesGPR: false,
                mayReadPC: false,
                mayWritePC: false,
                relevantToGPRWrite: false, // contains the actual identity of the register
                codeAddrRef: false,
                dataAddrRef: false,
                otherImportant: false,
                forcedVal: null,
            });
            if(type == 'fake')
                info.otherImportant = true;
            else switch(insn.namespace) {
            case 'ARM': {
                let isGPR = false;
                // tcGPR: just llvm noise - actually, what is MOVr_TC?
                // rGPR: restricted, but we don't care
                // tGPR: 3 bit
                if(type.match(/^(GPR(|PairOp|nopc|withAPSR|sp)|tcGPR|rGPR|tGPR|postidx_reg)$/)) {
                    isGPR = true;
                    let mayBePC = type != 'tGPR' && type != 'GPRsp';
                    if(info.out) {
                        info.writesGPR = true;
                        info.mayWritePC = mayBePC;
                    } else {
                        info.mayReadPC = mayBePC;
                        if(varr == 'Rn' && varInfo['wb'])
                            info.relevantToGPRWrite = true; // $wb (writeback) = $Rn
                    }
                } else if(type.match(/^(so_reg_(imm|reg)|t2_so_reg|shift_so_reg_reg|addr_offset_none)$/) ||
                          (type == '?' && insn.name.match(/^t2TB/))) {
                    isGPR = true; // GPR read, can't writeback
                    info.mayReadPC = true;
                } else if(type.match(/((adr|ldr)label$|^t_addrmode_pc$)/))
                    info.dataAddrRef = true;
                else if(type.match(/^t_addrmode/))
                    ; // these can't writeback or be PC
                else if(type.match(/addrmode|(am.*offset)|addr_offset|^postidx|^ldst_so_reg$/))
                    info.relevantToGPRWrite = true;
                else if(type.match(/target$/)) {
                    info.mayWritePC = true;
                    info.codeAddrRef = true;
                } else if(type.match(/^it_mask|it_pred$/))
                    info.otherImportant = true;
                else if(type == 'pred')
                    info.otherImportant = insn.name == 'B';
                else if(type == 'reglist') {
                    // this is listed in InOperandList even though it writes
                    if(insn.name.match(/POP|LDM/) && insn.name != 'tLDMIA') {
                        info.writesGPR = true;
                        info.mayWritePC = true;
                    }
                } else if(type.match(/^(SPR|DPR|spr_reglist|dpr_reglist|vfp_f..imm|fbits..)$/))
                    ; // floating point
                else if(type.match(/imm0|imm$|^imm|^((s_)?cc_out|iflags_op|setend_op|imod_op|msr_mask|pkh_..._amt|memb_opt|instsyncb_opt|banked_reg)$/))
                    ; // misc unuseful stuff
                else {
                    console.log(`insn ${insn.name} var ${varr} has unknown type ${type}`);
                }

                // t_addrmode_rr

                // sanity check
                if(varr.match(/^R[dtnm]/) && !isGPR)
                    throw `? insn ${insn.name} var ${varr} type ${type}`;
                break;
            }
            case 'AArch64': {
                // yay, highly restricted use of PC
                //console.log(insn.name, insn.isBranchy, type);
                if(insn.isBranchy && (type == 'addr' || type.match(/b.*target$/)))
                    info.codeAddrRef = true;
                else if(type.match(/^adrp?label|am_ldrlit$/))
                    info.dataAddrRef = true;
                if(submode == 'hook') {
                    if((insn.name.match(/^(LDR.*l|ADRP?)$/) &&
                       (type == 'Rt' || type == 'Xd')) || // hack
                       (insn.name.match(/^(RET|BLR)$/) && type == 'Rn'))
                        info.otherImportant = true;
                }
                break;
            }
            default:
                throw '?';
            } // switch

            info.interesting = info.codeAddrRef || info.dataAddrRef ||
                               info.otherImportant || info.mayWritePC;
            if(info.interesting) {
                anyInteresting = true;
                if(info.writesGPR)
                    anyWritesGPR = true;
            }
            varInfo[varr] = makeDefensive(varInfo[varr]);
        }

        if(!anyInteresting)
            return uninterestingReturn(insn);

        if(submode == 'hook') {
            for(let [varr, stats] of items(varInfo))
                if(anyWritesGPR && stats.relevantToGPRWrite)
                    stats.interesting = true;
        }

        if(insn.namespace == 'ARM') {
            let eligible = Array.from(filter(varr => varInfo[varr].writesGPR && varInfo[varr].mayWritePC, keys(varInfo)));
            if(eligible.length == 1 && varInfo[eligible[0]].size != 0) {
                let varr = eligible[0];
                let stats = varInfo[varr];
                if(stats.size == 4)
                    stats.forcedVal = ['1', '1', '1', '1'];
                else if(stats.size == 16) {
                    stats.forcedVal = [];
                    for(let i = 0; i < 15; i++)
                        stats.forcedVal.push('?');
                    stats.forcedVal.push('1');
                } else
                    throw `? ${insn.name} ${varr}`;
                stats.interesting = false;
            }
        }

        insn.inst = insn.inst.map((bit, i) => {
            if(!Array.isArray(bit))
                return bit;
            let stats = varInfo[bit[0]];
            if(stats.forcedVal)
                return stats.forcedVal[bit[1]];
            else if(!stats.interesting)
                return '?'; // redact
            else
                return bit;
        });

        /*
        happens sometimes
        if(nbits < opBitLocs.length)
            console.log('not all bit locs accounted for: ' + insn.name + ' : ' + JSON.stringify(insn.inst));
        */
        let nameBits = [];
        for(let varr in varInfo) {
            let info = varInfo[varr];
            if(info.interesting)
                nameBits.push(varr + (info.out ? '_out' : ''));
        }
        nameBits.sort();
        let name = nameBits.join(',');
        if(!name)
            name = 'x';
        //console.log('representing', insn.name, 'as', name);
        return name;
    });
    //console.log(insns2);
    let node = genDisassembler(insns2, ns, {maxLength: 5, uniqueNodes: true});
    //console.log(ppTable(node));
    console.log(genGeneratedWarning());
    for(let [groupName, groupInsns] of items(groupBy(insn => insn.groupName, insns2))) {
        let comment = `/${''}* ${groupName}:`;
        let its = Array.from(items(groupBy(insn => insn.groupAndBitsName, groupInsns)));
        for(let [groupAndBitsName, groupAndBitsInsns] of its)
            comment += (its.length == 1 ? ' ' : ` [${groupAndBitsName}] `) +
                       groupAndBitsInsns.map(insn => insn.name).join(', ');
        comment += ' */';
        console.log(comment);
    }
    let useBitslice = submode == 'hook';
    let out = tableToBitsliceOrValCaller(node,
        opt.options['dis-pattern'] || 'XXX',
        opt.options['dis-extra-args'] || (lang.isRust ? '' : 'ctx'),
        useBitslice);
    writeFile(outfile, out);
}

function genDebugDisassembler(outfile) {
    let node = genDisassembler(insns, ns, {maxLength: 5, uniqueNodes: true});
    let data = genGeneratedWarning() + '\n';
    data += tableToDebugCaller(node, 'cb',
                               opt.options['dis-extra-args'] ? [opt.options['dis-extra-args']] : (lang.isRust ? [] : ['ctx']));
    data += '\n';
    writeFile(outfile, data);
}

if(opt.options['gen-sema']) {
    genSema(insns, ns);
}
if(opt.options['extraction-formulas']) {
    for(let insn of insns) {
        console.log(insn.name);
        let runsByOp = instToOpRuns(insn.inst);
        for(let op in runsByOp)
            console.log('   ' + op + ': ' + lang.render(opRunsToExtractionFormula(runsByOp[op], 'x')));
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
let name = opt.options['print-op-positions'];
if(name) {
    printOpPositions(insns, name);
}
if(opt.options['print-insns']) {
    for(let insn of insns) {
        console.log(insn);
    }
}
