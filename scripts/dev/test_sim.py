#!/usr/bin/env python3
"""Simulation of time-based encoder/decoder across display refresh rates."""

import random


def test_basic(sp, hz, seed):
    """No VFR, just encoder→decoder at given display Hz."""
    random.seed(seed)
    d = "".join(random.choice("01") for _ in range(320))
    f = "1010101010101010" + d + "0101010101010101"
    fm = 1000.0 / hz
    tt, bs, bi = 0.0, 0.0, 0
    fr = []
    while bi < len(f):
        while bi < len(f) and tt - bs >= sp:
            bs += sp
            bi += 1
        if bi >= len(f):
            break
        fr.append((tt / 1000, f[bi] == "1"))
        tt += fm
    sc = []
    p = "1" if fr[0][1] else "0"
    sc.append((p, fr[0][0]))
    for i in range(1, len(fr)):
        s = "1" if fr[i][1] else "0"
        if s != p:
            sc.append((s, fr[i][0]))
            p = s
    td = []
    for i in range(len(sc)):
        nt = sc[i + 1][1] if i + 1 < len(sc) else fr[-1][0] + fm / 1000
        td.append(nt - sc[i][1])
    bd = sp / 1000
    dec = ""
    for i in range(len(sc)):
        dec += sc[i][0] * max(1, round(td[i] / bd))
    si = dec.find("1010101010101010")
    ei = dec.rfind("0101010101010101")
    return si >= 0 and ei > si and dec[si + 16 : ei] == d


def test_vfr(sp, hz, seed):
    """With VFR codec at 60fps + 10% jitter."""
    random.seed(seed)
    d = "".join(random.choice("01") for _ in range(320))
    f = "1010101010101010" + d + "0101010101010101"
    fm = 1000.0 / hz
    tt, bs, bi = 0.0, 0.0, 0
    fr = []
    while bi < len(f):
        while bi < len(f) and tt - bs >= sp:
            bs += sp
            bi += 1
        if bi >= len(f):
            break
        fr.append((tt / 1000, f[bi] == "1"))
        tt += fm
    # VFR codec at ~60fps with 10% jitter
    cfm = 1000.0 / 60
    vid = []
    vt = 0.0
    while vt / 1000 <= fr[-1][0] + 0.02:
        st = False
        for ct, cg in fr:
            if ct <= vt / 1000:
                st = cg
            else:
                break
        j = random.gauss(0, cfm * 0.1)
        vid.append((max(0, vt + j) / 1000, st))
        vt += cfm
    vid.sort(key=lambda x: x[0])
    # Decoder
    sc = []
    p = "1" if vid[0][1] else "0"
    sc.append((p, vid[0][0]))
    for i in range(1, len(vid)):
        s = "1" if vid[i][1] else "0"
        if s != p:
            sc.append((s, vid[i][0]))
            p = s
    td = []
    for i in range(len(sc)):
        nt = sc[i + 1][1] if i + 1 < len(sc) else vid[-1][0] + cfm / 1000
        td.append(nt - sc[i][1])
    bd = sp / 1000
    dec = ""
    for i in range(len(sc)):
        dec += sc[i][0] * max(1, round(td[i] / bd))
    si = dec.find("1010101010101010")
    ei = dec.rfind("0101010101010101")
    return si >= 0 and ei > si and dec[si + 16 : ei] == d


if __name__ == "__main__":
    N = 200
    print(f"=== BASIC TEST (no VFR, {N} seeds) ===")
    for sp in [200, 500]:
        for hz in [24, 30, 37, 48, 60, 75, 90, 120, 144, 240]:
            ok = sum(1 for s in range(N) if test_basic(sp, hz, s))
            tag = "PASS" if ok == N else "FAIL"
            print(f"  [{tag}] {sp}ms {hz:>3}Hz: {ok}/{N}")

    N2 = 100
    print(f"\n=== VFR TEST (60fps codec + 10% jitter, {N2} seeds) ===")
    for sp in [200, 500]:
        for hz in [30, 37, 60, 120]:
            ok = sum(1 for s in range(N2) if test_vfr(sp, hz, s))
            tag = "PASS" if ok == N2 else "FAIL"
            print(f"  [{tag}] {sp}ms {hz:>3}Hz VFR: {ok}/{N2}")

    print("\nDone!")
