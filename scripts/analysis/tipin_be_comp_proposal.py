"""
20.18 candidate: single-table tip-in fix = reshape BE-comp DATA (0xCD14C) only.
Leave axis (0xCD128), base A/B, RPM comp, gates, ECT comps UNTOUCHED (single-variable).

Goal: stop the BE-comp from gutting tip-in at the BE the cusp stabs actually live at
(1-3 psi). Keep cell0 (BE<=0 = boost met => no tip-in) and cell8 (neutral) unchanged.
Stay well short of garn's +50% (which over-enriches every stab).
"""
import struct, numpy as np
rom=open('rom/AE5L600L 20g rev 20.17.bin','rb').read()
comp=lambda b: b*0.78125-100
inv =lambda c: int(round((c+100)/0.78125))

be_ax=[x*0.01933677 for x in struct.unpack('>9f',rom[0xcd128:0xcd128+36])]
cur_bytes=list(rom[0xcd14c:0xcd14c+9])
cur=[comp(b) for b in cur_bytes]

# proposed comp% (monotone, lift cells 1-7, keep 0 and 8)
prop = [-88, -58, -40, -25, -14, -7, -3, -1, 0]
prop_bytes=[cur_bytes[0]]+[inv(c) for c in prop[1:8]]+[cur_bytes[8]]
prop_real=[comp(b) for b in prop_bytes]

print("BE-comp (0xCD14C) — current vs proposed")
print(f"{'cell':>4}{'BE psi':>8}{'cur%':>8}{'curByte':>8}{'  ->':>4}{'newByte':>8}{'new%':>8}")
for i in range(9):
    print(f"{i:>4}{be_ax[i]:>8.2f}{cur[i]:>8.1f}{cur_bytes[i]:>8}{'  ->':>4}{prop_bytes[i]:>8}{prop_real[i]:>8.1f}")
print("monotonic:", all(prop_real[i]<=prop_real[i+1]+1e-6 for i in range(8)))
print("raw bytes to flash @0xCD14C:", ' '.join(f'{b:02X}' for b in prop_bytes))

# net tip-in at cusp operating points (base @dTPS, RPM comp from ROM, BE comp cur vs prop)
def fN(a,n): return [struct.unpack('>f',rom[a+4*i:a+4*i+4])[0] for i in range(n)]
def u16(a,n): return [struct.unpack('>H',rom[a+2*i:a+2*i+2])[0] for i in range(n)]
rpm_ax=fN(0xcd0d8,16); rpm_cp=[comp(b) for b in rom[0xcd118:0xcd118+16]]
bax_ed=fN(0xced08,18); bdat=[x*0.004 for x in u16(0xced50,18)]
def be_interp(be,tbl): return tbl[0] if be<=0 else (tbl[-1] if be>=be_ax[-1] else np.interp(be,be_ax,tbl))
def net(dtps,rpm,be,tbl):
    base=np.interp(dtps,bax_ed,bdat); rc=np.interp(rpm,rpm_ax,rpm_cp); bc=be_interp(be,tbl)
    return base*(1+rc/100)*(1+bc/100), base, rc, bc

print("\nNet tip-in IPW (ms) at cusp operating points:")
pts={'gentle cusp stab (BE 1.8, dTPS 6, 2000rpm)':(6,2000,1.8),
     'mid cusp stab     (BE 2.8, dTPS 8, 2300rpm)':(8,2300,2.8),
     'deep early-ramp   (BE 1.4, dTPS 9, 2600rpm)':(9,2600,1.4),
     'deep settled      (BE 7.0, dTPS 10,2600rpm)':(10,2600,7.0)}
for lbl,(d,r,be) in pts.items():
    nc,b,rc,bcc=net(d,r,be,cur); npd,_,_,bcp=net(d,r,be,prop_real)
    print(f"  {lbl}: cur {nc:.2f}ms (BEc {bcc:+.0f}%) -> prop {npd:.2f}ms (BEc {bcp:+.0f}%)   x{npd/nc:.1f}")
print("\nNote: deep-settled (BE>6.73) unchanged by design (cell8 untouched) — still garn-level.")
print("Steady cruise unaffected: tip-in needs dTPS>0; at dTPS~0 base~0 so BEc multiplies ~0.")
