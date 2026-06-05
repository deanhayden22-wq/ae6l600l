"""
Cross-reference the tip-in / overrun-resume fueling levers across three tunes:
  stock  = rom/ae5l600l.bin
  garn   = rom/13 20g Base rev 25 e garn.hex   (raw binary despite .hex)
  20.17  = rom/AE5L600L 20g rev 20.17.bin       (current)

Lever 1 (overrun resume, scalars):
  cc49c Overrun initial injector enrichment (pulsewidth)  ms = raw*0.001
  cc498 Overrun Enrich RPM Delta Activation               raw ecu value
  cc4ec Overrun Fueling Cut Counter RPM Threshold          RPM

Lever 2 (base tip-in magnitude, 18-elem along Throttle Angle Change %):
  ced50 Throttle Tip-in Enrichment A   IPW(ms) = raw_u16*0.004 ; axis ced08 (float %)
  cedbc Throttle Tip-in Enrichment B   IPW(ms) = raw_u16*0.004 ; axis ced74 (float %)

Multipliers that scale the base (so magnitude can only be judged together):
  cd118 Tip-in comp (RPM)   comp% = u8*0.78125-100 ; axis cd0d8 (float RPM)
  cd14c Tip-in comp (BoostErr) comp% = u8*0.78125-100 ; axis cd128 (float, psi=raw*0.01933677)
"""
import struct
ROMS={'stock':'rom/ae5l600l.bin','garn':'rom/13 20g Base rev 25 e garn.hex',
      '20.17':'rom/AE5L600L 20g rev 20.17.bin'}
R={k:open(v,'rb').read() for k,v in ROMS.items()}
def f1(b,a): return struct.unpack('>f',b[a:a+4])[0]
def fN(b,a,n): return [struct.unpack('>f',b[a+4*i:a+4*i+4])[0] for i in range(n)]
def u16N(b,a,n): return [struct.unpack('>H',b[a+2*i:a+2*i+2])[0] for i in range(n)]
def u8N(b,a,n): return list(b[a:a+n])
comp=lambda x:x*0.78125-100

print("="*72)
print("LEVER 1 - OVERRUN / FUEL-CUT RESUME (scalars)")
print("="*72)
print(f"{'':<42}{'stock':>9}{'garn':>9}{'20.17':>9}")
print(f"{'Overrun initial injector enrich (ms)':<42}"+''.join(f'{f1(R[k],0xcc49c)*0.001:>9.2f}' for k in R))
print(f"{'Overrun Enrich RPM Delta Activation (raw)':<42}"+''.join(f'{f1(R[k],0xcc498):>9.1f}' for k in R))
print(f"{'Overrun Fueling Cut Counter RPM Thresh':<42}"+''.join(f'{f1(R[k],0xcc4ec):>9.0f}' for k in R))

print("\n"+"="*72)
print("LEVER 2 - BASE TIP-IN ENRICHMENT A  (IPW ms by throttle-angle-change %)")
print("="*72)
axA={k:fN(R[k],0xced08,18) for k in R}
datA={k:u16N(R[k],0xced50,18) for k in R}
print(f"{'dTPS% (20.17 axis)':<8}"+''.join(f'{x:>8.1f}' for x in axA['20.17'][:12]))
for k in R:
    print(f"{k+' IPW':<8}"+''.join(f'{d*0.004:>8.2f}' for d in datA[k][:12]))
print("  (cols 12-17 continue; shown first 12 covering the live stab range)")
ratio=[datA['garn'][i]/max(1,datA['20.17'][i]) for i in range(8)]
print("  garn vs 20.17 ratio:", ' '.join(f'{r:.2f}' for r in ratio))

print("\n"+"="*72)
print("LEVER 2 - BASE TIP-IN ENRICHMENT B")
print("="*72)
datB={k:u16N(R[k],0xcedbc,18) for k in R}
for k in R:
    print(f"{k+' IPW':<8}"+''.join(f'{d*0.004:>8.2f}' for d in datB[k][:12]))

print("\n"+"="*72)
print("MULTIPLIER - Tip-in comp (RPM)  comp% (axis = RPM)")
print("="*72)
axR=fN(R['20.17'],0xcd0d8,16)
print(f"{'RPM':<8}"+''.join(f'{int(r):>7}' for r in axR[:11]))
for k in R:
    print(f"{k:<8}"+''.join(f'{comp(b):>7.0f}' for b in u8N(R[k],0xcd118,16)[:11]))

print("\n"+"="*72)
print("MULTIPLIER - Tip-in comp (Boost Error)  comp% (axis psi)")
print("="*72)
for k in R:
    ax=[x*0.01933677 for x in fN(R[k],0xcd128,9)]
    print(f"{k} axis psi:"+''.join(f'{p:>7.2f}' for p in ax))
    print(f"{k} comp%   :"+''.join(f'{comp(b):>7.1f}' for b in u8N(R[k],0xcd14c,9)))
