"""
Isolate and dissect the high-load 5th-gear highway knock event.

User hypothesis to test:
  "A small pedal blip causes a lean condition. The tip-in enrichment should
   have fired, but because the boost error was so close (small), it was
   probably very reduced -> lean -> knock."

We test that chain against the data: pedal-rate, boost error (Trgt-mrp),
AFR error (wbo2 vs commanded, with sensor-lag shift), and the knock-correction
column, lining them all up on a common time axis.

Source: C:/Users/Dean/Desktop/Untitled 1.csv  (one isolated 5th-gear pull)
"""
import pandas as pd
import numpy as np

SRC = r"C:/Users/Dean/Desktop/Untitled 1.csv"
df = pd.read_csv(SRC)
df.columns = [c.strip() for c in df.columns]

# ---- sanity: column alignment ---------------------------------------------
print("COLUMNS:", list(df.columns))
print(f"rows={len(df)}  t={df.time.min():.2f}..{df.time.max():.2f}s  "
      f"dt~{np.median(np.diff(df.time)):.3f}s")
print(f"MPH {df.MPH.min()}-{df.MPH.max()}  RPM {df.RPM.min()}-{df.RPM.max()}  "
      f"avcs p5/p50/p95 = {df.avcs.quantile(.05):.0f}/{df.avcs.median():.0f}/{df.avcs.quantile(.95):.0f}")

# ---- derived signals -------------------------------------------------------
df["boost_err"] = df.Trgt_Boost - df.mrp          # +ve = under target
df["overboost"] = df.mrp - df.Trgt_Boost          # +ve = OVER target
df["afr_err"]   = df.wbo2 - df.AFR                 # +ve = leaner than commanded
# wideband transport+response lag ~0.2s = 5 samples @25Hz: shift wbo2 earlier
LAG = 5
df["wbo2_combustion"] = df.wbo2.shift(-LAG)        # what mixture actually was
df["afr_err_lagadj"]  = df.wbo2_combustion - df.AFR
df["acc_rate"]  = df.Accelerator.diff() / df.time.diff()   # %/s
df["thr_rate"]  = df.Throttle.diff() / df.time.diff()

# knock column: header calls it FLKC but it behaves as a recovering feedback pull
df["knock"] = df.FLKC

# ---- knock window ----------------------------------------------------------
knock = df[df.knock < 0]
print(f"\n=== KNOCK (FLKC<0): {len(knock)} samples, "
      f"t {knock.time.min():.2f}..{knock.time.max():.2f}  "
      f"(dur {knock.time.max()-knock.time.min():.2f}s)  worst {df.knock.min():.2f} deg ===")
print(f"FBKC range over whole log: {df.FBKC.min()}..{df.FBKC.max()}")

# conditions AT knock onset
on = df[df.knock < 0].index.min()
print(f"\n-- at knock onset (sample {df.loc[on,'sample']:.0f}, t={df.loc[on,'time']:.2f}) --")
for c in ["RPM","MPH","Accelerator","Throttle","mrp","Trgt_Boost","overboost",
          "wbo2","AFR","afr_err","Timing","IAT","avcs","wgdc","IDC"]:
    print(f"   {c:<12}{df.loc[on,c]:.2f}")

# ---- worst lean excursion during the pull (open loop only) -----------------
ol = df[df["CL/OL"] == 10].copy()
worst = ol.loc[ol.afr_err.idxmax()]
print(f"\n=== worst lean-of-command (OL): sample {worst['sample']:.0f} t={worst.time:.2f}  "
      f"wbo2 {worst.wbo2:.2f} vs cmd {worst.AFR:.2f}  (+{worst.afr_err:.2f} AFR) ===")
print(f"   at that point: mrp {worst.mrp:.2f} / Trgt {worst.Trgt_Boost:.2f} "
      f"(BE {worst.boost_err:+.2f})  acc {worst.Accelerator:.1f}%  RPM {worst.RPM:.0f}")

# ---- peak overboost --------------------------------------------------------
pkob = df.loc[df.overboost.idxmax()]
print(f"\n=== peak overboost: sample {pkob['sample']:.0f} t={pkob.time:.2f}  "
      f"mrp {pkob.mrp:.2f} vs Trgt {pkob.Trgt_Boost:.2f} = +{pkob.overboost:.2f} psi over ===")
print(f"   wbo2 {pkob.wbo2:.2f} (cmd {pkob.AFR:.2f})  Timing {pkob.Timing:.1f}  "
      f"knock {pkob.knock:.2f}  RPM {pkob.RPM:.0f}")

# ---- timeline table around the whole event --------------------------------
cols = ["time","RPM","MPH","Accelerator","Throttle","mrp","Trgt_Boost",
        "overboost","wbo2","AFR","afr_err","Timing","knock"]
win = df[(df.time >= 8247.5) & (df.time <= 8253.0)]
pd.set_option("display.width", 200, "display.max_rows", 200,
              "display.float_format", lambda x: f"{x:7.2f}")
print("\n=== TIMELINE 8247.5 .. 8253.0 (every 3rd sample) ===")
print(win.iloc[::3][cols].to_string(index=False))

# ---- tip-in / boost-error coupling check -----------------------------------
# secondary pedal push (the 'blip'): find max acc_rate burst before knock
pre = df[(df.time >= 8247.0) & (df.time < df.loc[on,"time"])]
blip = pre.loc[pre.acc_rate.idxmax()]
print(f"\n=== biggest pedal push before knock: t={blip.time:.2f}  "
      f"acc_rate {blip.acc_rate:+.0f}%/s  acc {blip.Accelerator:.1f}%  "
      f"BE(Trgt-mrp) {blip.boost_err:+.2f} psi ===")
print("   (BE < 9.9 psi => tip-in BE comp in attenuation zone per "
      "project_target_boost_tipin_coupling)")

# correlation: does knock track lean, or overboost?
kd = df[df.time.between(8248.0, 8253.5)]
print(f"\ncorr(knock_depth, overboost) = {kd['knock'].corr(kd['overboost']):.2f}")
print(f"corr(knock_depth, -afr_err_lagadj) = {kd['knock'].corr(-kd['afr_err_lagadj']):.2f}")
print(f"corr(knock_depth, RPM) = {kd['knock'].corr(kd['RPM']):.2f}")
