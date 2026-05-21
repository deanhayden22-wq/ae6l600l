"""DEFEND: is the 20.11->20.12 stutter improvement real, or just drive-context shift?
Approach: restrict all 3 revs to a COMMON operating envelope and compare like-for-like.
Common envelope:
  - active pedal (Accelerator > 5)
  - RPM 1500-4500
  - load 0.3-1.5
  - MPH 15-65 (urban/suburban — not highway cruise)
And: only count stutter events that occur INSIDE pedal-modulation episodes
(i.e. APP is oscillating, not in steady cruise — to avoid the 'cruise has no stutters because cruise has no pedal motion' tautology).
"""
import pandas as pd, numpy as np
from pathlib import Path

OUT = Path("/sessions/epic-happy-cannon/mnt/outputs/explore")
df = pd.read_parquet(OUT / "all.parquet").sort_values(["log_id","sample"]).reset_index(drop=True)

df["dthr"] = df.groupby("log_id")["Throttle"].diff()
df["dapp"] = df.groupby("log_id")["Accelerator"].diff()
df["app_lag"] = df.groupby("log_id")["Accelerator"].shift(1)
df["app_3s_std"] = df.groupby("log_id")["Accelerator"].rolling(75, min_periods=10).std().reset_index(level=0, drop=True)

# Common operating envelope mask
in_env = (df.Accelerator > 5) & (df.RPM > 1500) & (df.RPM < 4500) & (df.load > 0.3) & (df.load < 1.5) & (df.MPH > 15) & (df.MPH < 65)

# Pedal-modulation episode: APP standard deviation over 3s > 5% (driver feathering)
pedal_active = in_env & (df.app_3s_std > 5)

# Stutter inside that envelope
stut_mask = pedal_active & (df.app_lag > 5) & (df.dapp.abs() < 1.5) & (df.dthr <= -3)

print("=== Normalized comparison: common operating envelope (in-town/urban) ===")
rows = []
for rev in ["20.10","20.11","20.12"]:
    rev_mask = df.rev == rev
    env_min = (rev_mask & in_env).sum() / 25 / 60
    pedal_min = (rev_mask & pedal_active).sum() / 25 / 60
    n_stut = (rev_mask & stut_mask).sum()
    rate_env = n_stut / env_min if env_min>0 else 0
    rate_ped = n_stut / pedal_min if pedal_min>0 else 0
    rows.append({"rev": rev, "in_envelope_min": round(env_min,1), "pedal_modulating_min": round(pedal_min,1), "n_stutters": int(n_stut), "per_env_min": round(rate_env,3), "per_pedal_mod_min": round(rate_ped,3)})
out_table = pd.DataFrame(rows)
print(out_table.to_string(index=False))
out_table.to_csv(OUT/"stutter_normalized.csv", index=False)

# Bootstrap CI for the rate
print("\n=== Bootstrap 95% CI on rate per pedal-modulating minute (10k resamples of episodes) ===")
# build per-log-episode rates
def episodes(rev):
    sub_df = df[(df.rev == rev) & pedal_active].copy()
    # split into episodes by log_id and contiguous segments
    eps = []
    for log_id, sub in sub_df.groupby("log_id"):
        if len(sub) == 0: continue
        # contiguous = sample index continuous (gap > 1 row = break)
        gaps = sub["sample"].diff() > 1
        sub["ep"] = gaps.cumsum()
        for ep_id, ep in sub.groupby("ep"):
            n_samples = len(ep)
            n_stut = stut_mask.loc[ep.index].sum()
            eps.append((n_samples, n_stut))
    return eps

rng = np.random.default_rng(42)
for rev in ["20.10","20.11","20.12"]:
    eps = episodes(rev)
    if len(eps) == 0:
        print(f"rev {rev}: no episodes")
        continue
    eps_arr = np.array(eps)
    rates = []
    for _ in range(10000):
        idx = rng.integers(0, len(eps_arr), len(eps_arr))
        s = eps_arr[idx].sum(axis=0)
        if s[0] > 0:
            rates.append(s[1] / (s[0]/25/60))
    rates = np.array(rates)
    print(f"  rev {rev}: median rate={np.median(rates):.3f}/min  95%CI=[{np.quantile(rates, 0.025):.3f}, {np.quantile(rates, 0.975):.3f}]  n_episodes={len(eps_arr)}")

# Confirm: is the difference statistically clean even after normalizing?
# Bonus: stutter depth distribution (how severe are they when they happen?)
print("\n=== Stutter SEVERITY (dthr percentile) when they do happen ===")
for rev in ["20.10","20.11","20.12"]:
    rev_stut = df[(df.rev == rev) & stut_mask]
    if len(rev_stut) == 0: continue
    print(f"rev {rev}: dthr p50={rev_stut.dthr.median():.2f}%  p90={rev_stut.dthr.quantile(0.10):.2f}%  p99={rev_stut.dthr.quantile(0.01):.2f}%")
