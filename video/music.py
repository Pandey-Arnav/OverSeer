import os
import numpy as np
from scipy.io import wavfile

SR = 44100
DUR = 30.0
N = int(SR*DUR)
t = np.arange(N) / SR
out = np.zeros(N)

def env_exp(n, sr, decay):
    tt = np.arange(n)/sr
    return np.exp(-tt/decay)

def add_at(buf, sound, start_t):
    i0 = int(start_t*SR)
    i1 = i0 + len(sound)
    if i1 > len(buf):
        sound = sound[:len(buf)-i0]
        i1 = len(buf)
    if i0 < 0 or i0 >= len(buf):
        return
    buf[i0:i1] += sound

BPM = 108.0
BEAT = 60.0/BPM        # ~0.5556s
EIGHTH = BEAT/2

# ---- root notes (A minor-ish, moody/techy) ----
def note_hz(semi_from_a1):
    return 55.0 * (2 ** (semi_from_a1/12.0))

A1, C2, E2 = note_hz(0), note_hz(3), note_hz(7)
A3, C4, E4, G4 = note_hz(24), note_hz(27), note_hz(31), note_hz(34)

# =========================================================
# 1) Sub-bass pulse on every beat
# =========================================================
n_beats = int(DUR/BEAT) + 1
bass_notes = [A1, A1, C2, A1] * (n_beats//4 + 2)
for i in range(n_beats):
    bt = i*BEAT
    if bt > DUR: break
    dur = min(BEAT*0.9, DUR-bt)
    n = int(dur*SR)
    if n <= 0: continue
    tone = np.sin(2*np.pi*bass_notes[i]*np.arange(n)/SR)
    e = env_exp(n, SR, 0.28)
    add_at(out, tone*e*0.16, bt)

# =========================================================
# 2) Soft arpeggio, 8th notes, triangle-ish (sine + light harmonic)
# =========================================================
arp_pattern = [A3, C4, E4, C4, A3, E4, C4, G4]
n_eighths = int(DUR/EIGHTH) + 1
for i in range(n_eighths):
    et = i*EIGHTH
    if et > DUR - 0.05: break
    freq = arp_pattern[i % len(arp_pattern)]
    dur = min(EIGHTH*0.85, DUR-et)
    n = int(dur*SR)
    if n <= 0: continue
    tt = np.arange(n)/SR
    tone = np.sin(2*np.pi*freq*tt) + 0.25*np.sin(2*np.pi*freq*2*tt)
    e = env_exp(n, SR, 0.09)
    vol = 0.045 if (i % 2 == 0) else 0.03
    add_at(out, tone*e*vol, et)

# =========================================================
# 3) Sustained pad bed (very low, slow fades per section)
# =========================================================
pad_freqs = [A3, C4, E4]
pad = np.zeros(N)
for f in pad_freqs:
    pad += np.sin(2*np.pi*f*t + f*0.001)
pad /= len(pad_freqs)
fade_in = np.clip(t/2.0, 0, 1)
fade_out = np.clip((DUR-t)/2.0, 0, 1)
pad_env = fade_in*fade_out
out += pad*pad_env*0.028

# =========================================================
# 4) Sync accents: soft "blip" per graph-node reveal in the hero
#    scene (t = 0,1,2,3,4s), then a bigger "impact" for BLOCKED (t=5s)
# =========================================================
rng = np.random.default_rng(7)
blip_times = [0.35, 1.6, 2.85, 4.1, 5.35]
for bt in blip_times:
    n = int(0.12*SR)
    tt = np.arange(n)/SR
    freq = 740
    tone = np.sin(2*np.pi*freq*tt*(1+tt*2))
    e = env_exp(n, SR, 0.05)
    add_at(out, tone*e*0.05, bt)

# impact hit for "BLOCKED" reveal (hero's 6th node lights at t=6.25s)
impact_t = 6.6
n = int(0.5*SR)
tt = np.arange(n)/SR
sub = np.sin(2*np.pi*70*tt) * env_exp(n, SR, 0.22)
noise = rng.standard_normal(n) * env_exp(n, SR, 0.04)
impact = sub*0.5 + noise*0.25
add_at(out, impact*0.5, impact_t)

# small accent blips at each later scene change too (subtle, keeps momentum)
for st in [9.0, 12.0, 18.0, 27.0]:
    n = int(0.15*SR)
    tt = np.arange(n)/SR
    tone = np.sin(2*np.pi*520*tt)
    e = env_exp(n, SR, 0.06)
    add_at(out, tone*e*0.035, st)

# =========================================================
# Master fades + normalize
# =========================================================
fade_len = int(0.4*SR)
out[:fade_len] *= np.linspace(0,1,fade_len)
fade_len_out = int(0.7*SR)
out[-fade_len_out:] *= np.linspace(1,0,fade_len_out)

peak = np.max(np.abs(out))
if peak > 0:
    out = out / peak * 0.7   # headroom, background-level volume

out_i16 = np.int16(np.clip(out, -1, 1) * 32767)
wavfile.write(os.path.join(os.path.dirname(os.path.abspath(__file__)), "overseer_bgm.wav"), SR, out_i16)
print("wrote overseer_bgm.wav", len(out_i16)/SR, "s")
