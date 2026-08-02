import os, math, textwrap
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720
FPS = 30
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "frames")
os.makedirs(OUT, exist_ok=True)

# ---- palette (matches the html ad) ----
BG      = (10, 13, 18)
PANEL   = (18, 22, 29)
PANEL2  = (23, 28, 36)
LINE    = (38, 44, 54)
TEXT    = (231, 235, 241)
MUTED   = (124, 135, 152)
ALERT   = (255, 75, 43)
ALERT_D = (74, 35, 24)
SAFE    = (51, 214, 166)
SAFE_D  = (22, 52, 48)
WARN    = (255, 176, 32)
WARN_D  = (42, 33, 10)

SANS_DIR = os.path.join(HERE, "fonts", "inter-tight") + os.sep
def FS(name, size):
    return ImageFont.truetype(SANS_DIR + name, size)

MONO_DIR = os.path.join(HERE, "fonts", "jetbrains-mono") + os.sep
def FM(name, size):
    return ImageFont.truetype(MONO_DIR + name, size)

f_h1      = FS("InterTight-Bold.ttf", 46)
f_h1_sm   = FS("InterTight-Bold.ttf", 34)
f_sec     = FS("InterTight-Bold.ttf", 30)
f_body    = FS("InterTight-Regular.ttf", 17)
f_body_sm = FS("InterTight-Regular.ttf", 14)
f_mono    = FM("JetBrainsMono-Regular.ttf", 13)
f_mono_sm = FM("JetBrainsMono-Regular.ttf", 12)
f_mono_b  = FM("JetBrainsMono-Bold.ttf", 13)
f_card_h  = FS("InterTight-SemiBold.ttf", 16)
f_score   = FS("InterTight-ExtraBold.ttf", 48)
f_brand   = FS("InterTight-Bold.ttf", 22)
f_eyebrow = FM("JetBrainsMono-Bold.ttf", 13)

def ease(t):
    return t*t*(3-2*t)

def clamp(v, a=0.0, b=1.0):
    return max(a, min(b, v))

def lerp_color(c1, c2, t):
    return tuple(int(c1[i] + (c2[i]-c1[i])*t) for i in range(3))

def new_canvas():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img, "RGBA")
    return img, d

def fade_alpha(base_img, alpha):
    if alpha >= 0.999:
        return base_img
    bgimg = Image.new("RGB", (W, H), BG)
    return Image.blend(bgimg, base_img, clamp(alpha))

def text_w(draw, txt, font):
    bbox = draw.textbbox((0,0), txt, font=font)
    return bbox[2]-bbox[0]

def draw_eye(d, cx, cy, r, fill=ALERT, pupil=None, alpha=None):
    """Draws the orange/black eye-mark logo: a lens/almond shape with a
    black vertical-slit pupil, matching the HTML logo's SVG path."""
    if pupil is None:
        pupil = BG
    n = 24
    h = r * 0.727
    pts_top = []
    pts_bot = []
    for i in range(n+1):
        tt = -1 + 2*i/n
        x = cx + r*tt
        yoff = h * math.sqrt(max(0, 1 - tt*tt))
        pts_top.append((x, cy - yoff))
        pts_bot.append((x, cy + yoff))
    poly = pts_top + list(reversed(pts_bot))
    fcol = fill if alpha is None else fill + (alpha,)
    pcol = pupil if alpha is None else pupil + (alpha,)
    d.polygon(poly, fill=fcol)
    prx = r * 0.145
    pry = r * 0.40
    d.ellipse([cx-prx, cy-pry, cx+prx, cy+pry], fill=pcol)

def draw_topbar(d, tag="ARMED", tag_color=SAFE, tag_bg=SAFE_D):
    d.line([(0,64),(W,64)], fill=LINE, width=1)
    draw_eye(d, 33, 32, 13)
    d.text((55,32), "OVERSEER", font=f_brand, fill=TEXT, anchor="lm")
    tw = text_w(d, tag, f_mono_b) + 20
    d.rounded_rectangle([W-32-tw, 32-12, W-32, 32+12], radius=5, fill=tag_bg)
    d.text((W-32-tw/2, 32), tag, font=f_mono_b, fill=tag_color, anchor="mm")

# ============================================================
# SCENE 1 — HERO with animated protection graph
# ============================================================
HERO_STEPS = [
    ("Bank login page",        '$ session opened - verifying domain fingerprint', False),
    ("Cloned domain flagged",  '$ event: domain registered 2 days ago, mimics bank cert  [RULE MATCH]', False),
    ("Autofill hijack attempt",'$ event: autofill fields injected outside form origin  [RULE MATCH]', False),
    ("Clipboard address swap", '$ event: clipboard rewritten - account number swapped', False),
    ("Credential POST",        '$ event: XHR POST -> credentials + one-time code', False),
    ("BLOCKED",                '$ verdict: risk 94/100  ACTION: BLOCKED', True),
]

def render_hero(t_scene):
    img, d = new_canvas()
    draw_topbar(d, tag="ARMED", tag_color=SAFE, tag_bg=SAFE_D)

    fade = ease(clamp(t_scene/0.15))

    lx = 70
    d.text((lx, 150), "BACKGROUND PROTECTION FOR YOUR MONEY", font=f_eyebrow, fill=WARN)
    lines = ["Your bank tab is a", "moving target.", "Overseer stands guard."]
    ly = 195
    for i, ln in enumerate(lines):
        col = ALERT if i == 2 else TEXT
        d.text((lx, ly), ln, font=f_h1, fill=col)
        ly += 58
    sub = ["A quiet background app that watches for fraud", "around your money and steps in before anything", "moves."]
    sy = ly + 18
    for ln in sub:
        d.text((lx, sy), ln, font=f_body, fill=MUTED)
        sy += 26

    bx = lx
    by = sy + 30
    btxt = "> SEE WHAT IT'S BLOCKED"
    bw = text_w(d, btxt, f_mono_b) + 36
    d.rounded_rectangle([bx, by, bx+bw, by+44], radius=6, fill=ALERT)
    d.text((bx+bw/2, by+22), btxt, font=f_mono_b, fill=BG, anchor="mm")

    px, py, pw, ph = 660, 110, 550, 490
    d.rounded_rectangle([px,py,px+pw,py+ph], radius=10, fill=PANEL, outline=LINE, width=1)
    d.text((px+22, py+26), "// PROTECTION LOG", font=f_mono_sm, fill=MUTED)

    n_steps = len(HERO_STEPS)
    cycle_len = 7.5
    per_step = cycle_len / n_steps
    raw_idx = t_scene / per_step
    active_idx = int(clamp(raw_idx, 0, n_steps-1+0.999))
    active_idx = min(active_idx, n_steps-1)

    node_x = px + pw//2
    node_y0 = py + 90
    gap = 62
    node_positions = [node_y0 + i*gap for i in range(n_steps)]

    for i in range(n_steps-1):
        y1 = node_positions[i] + 16
        y2 = node_positions[i+1] - 16
        is_last_edge = (i == n_steps-2)
        col = LINE
        if i < active_idx:
            col = ALERT if is_last_edge else WARN
        d.line([(node_x,y1),(node_x,y2)], fill=col, width=2)

    for i, (label, log, is_block) in enumerate(HERO_STEPS):
        cy = node_positions[i]
        lit = i <= active_idx
        col_outline = LINE
        col_fill = PANEL2
        if lit:
            col_outline = ALERT if is_block else WARN
            if is_block:
                col_fill = ALERT_D
        r = 15 if is_block else 13
        d.ellipse([node_x-r, cy-r, node_x+r, cy+r], fill=col_fill, outline=col_outline, width=2)
        tcol = TEXT if lit else MUTED
        if is_block and lit:
            tcol = ALERT
        d.text((node_x+26, cy), label, font=f_mono_sm, fill=tcol, anchor="lm")

    cur_log = HERO_STEPS[active_idx][1]
    d.line([(px+22, py+ph-46),(px+pw-22, py+ph-46)], fill=LINE, width=1)
    d.text((px+22, py+ph-24), cur_log, font=f_mono_sm, fill=MUTED)

    return fade_alpha(img, fade)

# ============================================================
# SCENE 2 — BUMPER: "not always watching, always ready"
# ============================================================
def render_bumper(t_scene):
    img, d = new_canvas()
    cx, cy = W//2, H//2 - 20

    dot_t = clamp((t_scene-0.1)/1.0)
    dot_col = lerp_color((60,66,76), SAFE, dot_t)
    r = 8
    d.ellipse([cx-r,cy-90-r,cx+r,cy-90+r], fill=dot_col)
    if dot_t > 0.3:
        glow_r = r + int(10*dot_t)
        overlay = Image.new("RGBA", (W,H), (0,0,0,0))
        od = ImageDraw.Draw(overlay)
        od.ellipse([cx-glow_r,cy-90-glow_r,cx+glow_r,cy-90+glow_r], fill=SAFE+(int(40*dot_t),))
        img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
        d = ImageDraw.Draw(img, "RGBA")

    a1 = ease(clamp(t_scene/0.5))
    line1 = "It's not always watching."
    w1 = text_w(d, line1, f_sec)
    d.text((cx-w1/2, cy-40), line1, font=f_sec, fill=lerp_color(BG, MUTED, a1))

    a2 = ease(clamp((t_scene-0.55)/0.5))
    line2 = "It's always ready."
    w2 = text_w(d, line2, f_sec)
    d.text((cx-w2/2, cy+2), line2, font=f_sec, fill=lerp_color(BG, TEXT, a2))

    return img

# ============================================================
# SCENE 3 — FEATURES grid
# ============================================================
FEATURES = [
    ("Background Guard", "Runs quietly behind whatever you're doing, not a dashboard you babysit.",
     "hooks: bank & payment domains, checkout forms,", "clipboard, autofill, wallet extensions, SMS prompts"),
    ("Threat Graph", "Turns scattered signals into the full story of what almost happened.",
     "example: bank login -> cloned domain ->", "autofill hijack -> clipboard swap -> blocked"),
    ("Rule + AI Risk Engine", "Instant rules catch known scams; AI reasons through anything new.",
     "rules: cloned bank domain, clipboard swap,", "checkout redirect chain, fake payment popup"),
    ("Silent Enforcement", "Stops the transfer, restores your clipboard, closes the tab.",
     "action: hold -> restore -> block,", "one tap to review what happened"),
]

def render_features(t_scene):
    img, d = new_canvas()
    draw_topbar(d, tag="4 SYSTEMS", tag_color=WARN, tag_bg=WARN_D)

    d.text((70,130), "WHAT'S ACTUALLY RUNNING", font=f_eyebrow, fill=MUTED)
    d.text((70,158), "Four systems, one pipeline", font=f_sec, fill=TEXT)

    grid_y = 230
    card_w, card_h, gap = 270, 300, 20
    total_w = card_w*4 + gap*3
    start_x = (W - total_w)//2

    for i, (title, desc, hook1, hook2) in enumerate(FEATURES):
        reveal_t = clamp((t_scene - i*0.35) / 0.4)
        a = ease(reveal_t)
        if a <= 0.02:
            continue
        cx = start_x + i*(card_w+gap)
        cy = grid_y + int((1-a)*24)
        overlay = Image.new("RGBA", (W,H), (0,0,0,0))
        od = ImageDraw.Draw(overlay)
        od.rounded_rectangle([cx,cy,cx+card_w,cy+card_h], radius=10, fill=PANEL+(int(255*a),), outline=LINE+(int(255*a),), width=1)
        od.rounded_rectangle([cx+22, cy+22, cx+22+34, cy+22+34], radius=7, fill=PANEL2+(int(255*a),))
        od.ellipse([cx+22+10, cy+22+10, cx+22+24, cy+22+24], outline=WARN+(int(255*a),), width=2)
        od.text((cx+22, cy+74), title, font=f_card_h, fill=TEXT+(int(255*a),), anchor="la")
        wrapped = textwrap.wrap(desc, width=30)
        wy = cy+100
        for ln in wrapped:
            od.text((cx+22, wy), ln, font=f_body_sm, fill=MUTED+(int(255*a),))
            wy += 20
        wy += 8
        od.text((cx+22, wy), hook1, font=f_mono_sm, fill=(90,96,110,int(255*a)))
        od.text((cx+22, wy+16), hook2, font=f_mono_sm, fill=(90,96,110,int(255*a)))
        img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
        d = ImageDraw.Draw(img, "RGBA")

    return img

# ============================================================
# SCENE 4 — OPEN THE APP: protection report + activity timeline
# ============================================================
TIMELINE_ITEMS = [
    ("TODAY, 9:14 AM", "Blocked a cloned bank login before credentials were sent.", "BLOCKED", SAFE, SAFE_D),
    ("YESTERDAY",       "Caught a clipboard swap during a $1,240 transfer.",         "BLOCKED", SAFE, SAFE_D),
    ("TUESDAY",         "Stopped a fake checkout page mid-payment.",                 "BLOCKED", SAFE, SAFE_D),
    ("MONDAY",          "Flagged a SIM-swap notification request for review.",       "FLAGGED", WARN, WARN_D),
    ("LAST WEEK",       "Held a wire transfer to a newly-added payee for review.",   "HELD",    WARN, WARN_D),
]

def render_open(t_scene):
    img, d = new_canvas()
    draw_topbar(d, tag="REPORT", tag_color=ALERT, tag_bg=ALERT_D)

    d.text((70,130), "OPEN THE APP", font=f_eyebrow, fill=MUTED)
    d.text((70,158), "See exactly what it stopped", font=f_sec, fill=TEXT)

    a1 = ease(clamp(t_scene/0.35))
    cx, cy, cw, ch = 70, 225, 560, 400
    d.rounded_rectangle([cx,cy,cx+cw,cy+ch], radius=10, fill=PANEL, outline=LINE, width=1)
    score_disp = int(94*a1)
    d.text((cx+24, cy+30), f"{score_disp}", font=f_score, fill=ALERT, anchor="la")
    sw = text_w(d, f"{score_disp}", f_score)
    d.text((cx+24+sw+6, cy+58), "/100", font=f_mono, fill=MUTED, anchor="la")
    d.text((cx+cw-24, cy+30), "CONFIDENCE", font=f_mono_sm, fill=MUTED, anchor="ra")
    d.text((cx+cw-24, cy+50), "0.91", font=f_card_h, fill=TEXT, anchor="ra")

    rows = [
        ("PATTERN", "Cloned Bank Domain + Clipboard Hijack"),
        ("GRAPH", "Bank login -> Cloned domain -> Autofill"),
        ("", "hijack -> Clipboard swap -> POST"),
        ("WHY", "Site was 2 days old, copied your bank's login,"),
        ("", "then rewrote your clipboard mid-transfer."),
        ("WHAT WE DID", "Blocked transfer, restored clipboard, closed tab."),
    ]
    ry = cy+100
    for i,(k,v) in enumerate(rows):
        rt = clamp((t_scene - 0.2 - i*0.08)/0.25)
        if rt <= 0.01:
            ry += 46
            continue
        a = ease(rt)
        d.line([(cx+24, ry),(cx+cw-24, ry)], fill=LINE, width=1)
        if k:
            d.text((cx+24, ry+16), k, font=f_mono_sm, fill=lerp_color(BG, MUTED, a))
        d.text((cx+150, ry+16), v, font=f_body_sm, fill=lerp_color(BG, TEXT, a))
        ry += 46

    lx, ly = 690, 225
    d.text((lx, ly-38), "// RECENT ACTIVITY", font=f_mono_sm, fill=MUTED)
    for i,(when,desc,tagtxt,tagcol,tagbg) in enumerate(TIMELINE_ITEMS):
        rt = clamp((t_scene - 0.15 - i*0.13)/0.3)
        if rt <= 0.01: continue
        a = ease(rt)
        yy = ly + i*78 + int((1-a)*14)
        d.text((lx, yy), when, font=f_mono_sm, fill=lerp_color(BG, MUTED, a))
        tw = text_w(d, tagtxt, f_mono_sm)+16
        d.rounded_rectangle([lx+460-tw, yy-4, lx+460, yy+14], radius=4, fill=lerp_color(BG,tagbg,a))
        d.text((lx+460-tw/2, yy+5), tagtxt, font=f_mono_sm, fill=lerp_color(BG,tagcol,a), anchor="mm")
        d.text((lx, yy+22), desc, font=f_body_sm, fill=lerp_color(BG, TEXT, a))
        if i < len(TIMELINE_ITEMS)-1:
            d.line([(lx, yy+56),(lx+460, yy+56)], fill=lerp_color(BG, LINE, a), width=1)

    return img

# ============================================================
# SCENE 5 — FOOTER / END CARD
# ============================================================
def render_footer(t_scene):
    img, d = new_canvas()
    a = ease(clamp(t_scene/0.4))

    cx, cy = W//2, H//2 - 40
    draw_eye(d, cx, cy-96, 20, alpha=int(255*a))
    brand = "OVERSEER"
    bw = text_w(d, brand, f_h1_sm)
    d.text((cx - bw/2, cy-60), brand, font=f_h1_sm, fill=lerp_color(BG,TEXT,a))

    tag = "Doesn't watch every second. Catches the moment that matters."
    tw = text_w(d, tag, f_body)
    d.text((cx-tw/2, cy+10), tag, font=f_body, fill=lerp_color(BG,MUTED,a))

    badges = ["BACKGROUND APP","OPENS ON DEMAND","FRAUD PATTERN DETECTION"]
    total = sum(text_w(d,b,f_mono_sm)+30 for b in badges) + 20*(len(badges)-1)
    bx = cx - total/2
    by = cy+70
    for b in badges:
        bt = clamp((t_scene-0.3)/0.3)
        ba = ease(bt)
        bw2 = text_w(d,b,f_mono_sm)+30
        d.rounded_rectangle([bx,by-15,bx+bw2,by+15], radius=6, outline=lerp_color(BG,LINE,ba), width=1)
        d.text((bx+bw2/2, by), b, font=f_mono_sm, fill=lerp_color(BG,MUTED,ba), anchor="mm")
        bx += bw2+20

    return img

# ============================================================
# TIMELINE (30s total, no team scene)
# ============================================================
SCENES = [
    (render_hero,     9.0),
    (render_bumper,   3.0),
    (render_features, 6.0),
    (render_open,     9.0),
    (render_footer,   3.0),
]

frame_i = 0
for render_fn, dur in SCENES:
    n = int(dur*FPS)
    for k in range(n):
        t_scene = k/FPS
        img = render_fn(t_scene)
        img.save(f"{OUT}/frame_{frame_i:05d}.png")
        frame_i += 1

print("total frames:", frame_i, "duration:", frame_i/FPS, "s")
