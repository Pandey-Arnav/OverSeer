import math, os
from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
os.makedirs(OUT, exist_ok=True)

ALERT = (255, 75, 43, 255)
WARN  = (255, 176, 32, 255)
SAFE  = (51, 214, 166, 255)
BG_TRANSPARENT = (0, 0, 0, 0)

SS = 4  # supersample factor
SIZE = 300 * SS
LW = 16 * SS  # line width

def canvas():
    return Image.new("RGBA", (SIZE, SIZE), BG_TRANSPARENT)

def save(img, name):
    img = img.resize((SIZE // SS, SIZE // SS), Image.LANCZOS)
    img.save(f"{OUT}/{name}.png")
    print("wrote", name)

def center():
    return SIZE // 2, SIZE // 2

# ---------------------------------------------------------------
def icon_guard(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    r = SIZE * 0.28
    d.ellipse([cx-r, cy-r, cx+r, cy+r], outline=color, width=LW)
    r2 = SIZE * 0.09
    d.ellipse([cx-r2, cy-r2, cx+r2, cy+r2], outline=color, width=LW)
    tick = SIZE * 0.13
    for ang in [0, 90, 180, 270]:
        rad = math.radians(ang)
        x0 = cx + (r+tick*0.15) * math.cos(rad)
        y0 = cy + (r+tick*0.15) * math.sin(rad)
        x1 = cx + (r+tick) * math.cos(rad)
        y1 = cy + (r+tick) * math.sin(rad)
        d.line([x0, y0, x1, y1], fill=color, width=LW)
    save(img, "icon_guard")

def icon_graph(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    pts = [(cx-SIZE*0.26, cy-SIZE*0.20), (cx+SIZE*0.26, cy-SIZE*0.20), (cx, cy+SIZE*0.26)]
    r = SIZE*0.075
    for p in pts[:-1]:
        d.line([p, pts[-1]], fill=color, width=int(LW*0.85))
    d.line([pts[0], pts[1]], fill=color, width=int(LW*0.85))
    for p in pts:
        d.ellipse([p[0]-r, p[1]-r, p[0]+r, p[1]+r], fill=color)
    save(img, "icon_graph")

def icon_bolt(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    s = SIZE * 0.30
    pts = [(cx+0.15*s, cy-1.0*s), (cx-0.55*s, cy+0.12*s), (cx-0.05*s, cy+0.12*s),
           (cx-0.15*s, cy+1.0*s), (cx+0.55*s, cy-0.12*s), (cx+0.05*s, cy-0.12*s)]
    d.polygon(pts, fill=color)
    save(img, "icon_bolt")

def icon_shield(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    s = SIZE * 0.30
    pts = [(cx, cy-1.05*s), (cx+0.9*s, cy-0.65*s), (cx+0.9*s, cy+0.15*s),
           (cx, cy+1.05*s), (cx-0.9*s, cy+0.15*s), (cx-0.9*s, cy-0.65*s)]
    d.line(pts+[pts[0]], fill=color, width=LW, joint="curve")
    save(img, "icon_shield")

def icon_envelope(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    w, h = SIZE*0.58, SIZE*0.40
    x0, y0 = cx-w/2, cy-h/2
    x1, y1 = cx+w/2, cy+h/2
    d.rectangle([x0, y0, x1, y1], outline=color, width=LW)
    d.line([x0, y0, cx, cy+h*0.12], fill=color, width=LW)
    d.line([x1, y0, cx, cy+h*0.12], fill=color, width=LW)
    save(img, "icon_envelope")

def icon_cart(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    w, h = SIZE*0.55, SIZE*0.36
    x0, y0 = cx-w/2, cy-h/2-SIZE*0.05
    x1, y1 = cx+w/2, cy+h/2-SIZE*0.05
    d.line([x0-SIZE*0.10, y0-SIZE*0.12, x0, y0], fill=color, width=LW)
    d.rectangle([x0, y0, x1, y1], outline=color, width=LW)
    d.line([x0, (y0+y1)/2, x1, (y0+y1)/2], fill=color, width=int(LW*0.7))
    wr = SIZE*0.05
    for wx in [x0+w*0.2, x1-w*0.2]:
        wy = y1+SIZE*0.10
        d.ellipse([wx-wr, wy-wr, wx+wr, wy+wr], fill=color)
    save(img, "icon_cart")

def icon_coin(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    r1 = SIZE*0.30
    r2 = SIZE*0.20
    d.ellipse([cx-r1, cy-r1, cx+r1, cy+r1], outline=color, width=LW)
    d.ellipse([cx-r2, cy-r2, cx+r2, cy+r2], outline=color, width=int(LW*0.6))
    save(img, "icon_coin")

def icon_zigzag(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    s = SIZE*0.30
    pts = [(cx-s, cy-s*0.7), (cx-s*0.15, cy-s*0.7), (cx-s*0.15, cy),
           (cx+s*0.7, cy), (cx+s*0.7, cy+s*0.7)]
    d.line(pts, fill=color, width=LW, joint="curve")
    ah = SIZE*0.09
    tipx, tipy = pts[-1]
    d.polygon([(tipx, tipy+ah), (tipx-ah, tipy-ah*0.3), (tipx+ah, tipy-ah*0.3)], fill=color)
    save(img, "icon_zigzag")

def icon_gift(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    w, h = SIZE*0.50, SIZE*0.38
    x0, y0 = cx-w/2, cy-h/2+SIZE*0.05
    x1, y1 = cx+w/2, cy+h/2+SIZE*0.05
    d.rectangle([x0, y0, x1, y1], outline=color, width=LW)
    lidh = SIZE*0.09
    d.rectangle([x0-SIZE*0.03, y0-lidh, x1+SIZE*0.03, y0], outline=color, width=LW)
    d.line([cx, y0-lidh, cx, y1], fill=color, width=int(LW*0.8))
    save(img, "icon_gift")

def icon_people(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    r = SIZE*0.11
    for dx in [-SIZE*0.14, SIZE*0.14]:
        hx, hy = cx+dx, cy-SIZE*0.16
        d.ellipse([hx-r, hy-r, hx+r, hy+r], outline=color, width=LW)
    for dx, sgn in [(-SIZE*0.14, -1), (SIZE*0.14, 1)]:
        bx = cx+dx
        d.arc([bx-SIZE*0.20, cy+SIZE*0.02, bx+SIZE*0.20, cy+SIZE*0.42], 200, 340, fill=color, width=LW)
    save(img, "icon_people")

def icon_doc(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    w, h = SIZE*0.44, SIZE*0.56
    x0, y0 = cx-w/2, cy-h/2
    x1, y1 = cx+w/2, cy+h/2
    fold = SIZE*0.12
    d.line([x0, y0, x1-fold, y0], fill=color, width=LW)
    d.line([x1-fold, y0, x1, y0+fold], fill=color, width=LW)
    d.line([x1, y0+fold, x1, y1], fill=color, width=LW)
    d.line([x1, y1, x0, y1], fill=color, width=LW)
    d.line([x0, y1, x0, y0], fill=color, width=LW)
    for i in range(3):
        ly = y0 + h*0.42 + i*h*0.16
        d.line([x0+w*0.16, ly, x1-w*0.16, ly], fill=color, width=int(LW*0.6))
    save(img, "icon_doc")

def icon_chat(color=WARN):
    img = canvas(); d = ImageDraw.Draw(img)
    cx, cy = center()
    w, h = SIZE*0.56, SIZE*0.38
    x0, y0 = cx-w/2, cy-h/2-SIZE*0.04
    x1, y1 = cx+w/2, cy+h/2-SIZE*0.04
    d.rounded_rectangle([x0, y0, x1, y1], radius=SIZE*0.06, outline=color, width=LW)
    d.polygon([(cx-SIZE*0.06, y1), (cx+SIZE*0.02, y1), (cx-SIZE*0.02, y1+SIZE*0.10)], fill=color)
    save(img, "icon_chat")

def icon_eye(fill=ALERT, pupil=(10,13,18,255)):
    img = Image.new("RGBA", (int(SIZE*1.3), SIZE), BG_TRANSPARENT)
    d = ImageDraw.Draw(img)
    cx, cy = img.size[0]//2, img.size[1]//2
    r = SIZE * 0.42
    h = r * 0.727
    n = 48
    pts_top, pts_bot = [], []
    for i in range(n+1):
        tt = -1 + 2*i/n
        x = cx + r*tt
        yoff = h * math.sqrt(max(0, 1 - tt*tt))
        pts_top.append((x, cy - yoff))
        pts_bot.append((x, cy + yoff))
    poly = pts_top + list(reversed(pts_bot))
    d.polygon(poly, fill=fill)
    prx, pry = r*0.145, r*0.40
    d.ellipse([cx-prx, cy-pry, cx+prx, cy+pry], fill=pupil)
    img = img.resize((img.size[0]//SS, img.size[1]//SS), Image.LANCZOS)
    img.save(f"{OUT}/eye_logo.png")
    print("wrote eye_logo")

icon_guard()
icon_graph()
icon_bolt()
icon_shield()
icon_envelope()
icon_cart()
icon_coin()
icon_zigzag()
icon_gift()
icon_people()
icon_doc()
icon_chat()
icon_eye()
print("done")
