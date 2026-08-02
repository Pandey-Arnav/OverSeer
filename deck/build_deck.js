const pptxgen = require("pptxgenjs");

const path = require("path");
const A = path.join(__dirname, "assets") + path.sep;

// ---- palette (matches the site/video) ----
const BG      = "0A0D12";
const PANEL   = "12161D";
const PANEL2  = "171C24";
const LINE    = "262C36";
const TEXT    = "E7EBF1";
const MUTED   = "7C8798";
const ALERT   = "FF4B2B";
const ALERT_D = "4A2318";
const SAFE    = "33D6A6";
const SAFE_D  = "163430";
const WARN    = "FFB020";
const WARN_D  = "2A210A";

const F_TITLE = "Arial";
const F_BODY  = "Arial";
const F_MONO  = "Courier New";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5
const PW = 13.333, PH = 7.5;

function bgSlide() {
  const s = pres.addSlide();
  s.background = { color: BG };
  return s;
}

function brandCorner(s, opts = {}) {
  const tag = opts.tag || null;
  s.addImage({ path: A + "eye_logo.png", x: 0.45, y: 0.35, w: 0.42, h: 0.325 });
  s.addText("OVERSEER", {
    x: 0.95, y: 0.33, w: 3, h: 0.36, fontFace: F_TITLE, bold: true,
    fontSize: 14, color: TEXT, align: "left", valign: "middle", charSpacing: 1, margin: 0
  });
  if (tag) {
    const tw = 0.09 * tag.length + 0.3;
    s.addShape(pres.ShapeType.roundRect, {
      x: PW - 0.45 - tw, y: 0.34, w: tw, h: 0.34, rectRadius: 0.06,
      fill: { color: tag.bg }, line: { type: "none" }
    });
    s.addText(tag.text, {
      x: PW - 0.45 - tw, y: 0.34, w: tw, h: 0.34, fontFace: F_MONO, bold: true,
      fontSize: 10.5, color: tag.color, align: "center", valign: "middle", margin: 0
    });
  }
}

function eyebrow(s, txt, x, y, color = WARN) {
  s.addText(txt.toUpperCase(), {
    x, y, w: 8, h: 0.32, fontFace: F_MONO, bold: true, fontSize: 11.5,
    color, charSpacing: 1.2, margin: 0
  });
}

function iconChip(s, iconPath, x, y, size = 0.62) {
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w: size, h: size, rectRadius: 0.09,
    fill: { color: PANEL2 }, line: { color: LINE, width: 0.75 }
  });
  const pad = size * 0.22;
  s.addImage({ path: iconPath, x: x + pad, y: y + pad, w: size - pad * 2, h: size - pad * 2 });
}

function featCard(s, x, y, w, h, iconPath, title, desc) {
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w, h, rectRadius: 0.08,
    fill: { color: PANEL }, line: { color: LINE, width: 0.75 }
  });
  iconChip(s, iconPath, x + 0.22, y + 0.22, 0.5);
  s.addText(title, {
    x: x + 0.22, y: y + 0.85, w: w - 0.44, h: 0.36, fontFace: F_TITLE, bold: true,
    fontSize: 14, color: TEXT, margin: 0, valign: "top"
  });
  s.addText(desc, {
    x: x + 0.22, y: y + 1.2, w: w - 0.44, h: h - 1.35, fontFace: F_BODY,
    fontSize: 11, color: MUTED, margin: 0, valign: "top", lineSpacingMultiple: 1.25
  });
}

function pill(s, txt, x, y, color, bg, fontSize = 10) {
  const w = txt.length * 0.072 + 0.28;
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w, h: 0.3, rectRadius: 0.05, fill: { color: bg }, line: { type: "none" }
  });
  s.addText(txt, {
    x, y, w, h: 0.3, fontFace: F_MONO, bold: true, fontSize, color,
    align: "center", valign: "middle", margin: 0
  });
  return w;
}

// =========================================================
// SLIDE 1 — TITLE
// =========================================================
{
  const s = bgSlide();
  pill(s, "HACKATHON — SAFETY TRACK", PW / 2 - 1.35, 0.9, WARN, WARN_D, 11);
  s.addImage({ path: A + "eye_logo.png", x: PW / 2 - 0.85, y: 1.6, w: 1.7, h: 1.31 });
  s.addText("OVERSEER", {
    x: 0, y: 3.05, w: PW, h: 0.95, fontFace: F_TITLE, bold: true, fontSize: 54,
    color: TEXT, align: "center", charSpacing: 2, margin: 0
  });
  s.addText("Free background protection against scam and phishing links.", {
    x: PW / 2 - 4, y: 3.95, w: 8, h: 0.5, fontFace: F_BODY, fontSize: 16,
    color: MUTED, align: "center", margin: 0
  });
  s.addShape(pres.ShapeType.ellipse, {
    x: PW / 2 - 3.1, y: 4.75, w: 0.09, h: 0.09, fill: { color: SAFE }, line: { type: "none" }
  });
  s.addText("Free to use  —  no subscription, no paywalled protection", {
    x: PW / 2 - 3.0, y: 4.62, w: 6, h: 0.35, fontFace: F_MONO, fontSize: 11.5,
    color: SAFE, align: "left", valign: "middle", margin: 0
  });
}

// =========================================================
// SLIDE 2 — THE PROBLEM
// =========================================================
{
  const s = bgSlide();
  brandCorner(s);
  eyebrow(s, "The problem", 0.7, 1.15);
  s.addText("Scam links move faster than warnings do.", {
    x: 0.7, y: 1.5, w: 6.3, h: 1.1, fontFace: F_TITLE, bold: true, fontSize: 30,
    color: TEXT, margin: 0, valign: "top"
  });
  const bullets = [
    "They arrive in texts, DMs, emails, and comments — not just shady websites.",
    "Official blocklists take time to catch up; scam domains rotate fast.",
    "By the time a link gets flagged, plenty of people have already clicked it."
  ];
  let by = 2.85;
  bullets.forEach(b => {
    s.addShape(pres.ShapeType.ellipse, { x: 0.7, y: by + 0.09, w: 0.09, h: 0.09, fill: { color: ALERT }, line: { type: "none" } });
    s.addText(b, { x: 0.98, y: by - 0.08, w: 5.9, h: 0.65, fontFace: F_BODY, fontSize: 13.5, color: MUTED, margin: 0, valign: "top", lineSpacingMultiple: 1.3 });
    by += 0.85;
  });

  // right panel: "before Overseer" mock
  const px = 7.5, py = 1.5, pw = 5.2, ph = 4.6;
  s.addShape(pres.ShapeType.roundRect, { x: px, y: py, w: pw, h: ph, rectRadius: 0.08, fill: { color: PANEL }, line: { color: LINE, width: 0.75 } });
  s.addText("// WITHOUT OVERSEER", { x: px + 0.3, y: py + 0.28, w: pw - 0.6, h: 0.3, fontFace: F_MONO, fontSize: 11, color: MUTED, margin: 0 });
  s.addShape(pres.ShapeType.roundRect, { x: px + 0.3, y: py + 0.8, w: pw - 0.6, h: 0.55, rectRadius: 0.06, fill: { color: PANEL2 }, line: { color: LINE, width: 0.75 } });
  s.addText("secure-bankonline-verify.com/login", { x: px + 0.5, y: py + 0.8, w: pw - 1.0, h: 0.55, fontFace: F_MONO, fontSize: 11.5, color: ALERT, valign: "middle", margin: 0 });
  s.addText("Looks identical to the real login page. No warning shown.", {
    x: px + 0.3, y: py + 1.55, w: pw - 0.6, h: 0.5, fontFace: F_BODY, fontSize: 12, color: MUTED, margin: 0, italic: true
  });
  s.addShape(pres.ShapeType.line, { x: px + 0.3, y: py + 2.3, w: pw - 0.6, h: 0, line: { color: LINE, width: 1 } });
  s.addText("214", { x: px + 0.3, y: py + 2.5, w: 2, h: 0.7, fontFace: F_TITLE, bold: true, fontSize: 34, color: ALERT, margin: 0 });
  s.addText("people had already been scammed by this link before it was ever flagged.", {
    x: px + 0.3, y: py + 3.25, w: pw - 0.6, h: 0.9, fontFace: F_BODY, fontSize: 12.5, color: TEXT, margin: 0, lineSpacingMultiple: 1.3
  });
}

// =========================================================
// SLIDE 3 — HOW IT WORKS (pipeline)
// =========================================================
{
  const s = bgSlide();
  brandCorner(s, { tag: { text: "ARMED", color: SAFE, bg: SAFE_D } });
  eyebrow(s, "How it works", 0.7, 1.15);
  s.addText("One quiet pipeline, four steps.", {
    x: 0.7, y: 1.5, w: 10, h: 0.6, fontFace: F_TITLE, bold: true, fontSize: 30, color: TEXT, margin: 0
  });

  const steps = [
    { icon: "icon_graph", label: "Link clicked" },
    { icon: "icon_guard", label: "Checked against scam list\n& community reports" },
    { icon: "icon_bolt", label: "Risk scored by\nrules + AI" },
    { icon: "icon_shield", label: "Warned or\nblocked" }
  ];
  const n = steps.length;
  const totalW = 10.5, gap = 0.5;
  const cardW = (totalW - gap * (n - 1)) / n;
  const startX = (PW - totalW) / 2;
  const cy = 3.6;

  steps.forEach((st, i) => {
    const x = startX + i * (cardW + gap);
    iconChip(s, A + st.icon + ".png", x + cardW / 2 - 0.35, cy - 0.9, 0.7);
    s.addText(st.label, {
      x: x - 0.15, y: cy + 0.05, w: cardW + 0.3, h: 0.7, fontFace: F_BODY, fontSize: 12,
      color: TEXT, align: "center", valign: "top", margin: 0, lineSpacingMultiple: 1.2
    });
    if (i < n - 1) {
      s.addText(">", {
        x: x + cardW + 0.03, y: cy - 0.62, w: gap - 0.06, h: 0.4, fontFace: F_MONO, bold: true,
        fontSize: 18, color: LINE, align: "center", valign: "middle", margin: 0
      });
    }
  });

  const lx = PW / 2 - 3.6, ly = 5.4, lw = 7.2;
  s.addShape(pres.ShapeType.roundRect, { x: lx, y: ly, w: lw, h: 0.7, rectRadius: 0.06, fill: { color: PANEL }, line: { color: LINE, width: 0.75 } });
  s.addText([
    { text: "$ verdict: risk 97/100  ", options: { color: MUTED } },
    { text: "ACTION: BLOCKED", options: { color: SAFE, bold: true } }
  ], {
    x: lx + 0.25, y: ly, w: lw - 0.5, h: 0.7, fontFace: F_MONO, fontSize: 13, valign: "middle", margin: 0
  });
}

// =========================================================
// SLIDE 4 — FOUR SYSTEMS (2x2)
// =========================================================
{
  const s = bgSlide();
  brandCorner(s);
  eyebrow(s, "What's actually running", 0.7, 1.15);
  s.addText("Four systems, one pipeline.", {
    x: 0.7, y: 1.5, w: 10, h: 0.55, fontFace: F_TITLE, bold: true, fontSize: 30, color: TEXT, margin: 0
  });

  const cards = [
    { icon: "icon_guard", title: "Background Guard", desc: "Checks links as you click them. Not a dashboard you have to babysit." },
    { icon: "icon_graph", title: "Threat Graph", desc: "Turns scattered signals into the full story of why a link was flagged." },
    { icon: "icon_bolt", title: "Rule + AI Risk Engine", desc: "Instant rules catch known scams; AI reasons through anything new." },
    { icon: "icon_shield", title: "Silent Enforcement", desc: "Warns you or blocks the link outright, before you'd notice anything." }
  ];
  const gW = 5.6, gH = 1.95, gx0 = PW / 2 - gW - 0.15, gx1 = PW / 2 + 0.15, gy0 = 2.35, gy1 = gy0 + gH + 0.25;
  featCard(s, gx0, gy0, gW, gH, A + cards[0].icon + ".png", cards[0].title, cards[0].desc);
  featCard(s, gx1, gy0, gW, gH, A + cards[1].icon + ".png", cards[1].title, cards[1].desc);
  featCard(s, gx0, gy1, gW, gH, A + cards[2].icon + ".png", cards[2].title, cards[2].desc);
  featCard(s, gx1, gy1, gW, gH, A + cards[3].icon + ".png", cards[3].title, cards[3].desc);
}

// =========================================================
// SLIDE 5 — COVERAGE (3x2)
// =========================================================
{
  const s = bgSlide();
  brandCorner(s);
  eyebrow(s, "Coverage", 0.7, 1.15);
  s.addText("The kinds of links it catches.", {
    x: 0.7, y: 1.5, w: 10, h: 0.55, fontFace: F_TITLE, bold: true, fontSize: 30, color: TEXT, margin: 0
  });

  const cards = [
    { icon: "icon_envelope", title: "Cloned bank & login links", desc: "Pages that copy a real bank or brokerage login pixel-for-pixel." },
    { icon: "icon_cart", title: "Fake checkout links", desc: "Payment pages that redirect through a lookalike gateway." },
    { icon: "icon_coin", title: "Crypto & investment scams", desc: "\"Double your money\" links shared in DMs and comments." },
    { icon: "icon_zigzag", title: "Malicious redirect chains", desc: "Links that bounce through domains to hide the real destination." },
    { icon: "icon_gift", title: "Fake giveaway links", desc: "\"You've won\" links designed to harvest card details." },
    { icon: "icon_people", title: "Community-reported links", desc: "Anything another user has flagged, even before any watchlist." }
  ];
  const cols = 3, gW = 3.75, gH = 2.05, gapX = 0.25, gapY = 0.25;
  const totalW = cols * gW + (cols - 1) * gapX;
  const startX = (PW - totalW) / 2;
  const startY = 2.35;
  cards.forEach((c, i) => {
    const col = i % cols, row = Math.floor(i / cols);
    const x = startX + col * (gW + gapX);
    const y = startY + row * (gH + gapY);
    featCard(s, x, y, gW, gH, A + c.icon + ".png", c.title, c.desc);
  });
}

// =========================================================
// SLIDE 6 — COMMUNITY REPORTS
// =========================================================
{
  const s = bgSlide();
  brandCorner(s);
  eyebrow(s, "Community reports", 0.7, 1.15);
  s.addText("Reported by someone. Blocked for everyone.", {
    x: 0.7, y: 1.5, w: 11.5, h: 0.6, fontFace: F_TITLE, bold: true, fontSize: 27, color: TEXT, margin: 0
  });
  s.addText("If you land on a scam link, flag it in a few seconds. The next person who clicks it gets warned automatically.", {
    x: 0.7, y: 2.1, w: 11.5, h: 0.45, fontFace: F_BODY, fontSize: 13, color: MUTED, margin: 0
  });

  // left: report form mock
  const lx = 0.7, ly = 2.8, lw = 5.3, lh = 4.0;
  s.addShape(pres.ShapeType.roundRect, { x: lx, y: ly, w: lw, h: lh, rectRadius: 0.08, fill: { color: PANEL }, line: { color: LINE, width: 0.75 } });
  iconChip(s, A + "icon_chat.png", lx + 0.28, ly + 0.28, 0.5);
  s.addText("Report a link", { x: lx + 0.9, y: ly + 0.28, w: 3, h: 0.5, fontFace: F_TITLE, bold: true, fontSize: 14, color: TEXT, valign: "middle", margin: 0 });

  s.addText("LINK", { x: lx + 0.3, y: ly + 1.0, w: 2, h: 0.3, fontFace: F_MONO, fontSize: 9.5, color: MUTED, margin: 0 });
  s.addShape(pres.ShapeType.roundRect, { x: lx + 0.3, y: ly + 1.3, w: lw - 0.6, h: 0.45, rectRadius: 0.05, fill: { color: PANEL2 }, line: { color: LINE, width: 0.75 } });
  s.addText("https://", { x: lx + 0.5, y: ly + 1.3, w: lw - 1, h: 0.45, fontFace: F_MONO, fontSize: 12, color: MUTED, valign: "middle", margin: 0 });

  s.addText("WHAT HAPPENED?", { x: lx + 0.3, y: ly + 1.95, w: 3, h: 0.3, fontFace: F_MONO, fontSize: 9.5, color: MUTED, margin: 0 });
  const chips = ["Scam / Fraud", "Phishing", "Fake checkout", "Other"];
  let cx = lx + 0.3;
  chips.forEach((c, i) => {
    const active = i === 0;
    const w = pill(s, c, cx, ly + 2.25, active ? ALERT : MUTED, active ? ALERT_D : PANEL2, 9.5);
    cx += w + 0.12;
  });

  s.addShape(pres.ShapeType.roundRect, { x: lx + 0.3, y: ly + 2.85, w: lw - 0.6, h: 0.5, rectRadius: 0.06, fill: { color: ALERT }, line: { type: "none" } });
  s.addText("Submit report", { x: lx + 0.3, y: ly + 2.85, w: lw - 0.6, h: 0.5, fontFace: F_MONO, bold: true, fontSize: 12, color: BG, align: "center", valign: "middle", margin: 0 });
  s.addText("No account or sign-up needed. Reviewed automatically within minutes.", {
    x: lx + 0.3, y: ly + 3.45, w: lw - 0.6, h: 0.45, fontFace: F_BODY, fontSize: 10.5, color: MUTED, margin: 0, italic: true, lineSpacingMultiple: 1.2
  });

  // right: feed
  const rx = 6.35, ry = 2.8, rw = 6.3;
  s.addText("// COMMUNITY REPORTS", { x: rx, y: ry, w: rw, h: 0.3, fontFace: F_MONO, fontSize: 11, color: MUTED, margin: 0 });
  const feed = [
    { domain: "secure-bankonline-verify[.]com", meta: "214 reports — cloned login page.", tag: "CONFIRMED", safe: true },
    { domain: "quick-crypto-doubler[.]net", meta: "12 reports — fake crypto doubling.", tag: "REVIEW", safe: false },
    { domain: "prize-claim-fast[.]info", meta: "58 reports — fake sweepstakes.", tag: "CONFIRMED", safe: true },
    { domain: "invoice-payment-update[.]com", meta: "6 reports — fake invoice redirect.", tag: "REVIEW", safe: false }
  ];
  let fy = ry + 0.4;
  feed.forEach(f => {
    s.addText(f.domain, { x: rx, y: fy, w: 4.4, h: 0.32, fontFace: F_MONO, fontSize: 12, color: TEXT, margin: 0 });
    pill(s, f.tag, rx + 4.55, fy, f.safe ? SAFE : WARN, f.safe ? SAFE_D : WARN_D, 9);
    s.addText(f.meta, { x: rx, y: fy + 0.32, w: rw, h: 0.32, fontFace: F_BODY, fontSize: 11, color: MUTED, margin: 0 });
    s.addShape(pres.ShapeType.line, { x: rx, y: fy + 0.78, w: rw, h: 0, line: { color: LINE, width: 0.75 } });
    fy += 0.95;
  });
}

// =========================================================
// SLIDE 7 — OPEN THE APP / PROTECTION REPORT
// =========================================================
{
  const s = bgSlide();
  brandCorner(s, { tag: { text: "REPORT", color: ALERT, bg: ALERT_D } });
  eyebrow(s, "Open the app", 0.7, 1.15);
  s.addText("See exactly what it stopped.", {
    x: 0.7, y: 1.5, w: 8, h: 0.6, fontFace: F_TITLE, bold: true, fontSize: 30, color: TEXT, margin: 0
  });
  s.addText("No live feed to babysit — open Overseer after the fact and get the full story in plain language.", {
    x: 0.7, y: 2.1, w: 11.5, h: 0.4, fontFace: F_BODY, fontSize: 13, color: MUTED, margin: 0
  });

  const cx = 0.7, cy = 2.75, cw = 6.0, ch = 3.9;
  s.addShape(pres.ShapeType.roundRect, { x: cx, y: cy, w: cw, h: ch, rectRadius: 0.08, fill: { color: PANEL }, line: { color: LINE, width: 0.75 } });
  s.addText("94", { x: cx + 0.3, y: cy + 0.25, w: 2, h: 0.9, fontFace: F_TITLE, bold: true, fontSize: 46, color: ALERT, margin: 0 });
  s.addText("/100", { x: cx + 1.55, y: cy + 0.65, w: 1, h: 0.5, fontFace: F_MONO, fontSize: 14, color: MUTED, margin: 0 });
  s.addText("CONFIDENCE", { x: cw + cx - 2.0, y: cy + 0.3, w: 1.7, h: 0.25, fontFace: F_MONO, fontSize: 9.5, color: MUTED, align: "right", margin: 0 });
  s.addText("0.91", { x: cw + cx - 2.0, y: cy + 0.55, w: 1.7, h: 0.35, fontFace: F_TITLE, bold: true, fontSize: 15, color: TEXT, align: "right", margin: 0 });

  const rows = [
    ["PATTERN", "Cloned Bank Login Link"],
    ["WHY", "This link led to a page that copied your bank's login exactly, and 214 other users had already reported it as a scam."],
    ["WHAT WE DID", "Blocked the page from loading and warned you before it opened."]
  ];
  let ry = cy + 1.35;
  rows.forEach(([k, v]) => {
    s.addShape(pres.ShapeType.line, { x: cx + 0.3, y: ry, w: cw - 0.6, h: 0, line: { color: LINE, width: 0.75 } });
    s.addText(k, { x: cx + 0.3, y: ry + 0.08, w: 1.5, h: 0.6, fontFace: F_MONO, fontSize: 10, color: MUTED, margin: 0 });
    s.addText(v, { x: cx + 1.9, y: ry + 0.08, w: cw - 2.2, h: 0.85, fontFace: F_BODY, fontSize: 11.5, color: TEXT, margin: 0, lineSpacingMultiple: 1.25 });
    ry += k === "WHY" ? 1.05 : 0.75;
  });

  // right: recent activity mini list
  const rx = 7.1, ry2 = 2.75, rw = 5.5;
  s.addText("// RECENT ACTIVITY", { x: rx, y: ry2, w: rw, h: 0.3, fontFace: F_MONO, fontSize: 11, color: MUTED, margin: 0 });
  const items = [
    ["TODAY, 9:14 AM", "Blocked a cloned bank login link before it opened.", "BLOCKED"],
    ["YESTERDAY", "Warned about a crypto \"doubling\" link from a group chat.", "BLOCKED"],
    ["MONDAY", "Flagged a giveaway link with only a few reports so far.", "FLAGGED"],
    ["LAST WEEK", "Blocked a link 340 people had already reported.", "BLOCKED"]
  ];
  let iy = ry2 + 0.4;
  items.forEach(([when, desc, tag]) => {
    s.addText(when, { x: rx, y: iy, w: 3, h: 0.28, fontFace: F_MONO, fontSize: 10, color: MUTED, margin: 0 });
    pill(s, tag, rx + rw - 1.3, iy - 0.02, tag === "BLOCKED" ? SAFE : WARN, tag === "BLOCKED" ? SAFE_D : WARN_D, 8.5);
    s.addText(desc, { x: rx, y: iy + 0.26, w: rw, h: 0.4, fontFace: F_BODY, fontSize: 11, color: TEXT, margin: 0, lineSpacingMultiple: 1.15 });
    s.addShape(pres.ShapeType.line, { x: rx, y: iy + 0.68, w: rw, h: 0, line: { color: LINE, width: 0.75 } });
    iy += 0.85;
  });
}

// =========================================================
// SLIDE 8 — WHY IT'S DIFFERENT (3 cols)
// =========================================================
{
  const s = bgSlide();
  brandCorner(s);
  eyebrow(s, "Why it's built this way", 0.7, 1.15);
  s.addText("Protection without the babysitting.", {
    x: 0.7, y: 1.5, w: 10, h: 0.55, fontFace: F_TITLE, bold: true, fontSize: 30, color: TEXT, margin: 0
  });
  s.addText("Most security tools ask you to watch a live feed. Overseer is built around the opposite idea.", {
    x: 0.7, y: 2.05, w: 11, h: 0.4, fontFace: F_BODY, fontSize: 13, color: MUTED, margin: 0
  });

  const cards = [
    { icon: "icon_doc", title: "No dashboard to babysit", desc: "Nothing to leave open on a second monitor. Overseer isn't a feed you're expected to watch." },
    { icon: "icon_guard", title: "Not continuously scanning", desc: "It steps in around specific moments — a link click — not your whole browsing session." },
    { icon: "icon_chat", title: "Explains every action", desc: "Every warning or block comes with a plain-language reason, not just a red banner." }
  ];
  const gW = 3.85, gH = 2.9, gap = 0.3;
  const totalW = 3 * gW + 2 * gap;
  const startX = (PW - totalW) / 2, y0 = 2.75;
  cards.forEach((c, i) => {
    featCard(s, startX + i * (gW + gap), y0, gW, gH, A + c.icon + ".png", c.title, c.desc);
  });
}

// =========================================================
// SLIDE 9 — PRICING
// =========================================================
{
  const s = bgSlide();
  brandCorner(s);
  eyebrow(s, "Pricing", PW / 2 - 0.6, 1.1, WARN);
  s.addText("One plan. It's free.", {
    x: 0, y: 1.4, w: PW, h: 0.6, fontFace: F_TITLE, bold: true, fontSize: 30, color: TEXT, align: "center", margin: 0
  });
  s.addText("No subscription. No premium tier. Nothing held back behind a paywall.", {
    x: 0, y: 2.0, w: PW, h: 0.4, fontFace: F_BODY, fontSize: 13, color: MUTED, align: "center", margin: 0
  });

  const cw = 7.4, cx = PW / 2 - cw / 2, cy = 2.6, ch = 4.1;
  s.addShape(pres.ShapeType.roundRect, { x: cx, y: cy, w: cw, h: ch, rectRadius: 0.1, fill: { color: PANEL }, line: { color: LINE, width: 0.75 } });
  s.addText([
    { text: "$0", options: { color: SAFE, bold: true, fontSize: 46 } },
    { text: "  / forever", options: { color: MUTED, fontSize: 14, fontFace: F_MONO } }
  ], { x: 0, y: cy + 0.35, w: PW, h: 0.9, align: "center", fontFace: F_TITLE, margin: 0 });
  s.addText("Every install gets the full system from day one.", {
    x: 0, y: cy + 1.25, w: PW, h: 0.4, fontFace: F_BODY, fontSize: 12.5, color: MUTED, align: "center", margin: 0
  });

  const items = ["Background Guard", "Threat Graph", "Rule + AI Risk Engine", "Silent Enforcement", "Report unlimited scam links", "Community-reported warnings"];
  const colW = (cw - 1.2) / 2;
  items.forEach((it, i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const ix = cx + 0.6 + col * (colW + 0.4);
    const iy = cy + 1.85 + row * 0.5;
    s.addText("✓", { x: ix, y: iy, w: 0.3, h: 0.35, fontFace: F_TITLE, bold: true, fontSize: 13, color: SAFE, margin: 0 });
    s.addText(it, { x: ix + 0.32, y: iy, w: colW - 0.32, h: 0.35, fontFace: F_BODY, fontSize: 12.5, color: TEXT, valign: "middle", margin: 0 });
  });
}

// =========================================================
// SLIDE 10 — CLOSING
// =========================================================
{
  const s = bgSlide();
  s.addImage({ path: A + "eye_logo.png", x: PW / 2 - 0.75, y: 1.9, w: 1.5, h: 1.155 });
  s.addText("OVERSEER", {
    x: 0, y: 3.25, w: PW, h: 0.8, fontFace: F_TITLE, bold: true, fontSize: 44, color: TEXT, align: "center", charSpacing: 2, margin: 0
  });
  s.addText("Doesn't watch every second. Catches the moment that matters.", {
    x: 0, y: 4.05, w: PW, h: 0.4, fontFace: F_BODY, fontSize: 14, color: MUTED, align: "center", margin: 0
  });

  const badges = ["FREE FOREVER", "BACKGROUND APP", "OPENS ON DEMAND", "COMMUNITY REPORTS"];
  const widths = badges.map(b => b.length * 0.078 + 0.32);
  const gap = 0.18;
  const totalW = widths.reduce((a, b) => a + b, 0) + gap * (badges.length - 1);
  let bx = PW / 2 - totalW / 2;
  const by = 4.75;
  badges.forEach((b, i) => {
    const w = widths[i];
    s.addShape(pres.ShapeType.roundRect, { x: bx, y: by, w, h: 0.34, rectRadius: 0.05, fill: { type: "none" }, line: { color: LINE, width: 0.75 } });
    s.addText(b, { x: bx, y: by, w, h: 0.34, fontFace: F_MONO, fontSize: 9.5, color: MUTED, align: "center", valign: "middle", margin: 0 });
    bx += w + gap;
  });
}

pres.writeFile({ fileName: path.join(__dirname, "overseer-deck.pptx") }).then(() => {
  console.log("done");
});
