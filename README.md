# Overseer

A free background app concept that checks links against known scams and
community reports, and warns you before you land on something dangerous.
Built for a safety-track hackathon.

## Contents

- **`website/`** — the marketing site (`index.html`, single self-contained file)
- **`video/`** — the 30s promo video generator
  - `gen.py` — renders all frames (Pillow) to `video/frames/`
  - `music.py` — synthesizes the background score (NumPy/SciPy) to `overseer_bgm.wav`
  - `fonts/` — Inter Tight + JetBrains Mono, used by the renderer
  - `output/overseer-video.mp4` — the final rendered video
- **`deck/`** — the pitch deck generator
  - `build_deck.js` — builds the deck (pptxgenjs)
  - `gen_icons.py` — generates the icon set (Pillow) into `deck/assets/`
  - `assets/` — generated icons + logo
  - `overseer-deck.pptx` — the final 10-slide deck

## Regenerating the video

```bash
cd video
pip install pillow numpy scipy
python3 gen.py            # renders frames/frame_00000.png ... frame_00899.png
python3 music.py           # writes overseer_bgm.wav
ffmpeg -y -framerate 30 -i frames/frame_%05d.png -i overseer_bgm.wav \
  -c:v libx264 -pix_fmt yuv420p -crf 18 -c:a aac -b:a 160k \
  -shortest -movflags +faststart output/overseer-video.mp4
```

## Regenerating the deck

```bash
cd deck
python3 gen_icons.py       # writes assets/*.png
npm install pptxgenjs      # if not already available
node build_deck.js         # writes overseer-deck.pptx
```

## Notes

- All three pieces (site, video, deck) share one visual system: dark
  graphite background, an orange/black eye mark, alert-orange + safe-green
  accents, Inter Tight for display type, JetBrains Mono for data/log text.
- This is hackathon-concept content — the fraud-detection claims describe
  the intended product, not a verified, shipping backend.
