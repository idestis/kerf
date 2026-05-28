# kerf — logo bundle

Vector and raster assets for the `kerf` brand mark and wordmark.

## What's in here

```
svg/    12 SVG files — vector source of truth
png/    56 PNG files at multiple sizes
```

### Layouts

| Layout | Description | Use for |
|---|---|---|
| `mark` | Logomark only (the cut circle, square canvas) | App icons, favicons, social avatars |
| `horizontal` | Mark left, "kerf" wordmark right | Nav bars, GitHub README headers, conference booth |
| `stacked` | Mark above, "kerf" wordmark below | Splash screens, social cards, posters |

### Color variants

| Variant | Fill | Background | Use when |
|---|---|---|---|
| `on-black` | white | black | Dark UI, terminal screenshots, dark mode |
| `on-white` | black | white | Light UI, docs, print |
| `dark-transparent` | black | none | Place on any light/medium background |
| `light-transparent` | white | none | Place on any dark/medium background |

The transparent variants use proper SVG alpha — the kerf cut shows the background through it, so the mark integrates with whatever it sits on.

## File naming

```
kerf-{layout}-{variant}.svg
kerf-{layout}-{variant}-{width}w.png
```

Examples:
- `kerf-mark-dark-transparent.svg` — black mark, transparent bg, square
- `kerf-horizontal-on-black-1024w.png` — horizontal layout, white on black, 1024px wide

## Design notes

- **Geometry:** circle of radius 100 (in viewBox units), cut by a 6-unit-wide diagonal at 20° below horizontal. The cut is implemented as an SVG `<mask>` so it punches true transparency, not a colored stripe.
- **Wordmark:** "kerf" set in Liberation Mono (SIL OFL licensed). Glyphs are outlined as SVG paths in the files — no font file dependency at render time.
- **No external dependencies:** every SVG is self-contained. Open in any modern browser, Figma, Inkscape, or Illustrator and it renders identically.

## Regenerating

The bundle is produced by Python scripts that compose geometry + glyph outlines:

```
build.py         — generates 12 SVGs from design tokens
render_pngs.py   — uses rsvg-convert to rasterize at all sizes
extract_glyphs.py — outlines the wordmark from Liberation Mono
```

To rebuild after a design token change (cut angle, gap width, color), edit `build.py` constants and rerun. SVG output is deterministic.

## License

The Liberation fonts used for the wordmark are SIL OFL — free for any use including commercial and modification. Glyphs in the SVG files are outlined paths, not embedded font data, so no font-license concerns travel with these files.

The logo design itself is yours.
