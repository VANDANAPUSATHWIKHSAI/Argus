---
description: Rule for retrieving the glass_theme_old template snapshot
globs: ["**/*"]
---

# glass_theme_old Rule

When the user asks for or mentions **`glass_theme_old`**, provide or restore the template files saved in:
- `d:\ARGUS\sample\FE\src\templates\glass_theme_old\`
- `d:\ARGUS\glass_theme_old\`

### Snapshot Components:
1. `GlassDashboardTemplate.jsx`: Complete frosted glass dashboard with:
   - Vertically centered floating sidebar navigation card (`top: calc(50% - 60px); transform: translateY(-50%)`).
   - Dedicated separate bottom-left session anchor card for user profile and logout.
   - Full-width floating topbar island capsule centered at the top of the viewport (`width: calc(100vw - 40px); left: 50%; transform: translateX(-50%)`).
2. `GlassDashboardTemplate.css`: Complete styling with greyish-black canvas (`#181a20`), neutral light mode (`#eef2f7`), crystal rims, and sheen.
3. `glass/`: The entire suite of 5 specialized glass sub-templates, 3D globe canvas, and gallery components.
