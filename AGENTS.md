# ARGUS Workspace Custom Instructions & Aliases

## Keyword Aliases

### `glass_theme_old`
Whenever the user asks for **`glass_theme_old`**, provide or restore the glass dashboard template snapshot stored in:
- `d:\ARGUS\sample\FE\src\templates\glass_theme_old/`
- Backup archive: `d:\ARGUS\glass_theme_old/`

**Snapshot specifications:**
- **Navigation Card**: Centered vertically in the left column (`top: calc(50% - 60px); transform: translateY(-50%)`).
- **User Session Card**: Separate floating card anchored at `bottom: 20px; left: 20px`.
- **Topbar Capsule**: Full-width centered island capsule (`width: calc(100vw - 40px); left: 50%; transform: translateX(-50%)`).
- **Dark Mode**: Refined greyish-black (`#181a20`) canvas with specular crystal rims.
- **Light Mode**: Frosted glass (`#eef2f7`).
- **Sub-templates**: Complete `glass/` suite (5 specialized glass variants, 3D canvas, switcher bar).
