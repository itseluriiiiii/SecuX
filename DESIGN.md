# Design System Document: The SecuX Perspective

 

## 1. Overview & Creative North Star: "The Neon Monolith"

 

The Creative North Star for this design system is **The Neon Monolith**. In the world of high-stakes cybersecurity, the interface must feel like a singular, authoritative entity—silent, powerful, and deeply intentional. 

 

We are moving away from the "Dashboard Fatigue" of thousands of tiny borders and boxes. Instead, we embrace **high-end editorial layouts** for technical data. This system leverages massive typographic scales, aggressive whitespace, and a "Vantablack" depth that allows neon accents to feel like light emitted from a screen, not just ink on a page. We combine the brutalist, centered confidence of Sarvam AI with a futuristic, glass-layered SOC aesthetic.

 

### The Signature Look

- **Intentional Asymmetry:** Break the grid with large, off-center display type.

- **Tonal Depth:** Depth is created through light, not lines.

- **Aggressive Whitespace:** Treat "empty" space as a defensive perimeter.

 

---

 

## 2. Colors: Obsidian & Ionized Gases

 

The color palette is rooted in `surface` (#131313). We do not use "gray"; we use varying densities of darkness.

 

### The "No-Line" Rule

**Explicit Instruction:** Do not use 1px solid borders to define sections. Traditional borders create visual noise that distracts from threat detection. Boundaries must be defined solely through:

1.  **Background Shifts:** Transitioning from `surface` to `surface_container_low`.

2.  **Negative Space:** Using a minimum of 64px gaps between major functional blocks.

 

### Surface Hierarchy & Nesting

Treat the UI as a series of physical layers. Use the following stack to create "nested" depth:

- **Level 0 (Base):** `surface_container_lowest` (#0E0E0E) - The infinite void.

- **Level 1 (Sections):** `surface` (#131313) - The standard workspace.

- **Level 2 (Cards):** `surface_container` (#201F1F) - Interaction zones.

- **Level 3 (Pop-overs):** `surface_container_highest` (#353534) - Immediate focus.

 

### The "Glass & Gradient" Rule

To achieve a "High-Tech SOC" feel, use **Glassmorphism** for floating panels.

- **Token Usage:** Use `secondary_container` at 20% opacity + 20px Backdrop Blur.

- **Signature Gradients:** For critical threats or CTAs, use a linear gradient: `primary` (#FFC793) to `primary_container` (#FFA133). This creates a "glowing filament" effect.

 

---

 

## 3. Typography: Editorial Authority

 

We use a high-contrast pairing of **Space Grotesk** (Display/Headlines) for a technical, futuristic edge and **Inter** (Body) for maximum legibility during incident response.

 

| Level | Token | Font | Size | Character |

| :--- | :--- | :--- | :--- | :--- |

| **Display** | `display-lg` | Space Grotesk | 3.5rem | Bold, -0.02em tracking |

| **Headline** | `headline-lg` | Space Grotesk | 2.0rem | Medium, 0 tracking |

| **Title** | `title-lg` | Inter | 1.375rem | Semi-Bold |

| **Body** | `body-md` | Inter | 0.875rem | Regular, 1.5 line-height |

| **Label** | `label-sm` | Inter | 0.6875rem | All Caps, +0.05em tracking |

 

**The Editorial Twist:** Use `display-lg` for single-word statuses (e.g., "SECURE" or "THREAT") centered in the viewport with massive padding. This mimics the Sarvam AI "minimalist-bold" aesthetic.

 

---

 

## 4. Elevation & Depth: Tonal Layering

 

Traditional shadows are forbidden. We use **Ambient Radiance**.

 

1.  **The Layering Principle:** Place a `surface_container_high` element atop a `surface` background. The subtle 2-3% shift in luminosity provides all the "lift" required.

2.  **Ambient Shadows:** For floating modals, use a shadow with a 40px blur, 0px offset, and 6% opacity using the `primary` (#FFC793) color. This mimics a soft glow from a neon light source.

3.  **The "Ghost Border":** If a separation is required for accessibility, use the `outline_variant` (#544435) at **15% opacity**. It should be felt, not seen.

4.  **Glassmorphism:** All "above-surface" elements (modals, tooltips) should use a backdrop filter: `blur(12px) saturate(150%)`.

 

---

 

## 5. Components: The SecuX Primitives

 

### Buttons (The "Light-Cycles")

- **Primary:** Gradient from `primary` to `primary_container`. No border. Text color: `on_primary_fixed`.

- **Secondary:** Transparent background with a `Ghost Border` (15% opacity `outline`). On hover, the background fills to 5% `primary`.

- **Tertiary:** Text only in `secondary`. Underlined only on hover.

 

### Cards & Lists (The "Gridless" Items)

- **Rule:** Forbid divider lines. 

- **Application:** Separate list items using a 12px vertical gap. Use a `surface_container_low` background on hover to highlight the row.

- **Threat Cards:** Use a left-accented "glow bar" (2px wide) using the `error` (#FFB4AB) token to indicate high-priority alerts.

 

### Input Fields (The "Terminal" Style)

- **Style:** Bottom-border only (using `outline_variant` at 30%). 

- **Focus State:** The bottom border transforms into a 2px `primary` line with a subtle 4px outer glow.

- **Label:** `label-sm` floating above the input in `on_surface_variant`.

 

### SOC-Specific Components

- **The "Pulse" Indicator:** A small 8px circle using `tertiary`. Apply a recursive CSS animation that scales an outline from 100% to 300% at 0% opacity to simulate a radar pulse.

- **The Glow-Metric:** Large `display-md` numbers for "Threat Score" with a `surface_tint` drop shadow to make the data feel "active."

 

---

 

## 6. Do's and Don'ts

 

### Do

- **Do** use centered layouts for empty states and high-level overviews to mirror the Sarvam AI inspiration.

- **Do** use `primary_fixed_dim` for icons to give them a "dimmed LED" look.

- **Do** prioritize "Breathing Room." If a layout feels crowded, remove a component rather than shrinking the margins.

 

### Don't

- **Don't** use pure white (#FFFFFF). Use `on_surface` (#E5E2E1) for text to prevent eye strain in dark environments.

- **Don't** use 90-degree corners. Use the `md` (0.375rem) roundedness scale for a sophisticated, engineered feel.

- **Don't** use standard "Success Green." This system relies on `secondary` (Blue/Indigo) for "Safe" and `primary/tertiary` (Orange/Red) for "Action/Danger." 

 

### Accessibility Note

Ensure all text on `surface` containers maintains at least a 4.5:1 contrast ratio. When using Glassmorphism, ensure the `on_surface` text has a dark text-shadow (0px 2px 4px #000) to maintain legibility over moving background elements.