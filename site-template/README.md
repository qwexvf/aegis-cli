# Docs template

Astro 6 + React 19 + Tailwind v4 + shadcn docs template. Pagefind search, dark/light theme, sidebar nav from frontmatter, GitHub-style markdown alerts, copy-on-click code blocks, scroll-spy TOC.

## Stack

- Astro 6 (MPA, MDX)
- React 19 (interactive islands only — search, mobile sidebar, theme toggle)
- Tailwind v4 (`@tailwindcss/vite`)
- shadcn/ui + radix
- Pagefind (static-build full-text search)
- Shiki (`github-light` / `github-dark-dimmed`)
- `remark-github-blockquote-alert` for `> [!NOTE]` alerts
- `rehype-slug` + `rehype-autolink-headings`

## Getting started

```sh
bun install
bun dev          # http://localhost:4321
bun build        # outputs to ./dist + runs pagefind
bun preview
```

> Requires Node ≥ 22.12 (Astro 6).

## Project layout

```
src/
├── content/
│   └── docs/                   # markdown / mdx — collection defined in content.config.ts
├── components/                 # Header, Sidebar, Search, ThemeToggle, MobileSidebar, ui/*
├── layouts/
│   ├── BaseLayout.astro        # html shell, theme init, copy-button script
│   └── DocsLayout.astro        # sidebar + article + prev/next + TOC
├── lib/
│   └── nav.ts                  # buildNav() — section/order from frontmatter
├── pages/
│   ├── index.astro             # landing page
│   └── [...slug].astro         # renders every doc collection entry
└── styles/
    ├── globals.css             # tokens, theme vars, base
    └── prose.css               # `.prose-docs` typographic styles
```

## Adding a page

Drop a `.md` or `.mdx` file in `src/content/docs/`. Frontmatter:

```yaml
---
title: Page title
description: Short summary for SEO + page header.
sidebar:
  label: Optional sidebar label   # falls back to title
  order: 1                        # lower = higher in sidebar
  hidden: false                   # set true to omit from nav
---
```

Sections are derived from directory: top-level files → "Start here", `guides/*` → Guides, `reference/*` → Reference, `contributing/*` → Contributing. Edit `src/lib/nav.ts` to change sections.

## Customization checklist

Search-and-replace these placeholders for your project:

- `https://example.com` — `astro.config.mjs` (`site:`)
- `your-org/your-repo` — `Header.astro`, `DocsLayout.astro` (edit-on-GitHub link)
- `Docs` brand — `Header.astro`, `BaseLayout.astro` title suffix
- `Project` — `src/pages/index.astro`
- Logo SVG — `Header.astro`
- Theme tokens — `src/styles/globals.css` (`--color-signal`, `--color-bg`, etc.)
- `docs-theme` localStorage key — `BaseLayout.astro` (if you don't want it to clash with another app on the same domain)

## Deploying to a subpath

Set `PUBLIC_BASE` at build time:

```sh
PUBLIC_BASE=/my-docs/ bun build
```

`astro.config.mjs` already reads it.
