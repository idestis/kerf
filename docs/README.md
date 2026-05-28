# kerf docs

Astro Starlight site. Published to https://idestis.github.io/kerf via GitHub Pages on every push to `main` that touches `docs/**`.

## Local

```bash
cd docs
npm install
npm run dev     # http://localhost:4321/kerf/
```

Or from the repo root:

```bash
task docs:install
task docs:dev
```

## Build

```bash
npm run build   # outputs ./dist
npm run preview # serves the built site locally
```

## Content layout

```
src/content/docs/
├── index.mdx                       # landing
├── getting-started/                # install, quickstart
├── concepts/                       # the kerf rule, threat model, format
├── guides/                         # one per workflow (KMS, age, edit, exec, …)
├── reference/                      # CLI, exit codes, configuration
└── contributing/                   # dev workflow, security policy
```

All pages are hand-authored MDX. The sidebar order is defined explicitly in `astro.config.mjs` — not auto-generated — so reordering or adding pages requires editing both the file and the config.

## Adding a page

1. Drop an `.mdx` file under the appropriate directory.
2. Add a `{ slug: "section/page-name" }` entry to the sidebar in `astro.config.mjs`.
3. Each MDX file needs a frontmatter block with `title` and (optionally) `description`.

## Honest scope right now

kerf is pre-alpha. Pages that describe unimplemented features carry a `WIP` callout at the top. As features land, the callout comes off and detail gets filled in. Reference pages for stubbed CLI commands stay deliberately thin until the implementation is real — don't pre-document flags that don't exist.
