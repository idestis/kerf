// Astro + Starlight config for kerf docs.
// Mirrors the pattern in pipe's docs so the dev experience matches across
// personal projects. Sidebar lists only pages that actually exist — new
// sections get added here alongside the page that documents them.

import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import remarkGfm from "remark-gfm";

export default defineConfig({
  site: "https://idestis.github.io",
  base: "/kerf",
  // GFM (tables, strikethrough, autolinks) is not applied to .mdx content out
  // of the box here, so wire remark-gfm in explicitly — without it the pipe
  // tables across the docs render as raw `| … |` text.
  markdown: {
    remarkPlugins: [remarkGfm],
  },
  integrations: [
    starlight({
      title: "kerf",
      description:
        "Diff-aware, KMS-first encryption for structured secret files. Edit one secret, change one line of git diff.",
      logo: {
        light: "./src/assets/logo-light.svg",
        dark: "./src/assets/logo-dark.svg",
        replacesTitle: true,
      },
      favicon: "/favicon.svg",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/idestis/kerf",
        },
      ],
      editLink: {
        baseUrl: "https://github.com/idestis/kerf/edit/main/docs/",
      },
      lastUpdated: true,
      sidebar: [
        {
          label: "Get Started",
          items: [
            { slug: "getting-started/introduction" },
            { slug: "getting-started/installation" },
            { slug: "getting-started/quickstart" },
          ],
        },
        {
          label: "Concepts",
          items: [{ slug: "concepts/the-kerf-rule" }],
        },
        {
          label: "Key providers",
          items: [
            { slug: "key-providers/overview" },
            { slug: "key-providers/age" },
            { slug: "key-providers/aws-kms" },
            { slug: "key-providers/gcp-kms" },
            { slug: "key-providers/azure-key-vault" },
          ],
        },
        {
          label: "Reference",
          items: [
            { slug: "reference/cli" },
            {
              label: "Commands",
              items: [
                { slug: "reference/commands/encrypt-decrypt" },
                { slug: "reference/commands/edit-set" },
                { slug: "reference/commands/inspect" },
                { slug: "reference/commands/recipients-rotation" },
                { slug: "reference/commands/plumbing" },
              ],
            },
            { slug: "reference/exit-codes" },
          ],
        },
        {
          label: "Contributing",
          items: [
            { slug: "contributing/development" },
            { slug: "contributing/security" },
          ],
        },
      ],
      head: [
        {
          tag: "meta",
          attrs: { name: "theme-color", content: "#0a0f1a" },
        },
        {
          tag: "link",
          attrs: {
            rel: "icon",
            type: "image/png",
            sizes: "32x32",
            href: "/kerf/favicon-32x32.png",
          },
        },
        {
          tag: "link",
          attrs: {
            rel: "icon",
            type: "image/png",
            sizes: "64x64",
            href: "/kerf/favicon-64x64.png",
          },
        },
        {
          tag: "link",
          attrs: {
            rel: "apple-touch-icon",
            sizes: "256x256",
            href: "/kerf/apple-touch-icon.png",
          },
        },
        {
          tag: "meta",
          attrs: {
            property: "og:image",
            content: "https://idestis.github.io/kerf/og-image.png",
          },
        },
        {
          tag: "meta",
          attrs: {
            property: "og:image:alt",
            content: "kerf — diff-aware, KMS-first encryption for structured secret files",
          },
        },
      ],
    }),
  ],
});
