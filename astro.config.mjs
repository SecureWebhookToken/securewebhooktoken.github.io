import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import react from '@astrojs/react';

export default defineConfig({
  site: 'https://securewebhooktoken.github.io',
  outDir: './docs',
  integrations: [
    react(),
    starlight({
      title: 'Secure Webhook Token',
      logo: {
        src: './src/assets/swt-logo.svg',
        alt: 'SWT Logo',
      },
      defaultLocale: 'root',
      locales: {
        root: {
          label: 'English',
          lang: 'en',
        },
        de: {
          label: 'Deutsch',
          lang: 'de',
        },
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/SecureWebhookToken',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/SecureWebhookToken/securewebhooktoken.github.io/edit/main/',
      },
      customCss: ['./src/styles/custom.css'],
      head: [
        {
          tag: 'link',
          attrs: {
            rel: 'alternate',
            type: 'text/plain',
            href: '/llms.txt',
            title: 'LLM-friendly documentation',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'alternate',
            type: 'text/plain',
            href: '/llms-full.txt',
            title: 'Full LLM context bundle',
          },
        },
        {
          tag: 'script',
          attrs: {
            async: true,
            src: 'https://www.googletagmanager.com/gtag/js?id=G-NJ3XM81KF3',
          },
        },
        {
          tag: 'script',
          content: `
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', 'G-NJ3XM81KF3', { anonymize_ip: true });
          `,
        },
      ],
      sidebar: [
        {
          label: 'Interactive Tools',
          translations: { de: 'Interaktive Tools' },
          items: [
            {
              label: 'SWT Playground',
              slug: 'playground',
              badge: { text: 'Live', variant: 'tip' },
            },
          ],
        },
        {
          label: 'Specification',
          translations: { de: 'Spezifikation' },
          items: [
            {
              label: 'SWT Specification (Draft-03)',
              translations: { de: 'SWT Spezifikation (Draft-03)' },
              slug: 'docs/swt/specification',
            },
            {
              label: 'Security Guidelines',
              translations: { de: 'Sicherheitsrichtlinien' },
              slug: 'docs/swt/security',
            },
            {
              label: 'Error Handling',
              translations: { de: 'Fehlerbehandlung' },
              slug: 'docs/swt/error-handling',
            },
          ],
        },
        {
          label: 'Implementations',
          translations: { de: 'Implementierungen' },
          items: [
            {
              label: 'Quickstart (Go, JS, Python, cURL)',
              translations: { de: 'Schnellstart (Go, JS, Python, cURL)' },
              slug: 'docs/swt/implementations/quickstart',
            },
            {
              label: 'Go Reference Library (v0.5.0)',
              translations: { de: 'Go Referenzbibliothek (v0.5.0)' },
              items: [
                {
                  label: 'Client-side Token Generation',
                  translations: { de: 'Clientseitige Token-Generierung' },
                  slug: 'docs/swt/implementations/go/client',
                },
                {
                  label: 'Server-side Validation & Middleware',
                  translations: { de: 'Serverseitige Validierung & Middleware' },
                  slug: 'docs/swt/implementations/go/server',
                },
                {
                  label: 'Replay Protection',
                  translations: { de: 'Replay-Schutz' },
                  slug: 'docs/swt/implementations/go/replay-protection',
                },
              ],
            },
            {
              label: 'JavaScript / Node.js',
              items: [
                {
                  label: 'Client-side Token Generation',
                  translations: { de: 'Clientseitige Token-Generierung' },
                  slug: 'docs/swt/implementations/js/client',
                },
                {
                  label: 'Server-side Validation',
                  translations: { de: 'Serverseitige Validierung' },
                  slug: 'docs/swt/implementations/js/server',
                },
                {
                  label: 'Webhook Handler & Replay',
                  translations: { de: 'Webhook-Handler & Replay-Schutz' },
                  slug: 'docs/swt/implementations/js/webhook-handler',
                },
              ],
            },
            {
              label: 'Python',
              items: [
                {
                  label: 'Create & Validate SWT',
                  translations: { de: 'SWT erstellen & validieren' },
                  slug: 'docs/swt/implementations/python/create-validate',
                },
              ],
            },
          ],
        },
        {
          label: 'Legal',
          translations: { de: 'Rechtliches' },
          items: [
            {
              label: 'Privacy Policy',
              translations: { de: 'Datenschutz' },
              slug: 'privacy',
            },
          ],
        },
      ],
    }),
  ],
});
