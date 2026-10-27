// @ts-check
import {themes as prismThemes} from 'prism-react-renderer';
import { remarkAlert } from 'remark-github-blockquote-alert';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'MethodMan',
  tagline: 'Trilingual HTB/OSCP walkthroughs, web security reference and pentest tooling',
  favicon: 'img/favicon.ico',

  future: { v4: true },

  url: 'https://methodman.pages.dev',
  baseUrl: '/',

  organizationName: 'N3xu666',
  projectName: 'MethodMan',

  onBrokenLinks: 'warn',
  onBrokenAnchors: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    format: 'detect',
  },

  presets: [
    [
      'classic',
      ({
        docs: {
          sidebarPath: './sidebars.js',
          remarkPlugins: [remarkAlert],
          routeBasePath: 'writeups',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig: {
    image: 'img/docusaurus-social-card.jpg',
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    navbar: {
      title: 'MethodMan',
      logo: {
        alt: 'MethodMan',
        src: 'img/logo.svg',
      },
      items: [
        { to: '/', label: 'Graph', position: 'left' },
        { to: '/writeups', label: 'Writeups', position: 'left' },
        { href: 'https://github.com/N3xu666/MethodMan', label: 'GitHub', position: 'right' },
      ],
    },
    footer: {
      style: 'dark',
      links: [],
      copyright: `MethodMan - CC BY-NC 4.0 | Built with Docusaurus`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  },
};

export default config;