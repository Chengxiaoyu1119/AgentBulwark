import type { Config } from '@docusaurus/types';
import type { Preset } from '@docusaurus/preset-classic';

const siteUrl =
  process.env.AGENT_SUPERVISOR_DOCS_SITE_URL ??
  'http://127.0.0.1:3000';
const wwwUrl =
  process.env.AGENT_SUPERVISOR_WWW_URL ??
  'http://127.0.0.1:4321';
const consoleUrl =
  process.env.AGENT_SUPERVISOR_CONSOLE_URL ??
  'http://127.0.0.1:5178';

const config: Config = {
  title: 'AgentBulwark · 智垒',
  tagline: 'AI Agent 防火墙：请求、上下文、输出与工具行动的运行时边界',
  favicon: 'img/favicon.png',
  url: siteUrl,
  baseUrl: '/',
  organizationName: 'Chengxiaoyu1119',
  projectName: 'AgentBulwark',
  scripts: [{ src: '/js/silence-react-devtools-prompt.js', async: false }],
  onBrokenLinks: 'throw',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn'
    }
  },
  i18n: {
    defaultLocale: 'zh-CN',
    locales: ['zh-CN']
  },
  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          routeBasePath: '/',
          editUrl: undefined
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css'
        }
      } satisfies Preset.Options
    ]
  ],
  themeConfig: {
    image: 'img/favicon.png',
    navbar: {
      title: 'AgentBulwark · 智垒',
      logo: {
        alt: 'AgentBulwark 智垒',
        src: 'img/favicon.png'
      },
      items: [
        { type: 'docSidebar', sidebarId: 'mainSidebar', position: 'left', label: '文档' },
        { to: '/quickstart', label: '快速开始', position: 'left' },
        { href: wwwUrl, label: '官网', position: 'right' },
        { href: consoleUrl, label: '控制台', position: 'right' },
        {
          href: 'https://github.com/Chengxiaoyu1119/AgentBulwark',
          label: 'GitHub',
          position: 'right',
          className: 'header-github-link',
          'aria-label': 'GitHub 仓库'
        }
      ]
    },
    footer: {
      style: 'light',
      copyright: `Copyright © ${new Date().getFullYear()} AgentBulwark.`
    },
    prism: {
      additionalLanguages: ['powershell', 'bash', 'json']
    }
  } satisfies Preset.ThemeConfig
};

export default config;
