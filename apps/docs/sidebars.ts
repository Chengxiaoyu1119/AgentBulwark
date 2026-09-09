import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  mainSidebar: [
    {
      type: 'category',
      label: '入门',
      items: ['intro', 'quickstart', 'architecture']
    },
    {
      type: 'category',
      label: '防护能力',
      items: ['attack-surfaces', 'scenarios', 'policies', 'reports']
    },
    {
      type: 'category',
      label: '接入与运行',
      items: ['api', 'faq']
    }
  ]
};

export default sidebars;
