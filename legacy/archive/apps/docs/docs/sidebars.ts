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
      label: '攻防能力',
      items: ['attack-surfaces', 'scenarios', 'policies', 'reports']
    },
    {
      type: 'category',
      label: '接入与运行',
      items: ['openclaw', 'api', 'faq']
    }
  ]
};

export default sidebars;
