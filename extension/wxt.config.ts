import { defineConfig } from 'wxt'

export default defineConfig({
  manifest: {
    name: 'X-Ray',
    description: 'AI-Assisted Browser Security Extension',
    version: '1.0.0',
    permissions: [
      'activeTab',
      'scripting',
      'storage',
      'tabs',
      'debugger',
      'declarativeNetRequest',
      'declarativeNetRequestFeedback',
    ],
    host_permissions: ['<all_urls>'],
  },
})
