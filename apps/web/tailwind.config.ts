import type { Config } from 'tailwindcss';
import uiPreset from '@worldlibertyfinancial/agent-ui/tailwind';

const config: Config = {
  presets: [uiPreset as Config],
  content: ['./src/**/*.{ts,tsx}', '../../packages/ui/src/**/*.{ts,tsx}']
};

export default config;
