/**
 * WXC CLI - TypeScript wrapper for the Windows eXecution Container
 */

// Legacy WxcExecutor (original implementation)
export { WxcExecutor, WxcExecutionOptions, WxcExecutionResult } from './wxc-executor';

export {
  createMinimalConfig,
  createNetworkRestrictedConfig,
  createFilesystemRestrictedConfig
} from './types';

