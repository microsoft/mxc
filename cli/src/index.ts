/**
 * WXC CLI - TypeScript wrapper for the Windows eXecution Container
 */

// Legacy ContainerExecutor (original implementation)
export { ContainerExecutor, ContainerExecutionOptions, ContainerExecutionResult } from './wxc-executor';

export {
  createMinimalConfig,
  createNetworkRestrictedConfig,
  createFilesystemRestrictedConfig
} from './types';

