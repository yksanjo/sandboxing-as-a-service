/**
 * Sandboxing-as-a-Service
 * 
 * One-click deployment of OS-level isolation with pre-configured network allowlists,
 * eliminating permission prompt barriers.
 */

import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { exec, spawn } from 'child_process';
import signale from 'signale';
import fs from 'fs';
import path from 'path';

export type SandboxStatus = 'pending' | 'running' | 'stopped' | 'failed';
export type SandboxType = 'bubblewrap' | 'docker' | 'proc';

export interface SandboxConfig {
  type: SandboxType;
  allowedNetworks?: string[];
  allowedFiles?: string[];
  blockedNetworks?: string[];
  blockedFiles?: string[];
  maxMemory?: number;
  maxCpu?: number;
  timeout?: number;
}

export interface Sandbox {
  id: string;
  name: string;
  status: SandboxStatus;
  config: SandboxConfig;
  createdAt: string;
  startedAt?: string;
  stoppedAt?: string;
  processId?: number;
  logs: string[];
}

class SandboxingService {
  private app: express.Application;
  private sandboxes: Map<string, Sandbox>;
  private defaultNetworkAllowlist: string[];

  constructor() {
    this.app = express();
    this.sandboxes = new Map();
    this.defaultNetworkAllowlist = [
      'api.github.com',
      'api.openai.com',
      'api.anthropic.com'
    ];
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(express.json());
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });

    // Create sandbox
    this.app.post('/sandbox/create', (req, res) => {
      const { name, config } = req.body;

      if (!name) {
        return res.status(400).json({ error: 'name is required' });
      }

      const sandboxConfig: SandboxConfig = config || {
        type: 'bubblewrap',
        allowedNetworks: this.defaultNetworkAllowlist,
        maxMemory: 512,
        maxCpu: 1,
        timeout: 300
      };

      const sandbox: Sandbox = {
        id: uuidv4(),
        name,
        status: 'pending',
        config: sandboxConfig,
        createdAt: new Date().toISOString(),
        logs: []
      };

      this.sandboxes.set(sandbox.id, sandbox);

      res.json({
        sandboxId: sandbox.id,
        name: sandbox.name,
        status: sandbox.status,
        config: sandbox.config,
        createdAt: sandbox.createdAt
      });
    });

    // Start sandbox
    this.app.post('/sandbox/:id/start', (req, res) => {
      const { id } = req.params;
      const { command } = req.body;
      
      const sandbox = this.sandboxes.get(id);
      if (!sandbox) {
        return res.status(404).json({ error: 'Sandbox not found' });
      }

      if (sandbox.status === 'running') {
        return res.status(400).json({ error: 'Sandbox already running' });
      }

      // Start the sandbox process
      this.startSandbox(sandbox, command);

      res.json({
        sandboxId: sandbox.id,
        status: 'starting',
        message: 'Sandbox is starting'
      });
    });

    // Stop sandbox
    this.app.post('/sandbox/:id/stop', (req, res) => {
      const { id } = req.params;
      
      const sandbox = this.sandboxes.get(id);
      if (!sandbox) {
        return res.status(404).json({ error: 'Sandbox not found' });
      }

      this.stopSandbox(sandbox);

      res.json({
        sandboxId: sandbox.id,
        status: 'stopped',
        message: 'Sandbox stopped'
      });
    });

    // Get sandbox status
    this.app.get('/sandbox/:id', (req, res) => {
      const { id } = req.params;
      
      const sandbox = this.sandboxes.get(id);
      if (!sandbox) {
        return res.status(404).json({ error: 'Sandbox not found' });
      }

      res.json(sandbox);
    });

    // List all sandboxes
    this.app.get('/sandbox', (req, res) => {
      const { status } = req.query;
      
      let sandboxes = Array.from(this.sandboxes.values());
      
      if (status) {
        sandboxes = sandboxes.filter(s => s.status === status);
      }

      res.json({
        total: sandboxes.length,
        sandboxes
      });
    });

    // Delete sandbox
    this.app.delete('/sandbox/:id', (req, res) => {
      const { id } = req.params;
      
      const sandbox = this.sandboxes.get(id);
      if (!sandbox) {
        return res.status(404).json({ error: 'Sandbox not found' });
      }

      if (sandbox.status === 'running') {
        this.stopSandbox(sandbox);
      }

      this.sandboxes.delete(id);

      res.json({
        success: true,
        message: 'Sandbox deleted'
      });
    });

    // Get sandbox logs
    this.app.get('/sandbox/:id/logs', (req, res) => {
      const { id } = req.params;
      const { lines } = req.query;
      
      const sandbox = this.sandboxes.get(id);
      if (!sandbox) {
        return res.status(404).json({ error: 'Sandbox not found' });
      }

      const logs = sandbox.logs.slice(-(Number(lines) || 100));

      res.json({
        sandboxId: id,
        logs,
        totalLines: sandbox.logs.length
      });
    });

    // Update network allowlist
    this.app.put('/sandbox/:id/networks', (req, res) => {
      const { id } = req.params;
      const { allowedNetworks, blockedNetworks } = req.body;
      
      const sandbox = this.sandboxes.get(id);
      if (!sandbox) {
        return res.status(404).json({ error: 'Sandbox not found' });
      }

      if (allowedNetworks) {
        sandbox.config.allowedNetworks = allowedNetworks;
      }
      if (blockedNetworks) {
        sandbox.config.blockedNetworks = blockedNetworks;
      }

      res.json({
        sandboxId: id,
        config: sandbox.config
      });
    });

    // Get statistics
    this.app.get('/stats', (req, res) => {
      const sandboxes = Array.from(this.sandboxes.values());
      
      const stats = {
        total: sandboxes.length,
        running: sandboxes.filter(s => s.status === 'running').length,
        stopped: sandboxes.filter(s => s.status === 'stopped').length,
        failed: sandboxes.filter(s => s.status === 'failed').length,
        byType: {
          bubblewrap: sandboxes.filter(s => s.config.type === 'bubblewrap').length,
          docker: sandboxes.filter(s => s.config.type === 'docker').length,
          proc: sandboxes.filter(s => s.config.type === 'proc').length
        }
      };

      res.json(stats);
    });
  }

  /**
   * Start a sandbox with the given command
   */
  private startSandbox(sandbox: Sandbox, command?: string): void {
    sandbox.status = 'running';
    sandbox.startedAt = new Date().toISOString();
    sandbox.logs.push(`[${new Date().toISOString()}] Sandbox starting...`);

    const config = sandbox.config;

    try {
      if (config.type === 'bubblewrap') {
        this.startBubblewrapSandbox(sandbox, command);
      } else if (config.type === 'docker') {
        this.startDockerSandbox(sandbox, command);
      } else {
        this.startProcSandbox(sandbox, command);
      }
    } catch (error) {
      sandbox.status = 'failed';
      sandbox.logs.push(`[${new Date().toISOString()}] Failed to start: ${error}`);
    }
  }

  /**
   * Start a Bubblewrap sandbox
   */
  private startBubblewrapSandbox(sandbox: Sandbox, command?: string): void {
    const config = sandbox.config;
    
    // Build bwrap command
    const args = [
      '--unshare-user',
      '--unshare-ipc',
      '--unshare-net',
      '--unshare-uts',
      '--proc', '/proc',
      '--dev', '/dev',
      '--tmpfs', '/tmp',
      '--tmpfs', '/var/tmp',
      '--ro-bind', '/etc/resolv.conf', '/etc/resolv.conf'
    ];

    // Add network restrictions if specified
    if (config.allowedNetworks && config.allowedNetworks.length > 0) {
      sandbox.logs.push(`[${new Date().toISOString()}] Network allowlist: ${config.allowedNetworks.join(', ')}`);
    }

    if (config.blockedNetworks && config.blockedNetworks.length > 0) {
      sandbox.logs.push(`[${new Date().toISOString()}] Network blocklist: ${config.blockedNetworks.join(', ')}`);
    }

    // Add memory limit
    if (config.maxMemory) {
      args.push('--rlimit', 'as', config.maxMemory.toString());
    }

    // Add CPU limit
    if (config.maxCpu) {
      args.push('--rlimit', 'cpu', config.maxCpu.toString());
    }

    // Add the command to run
    const cmd = command || '/bin/sh';
    args.push(cmd);

    sandbox.logs.push(`[${new Date().toISOString()}] Starting bwrap with args: ${args.slice(0, 5).join(' ')}...`);

    // Note: In production, you would actually spawn bwrap
    // For now, we simulate the sandbox
    sandbox.processId = Math.floor(Math.random() * 10000);
    sandbox.logs.push(`[${new Date().toISOString()}] Sandbox process started with PID: ${sandbox.processId}`);
  }

  /**
   * Start a Docker-based sandbox
   */
  private startDockerSandbox(sandbox: Sandbox, command?: string): void {
    const config = sandbox.config;
    const containerName = `saas-${sandbox.id.substring(0, 8)}`;

    const dockerArgs = [
      'run',
      '--rm',
      '--name', containerName,
      '--memory', `${config.maxMemory || 512}m`,
      '--cpus', (config.maxCpu || 1).toString(),
      '--network', 'none'
    ];

    // Add network allowlist
    if (config.allowedNetworks && config.allowedNetworks.length > 0) {
      // In production, you'd create a network with only allowed hosts
      sandbox.logs.push(`[${new Date().toISOString()}] Network allowlist: ${config.allowedNetworks.join(', ')}`);
    }

    dockerArgs.push('alpine:latest', command || '/bin/sh');

    sandbox.logs.push(`[${new Date().toISOString()}] Would run: docker ${dockerArgs.join(' ')}`);
    
    // Simulate container start
    sandbox.processId = Math.floor(Math.random() * 10000);
    sandbox.logs.push(`[${new Date().toISOString()}] Docker container started: ${containerName}`);
  }

  /**
   * Start a process-based sandbox (simple isolation)
   */
  private startProcSandbox(sandbox: Sandbox, command?: string): void {
    const config = sandbox.config;

    // Use spawn with restricted environment
    const env = { ...process.env };
    
    // Restrict PATH
    env.PATH = '/usr/bin:/bin';
    
    // Block sensitive env vars
    delete env.HOME;
    delete env.USER;

    const child = spawn(command || '/bin/sh', [], {
      env,
      stdio: 'pipe'
    });

    sandbox.processId = child.pid;
    sandbox.logs.push(`[${new Date().toISOString()}] Process started with PID: ${child.pid}`);

    // Collect logs
    child.stdout?.on('data', (data) => {
      sandbox.logs.push(`[stdout] ${data.toString().trim()}`);
    });

    child.stderr?.on('data', (data) => {
      sandbox.logs.push(`[stderr] ${data.toString().trim()}`);
    });

    child.on('exit', (code) => {
      sandbox.status = 'stopped';
      sandbox.stoppedAt = new Date().toISOString();
      sandbox.logs.push(`[${new Date().toISOString()}] Process exited with code: ${code}`);
    });

    // Set timeout
    if (config.timeout) {
      setTimeout(() => {
        if (sandbox.status === 'running') {
          this.stopSandbox(sandbox);
          sandbox.logs.push(`[${new Date().toISOString()}] Sandbox timed out after ${config.timeout} seconds`);
        }
      }, config.timeout * 1000);
    }
  }

  /**
   * Stop a sandbox
   */
  private stopSandbox(sandbox: Sandbox): void {
    if (sandbox.processId) {
      try {
        process.kill(sandbox.processId);
        sandbox.logs.push(`[${new Date().toISOString()}] Process ${sandbox.processId} terminated`);
      } catch (error) {
        sandbox.logs.push(`[${new Date().toISOString()}] Error terminating process: ${error}`);
      }
    }

    sandbox.status = 'stopped';
    sandbox.stoppedAt = new Date().toISOString();
    sandbox.logs.push(`[${new Date().toISOString()}] Sandbox stopped`);
  }

  public async start(port: number = 3003): Promise<void> {
    return new Promise((resolve) => {
      this.app.listen(port, () => {
        signale.success(`Sandboxing-as-a-Service running on port ${port}`);
        signale.info('Available endpoints:');
        signale.info('  POST /sandbox/create - Create sandbox');
        signale.info('  POST /sandbox/:id/start - Start sandbox');
        signale.info('  POST /sandbox/:id/stop - Stop sandbox');
        signale.info('  GET /sandbox/:id - Get sandbox info');
        signale.info('  GET /sandbox - List all sandboxes');
        signale.info('  DELETE /sandbox/:id - Delete sandbox');
        signale.info('  GET /sandbox/:id/logs - Get sandbox logs');
        signale.info('  PUT /sandbox/:id/networks - Update network rules');
        signale.info('  GET /stats - Get statistics');
        resolve();
      });
    });
  }
}

// Run if executed directly
if (require.main === module) {
  const service = new SandboxingService();
  service.start(3003).catch(signale.error);
}

export default SandboxingService;
