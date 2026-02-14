/**
 * Node.js application-layer sentinel — fallback for DYLD_INSERT_LIBRARIES on macOS.
 * Patches net.Socket.connect, fs.open*, child_process.spawn to emit interpose-like events.
 * Loaded via NODE_OPTIONS="--import node-preload-sentinel.mjs"
 */
import fs from 'node:fs';
import net from 'node:net';
import cp from 'node:child_process';
import { fileURLToPath } from 'node:url';

const traceFile = process.env.CLAWSIG_TRACE_FILE;
let inHook = false;

function emitLog(obj) {
  if (inHook || !traceFile) return;
  inHook = true;
  try {
    const ts = new Date().toISOString();
    const line = JSON.stringify({ layer: 'interpose', ts, pid: process.pid, ...obj }) + '\n';
    fs.appendFileSync(traceFile, line, { encoding: 'utf8' });
  } catch {
    // Best effort
  } finally {
    inHook = false;
  }
}

// 1. Hook Outbound Sockets
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
  if (!inHook) {
    let port, host = 'localhost';
    if (args[0] !== null && typeof args[0] === 'object') {
      port = args[0].port;
      host = args[0].host || 'localhost';
    } else {
      port = args[0];
      if (typeof args[1] === 'string') host = args[1];
    }
    if (port && host && !host.includes('127.0.0.1') && host !== 'localhost' && host !== '::1') {
      emitLog({
        syscall: 'connect',
        addr: host,
        port: Number(port),
        family: net.isIPv6(host) ? 'AF_INET6' : 'AF_INET',
        rc: 0,
      });
    }
  }
  return origConnect.apply(this, args);
};

// 2. Hook File Operations
const origOpenSync = fs.openSync;
fs.openSync = function(path, flags, mode) {
  const rc = origOpenSync.apply(this, arguments);
  if (!inHook) {
    const pathStr = String(path);
    if (!pathStr.includes('node_modules') && !pathStr.includes('.clawsig')) {
      emitLog({ syscall: 'open', path: pathStr, flags: String(flags), rc });
    }
  }
  return rc;
};

const origOpen = fs.open;
fs.open = function(path, flags, mode, callback) {
  if (!inHook) {
    const pathStr = String(path);
    if (!pathStr.includes('node_modules') && !pathStr.includes('.clawsig')) {
      emitLog({ syscall: 'open', path: pathStr, flags: String(flags), rc: 0 });
    }
  }
  return origOpen.apply(this, arguments);
};

if (fs.promises?.open) {
  const origPromisesOpen = fs.promises.open;
  fs.promises.open = async function(path, ...args) {
    const rc = await origPromisesOpen.apply(this, [path, ...args]);
    if (!inHook) {
      const pathStr = String(path);
      if (!pathStr.includes('node_modules') && !pathStr.includes('.clawsig')) {
        emitLog({ syscall: 'open', path: pathStr, flags: args[0] ? String(args[0]) : 'r', rc: 0 });
      }
    }
    return rc;
  };
}

// 3. Hook Subprocess Spawns (and propagate NODE_OPTIONS)
function injectEnv(options) {
  const env = Object.assign({}, options?.env || process.env);
  let preloadPath;
  try {
    preloadPath = fileURLToPath(import.meta.url);
  } catch {
    preloadPath = import.meta.url;
    if (preloadPath.startsWith('file://')) preloadPath = fileURLToPath(preloadPath);
  }
  const myImport = `--import ${preloadPath}`;

  const currentOpts = env.NODE_OPTIONS || '';
  if (!currentOpts.includes(myImport)) {
    env.NODE_OPTIONS = currentOpts ? `${currentOpts} ${myImport}` : myImport;
  }
  if (!env.CLAWSIG_TRACE_FILE && traceFile) {
    env.CLAWSIG_TRACE_FILE = traceFile;
  }
  return env;
}

const origSpawn = cp.spawn;
cp.spawn = function(command, args, options) {
  let opts = options;
  let parsedArgs = args;
  if (!Array.isArray(args)) {
    opts = args;
    parsedArgs = [];
  }
  const newOpts = { ...opts, env: injectEnv(opts) };
  if (!inHook) {
    emitLog({ syscall: 'posix_spawn', path: String(command), argv: Array.isArray(parsedArgs) ? parsedArgs.map(String) : [], rc: 0 });
  }
  return origSpawn.call(this, command, parsedArgs, newOpts);
};

const origSpawnSync = cp.spawnSync;
cp.spawnSync = function(command, args, options) {
  let opts = options;
  let parsedArgs = args;
  if (!Array.isArray(args)) {
    opts = args;
    parsedArgs = [];
  }
  const newOpts = { ...opts, env: injectEnv(opts) };
  if (!inHook) {
    emitLog({ syscall: 'posix_spawn', path: String(command), argv: Array.isArray(parsedArgs) ? parsedArgs.map(String) : [], rc: 0 });
  }
  return origSpawnSync.call(this, command, parsedArgs, newOpts);
};
