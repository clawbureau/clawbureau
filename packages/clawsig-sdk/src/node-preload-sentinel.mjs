/**
 * Node.js Application-Layer FS + Net Sentinel
 *
 * Intercepts ALL fs reads/writes/deletes and net.Socket.connect natively inside V8.
 * Uses a pre-opened raw FD for trace output — completely bypasses our own hooks.
 * Propagates automatically to child Node processes via NODE_OPTIONS.
 *
 * Loaded via NODE_OPTIONS="--import /path/to/node-preload-sentinel.mjs"
 */

import fs from 'node:fs';
import net from 'node:net';
import cp from 'node:child_process';
import { fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// Trace output — raw fd, never triggers our hooks
// ---------------------------------------------------------------------------
const traceFile = process.env.CLAWSIG_TRACE_FILE;

// Capture ORIGINAL functions BEFORE patching anything
const origOpenSync = fs.openSync;
const origWriteSync = fs.writeSync;
const origCloseSync = fs.closeSync;

// Open trace fd using the originals (bypasses any existing patches)
let traceFd = null;
if (traceFile) {
  try { traceFd = origOpenSync(traceFile, 'a'); } catch { /* skip */ }
}

let inHook = false;

function emitLog(obj) {
  if (traceFd === null || inHook) return;
  inHook = true;
  try {
    const line = Buffer.from(
      JSON.stringify({ layer: 'interpose', ts: new Date().toISOString(), pid: process.pid, ...obj }) + '\n',
    );
    origWriteSync(traceFd, line);
  } catch { /* best effort */ }
  finally { inHook = false; }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------
function getPathStr(p) {
  if (p === null || p === undefined) return '';
  if (Buffer.isBuffer(p)) return p.toString('utf8');
  if (p instanceof URL) return p.pathname;
  return String(p);
}

function shouldLogFs(pathStr) {
  if (!pathStr) return false;
  if (pathStr.includes('node_modules') || pathStr.includes('.git/') ||
      pathStr.includes('__pycache__') || pathStr.includes('.clawsig')) return false;
  if (pathStr.startsWith('/dev/') || pathStr.startsWith('/proc/') || pathStr.startsWith('/sys/')) return false;
  if (traceFile && pathStr === traceFile) return false;
  return true;
}

// ---------------------------------------------------------------------------
// FD → path mapping (for read(fd) / write(fd) tracking)
// ---------------------------------------------------------------------------
const fdPaths = new Map();

// ---------------------------------------------------------------------------
// 1. File Operations — READS
// ---------------------------------------------------------------------------

// fs.readFile(path, [options,] callback)
const origReadFile = fs.readFile;
fs.readFile = function (path, ...rest) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) {
    emitLog({ syscall: 'readFile', path: pathStr, rc: 0 });
  }
  return origReadFile.apply(this, [path, ...rest]);
};

// fs.readFileSync(path, [options])
const origReadFileSync = fs.readFileSync;
fs.readFileSync = function (path, ...rest) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) {
    emitLog({ syscall: 'readFile', path: pathStr, rc: 0 });
  }
  return origReadFileSync.apply(this, [path, ...rest]);
};

// fs.promises.readFile
if (fs.promises?.readFile) {
  const origPReadFile = fs.promises.readFile;
  fs.promises.readFile = function (path, ...rest) {
    const pathStr = getPathStr(path);
    if (!inHook && shouldLogFs(pathStr)) {
      emitLog({ syscall: 'readFile', path: pathStr, rc: 0 });
    }
    return origPReadFile.apply(this, [path, ...rest]);
  };
}

// fs.createReadStream
const origCreateReadStream = fs.createReadStream;
fs.createReadStream = function (path, options) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) {
    emitLog({ syscall: 'createReadStream', path: pathStr, rc: 0 });
  }
  return origCreateReadStream.apply(this, arguments);
};

// fs.read(fd, ...) — low-level fd read
const origRead = fs.read;
fs.read = function (fd, ...rest) {
  if (!inHook) {
    const pathStr = fdPaths.get(fd);
    if (pathStr && shouldLogFs(pathStr)) {
      emitLog({ syscall: 'read', path: pathStr, rc: 0 });
    }
  }
  return origRead.apply(this, [fd, ...rest]);
};

// fs.readSync(fd, ...)
const origReadSync = fs.readSync;
fs.readSync = function (fd, ...rest) {
  if (!inHook) {
    const pathStr = fdPaths.get(fd);
    if (pathStr && shouldLogFs(pathStr)) {
      emitLog({ syscall: 'read', path: pathStr, rc: 0 });
    }
  }
  return origReadSync.apply(this, [fd, ...rest]);
};

// ---------------------------------------------------------------------------
// 2. File Operations — WRITES
// ---------------------------------------------------------------------------

// fs.writeFile
const origWriteFile = fs.writeFile;
fs.writeFile = function (path, ...rest) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) {
    emitLog({ syscall: 'writeFile', path: pathStr, rc: 0 });
  }
  return origWriteFile.apply(this, [path, ...rest]);
};

// fs.writeFileSync
const origWriteFileSync = fs.writeFileSync;
fs.writeFileSync = function (path, ...rest) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) {
    emitLog({ syscall: 'writeFile', path: pathStr, rc: 0 });
  }
  return origWriteFileSync.apply(this, [path, ...rest]);
};

// fs.appendFile
const origAppendFile = fs.appendFile;
fs.appendFile = function (path, ...rest) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) {
    emitLog({ syscall: 'appendFile', path: pathStr, rc: 0 });
  }
  return origAppendFile.apply(this, [path, ...rest]);
};

// fs.appendFileSync
const origAppendFileSync = fs.appendFileSync;
fs.appendFileSync = function (path, ...rest) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) {
    emitLog({ syscall: 'appendFile', path: pathStr, rc: 0 });
  }
  return origAppendFileSync.apply(this, [path, ...rest]);
};

// fs.promises.writeFile / appendFile
if (fs.promises?.writeFile) {
  const origPWriteFile = fs.promises.writeFile;
  fs.promises.writeFile = function (path, ...rest) {
    const pathStr = getPathStr(path);
    if (!inHook && shouldLogFs(pathStr)) {
      emitLog({ syscall: 'writeFile', path: pathStr, rc: 0 });
    }
    return origPWriteFile.apply(this, [path, ...rest]);
  };
}
if (fs.promises?.appendFile) {
  const origPAppendFile = fs.promises.appendFile;
  fs.promises.appendFile = function (path, ...rest) {
    const pathStr = getPathStr(path);
    if (!inHook && shouldLogFs(pathStr)) {
      emitLog({ syscall: 'appendFile', path: pathStr, rc: 0 });
    }
    return origPAppendFile.apply(this, [path, ...rest]);
  };
}

// fs.createWriteStream
const origCreateWriteStream = fs.createWriteStream;
fs.createWriteStream = function (path, options) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) {
    emitLog({ syscall: 'createWriteStream', path: pathStr, rc: 0 });
  }
  return origCreateWriteStream.apply(this, arguments);
};

// fs.write(fd, ...) / fs.writeSync(fd, ...)
const origFsWrite = fs.write;
fs.write = function (fd, ...rest) {
  if (!inHook) {
    const pathStr = fdPaths.get(fd);
    if (pathStr && shouldLogFs(pathStr)) {
      emitLog({ syscall: 'write', path: pathStr, rc: 0 });
    }
  }
  return origFsWrite.apply(this, [fd, ...rest]);
};

fs.writeSync = function (fd, ...rest) {
  if (!inHook) {
    const pathStr = fdPaths.get(fd);
    if (pathStr && shouldLogFs(pathStr)) {
      emitLog({ syscall: 'write', path: pathStr, rc: 0 });
    }
  }
  return origWriteSync.apply(this, [fd, ...rest]);
};

// fs.copyFile / copyFileSync
const origCopyFile = fs.copyFile;
fs.copyFile = function (src, dest, ...rest) {
  const srcStr = getPathStr(src);
  const destStr = getPathStr(dest);
  if (!inHook) {
    if (shouldLogFs(srcStr)) emitLog({ syscall: 'copyFile', path: srcStr, flags: 'read', rc: 0 });
    if (shouldLogFs(destStr)) emitLog({ syscall: 'copyFile', path: destStr, flags: 'write', rc: 0 });
  }
  return origCopyFile.apply(this, [src, dest, ...rest]);
};

const origCopyFileSync = fs.copyFileSync;
fs.copyFileSync = function (src, dest, ...rest) {
  const srcStr = getPathStr(src);
  const destStr = getPathStr(dest);
  if (!inHook) {
    if (shouldLogFs(srcStr)) emitLog({ syscall: 'copyFile', path: srcStr, flags: 'read', rc: 0 });
    if (shouldLogFs(destStr)) emitLog({ syscall: 'copyFile', path: destStr, flags: 'write', rc: 0 });
  }
  return origCopyFileSync.apply(this, [src, dest, ...rest]);
};

if (fs.promises?.copyFile) {
  const origPCopyFile = fs.promises.copyFile;
  fs.promises.copyFile = function (src, dest, ...rest) {
    const srcStr = getPathStr(src);
    const destStr = getPathStr(dest);
    if (!inHook) {
      if (shouldLogFs(srcStr)) emitLog({ syscall: 'copyFile', path: srcStr, flags: 'read', rc: 0 });
      if (shouldLogFs(destStr)) emitLog({ syscall: 'copyFile', path: destStr, flags: 'write', rc: 0 });
    }
    return origPCopyFile.apply(this, [src, dest, ...rest]);
  };
}

// ---------------------------------------------------------------------------
// 3. File Operations — DELETE / RENAME / MKDIR
// ---------------------------------------------------------------------------
const origUnlink = fs.unlink;
fs.unlink = function (path, ...rest) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) emitLog({ syscall: 'unlink', path: pathStr, rc: 0 });
  return origUnlink.apply(this, [path, ...rest]);
};

const origUnlinkSync = fs.unlinkSync;
fs.unlinkSync = function (path) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) emitLog({ syscall: 'unlink', path: pathStr, rc: 0 });
  return origUnlinkSync.apply(this, arguments);
};

const origRename = fs.rename;
fs.rename = function (oldPath, newPath, ...rest) {
  const oldStr = getPathStr(oldPath);
  const newStr = getPathStr(newPath);
  if (!inHook) {
    if (shouldLogFs(oldStr)) emitLog({ syscall: 'rename', path: oldStr, flags: newStr, rc: 0 });
  }
  return origRename.apply(this, [oldPath, newPath, ...rest]);
};

const origRenameSync = fs.renameSync;
fs.renameSync = function (oldPath, newPath) {
  const oldStr = getPathStr(oldPath);
  const newStr = getPathStr(newPath);
  if (!inHook) {
    if (shouldLogFs(oldStr)) emitLog({ syscall: 'rename', path: oldStr, flags: newStr, rc: 0 });
  }
  return origRenameSync.apply(this, arguments);
};

if (fs.promises?.unlink) {
  const origPUnlink = fs.promises.unlink;
  fs.promises.unlink = function (path) {
    const pathStr = getPathStr(path);
    if (!inHook && shouldLogFs(pathStr)) emitLog({ syscall: 'unlink', path: pathStr, rc: 0 });
    return origPUnlink.apply(this, arguments);
  };
}
if (fs.promises?.rename) {
  const origPRename = fs.promises.rename;
  fs.promises.rename = function (oldPath, newPath) {
    const oldStr = getPathStr(oldPath);
    if (!inHook && shouldLogFs(oldStr)) emitLog({ syscall: 'rename', path: oldStr, flags: getPathStr(newPath), rc: 0 });
    return origPRename.apply(this, arguments);
  };
}

// ---------------------------------------------------------------------------
// 4. open / close — FD tracking
// ---------------------------------------------------------------------------
fs.openSync = function (path, ...rest) {
  const pathStr = getPathStr(path);
  const fd = origOpenSync.apply(this, [path, ...rest]);
  if (shouldLogFs(pathStr)) {
    fdPaths.set(fd, pathStr);
    if (!inHook) emitLog({ syscall: 'open', path: pathStr, flags: String(rest[0] || 'r'), rc: fd });
  }
  return fd;
};

const origOpen = fs.open;
fs.open = function (path, flags, mode, callback) {
  const pathStr = getPathStr(path);
  if (!inHook && shouldLogFs(pathStr)) {
    emitLog({ syscall: 'open', path: pathStr, flags: String(flags), rc: 0 });
  }
  // Find the callback (last function argument)
  const args = Array.from(arguments);
  const cbIdx = args.findIndex((a, i) => i > 0 && typeof a === 'function');
  if (cbIdx !== -1) {
    const origCb = args[cbIdx];
    args[cbIdx] = function (err, fd) {
      if (!err && fd !== undefined && shouldLogFs(pathStr)) {
        fdPaths.set(fd, pathStr);
      }
      return origCb.apply(this, arguments);
    };
    return origOpen.apply(this, args);
  }
  return origOpen.apply(this, arguments);
};

if (fs.promises?.open) {
  const origPOpen = fs.promises.open;
  fs.promises.open = async function (path, ...rest) {
    const pathStr = getPathStr(path);
    if (!inHook && shouldLogFs(pathStr)) {
      emitLog({ syscall: 'open', path: pathStr, flags: rest[0] ? String(rest[0]) : 'r', rc: 0 });
    }
    const handle = await origPOpen.apply(this, [path, ...rest]);
    if (handle?.fd && shouldLogFs(pathStr)) {
      fdPaths.set(handle.fd, pathStr);
    }
    return handle;
  };
}

fs.closeSync = function (fd) {
  fdPaths.delete(fd);
  return origCloseSync.apply(this, arguments);
};

const origClose = fs.close;
fs.close = function (fd, ...rest) {
  fdPaths.delete(fd);
  return origClose.apply(this, [fd, ...rest]);
};

// ---------------------------------------------------------------------------
// 5. Network — Socket.connect
// ---------------------------------------------------------------------------
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  if (!inHook) {
    let port, host = 'localhost';
    if (args[0] !== null && typeof args[0] === 'object') {
      port = args[0].port;
      host = args[0].host || 'localhost';
    } else {
      port = args[0];
      if (typeof args[1] === 'string') host = args[1];
    }
    if (port && host && host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
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

// Bound fdPaths cleanup on exit
process.on('exit', () => { fdPaths.clear(); });
