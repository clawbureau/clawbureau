import { printJson, printJsonError } from './json-output.js';
import { resolveRuntimeConfig, saveRuntimeConfig } from './runtime-config.js';

export interface ConfigSetOptions {
  key: string;
  value: string;
  json?: boolean;
  projectDir?: string;
}

export interface ConfigSetResult {
  status: 'ok' | 'error';
  key: string;
  value: string;
  configPath: string;
  error?: { code: string; message: string };
}

function parseBoolean(value: string): boolean | null {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  return null;
}

function emitError(jsonMode: boolean, code: string, message: string): void {
  if (jsonMode) {
    printJsonError({ code, message });
  } else {
    process.stderr.write(`Error: ${message}\n`);
  }
}

export async function runConfigSet(options: ConfigSetOptions): Promise<ConfigSetResult> {
  const jsonMode = !!options.json;
  const key = options.key.trim();
  const parsedValue = parseBoolean(options.value);

  if (key !== 'marketplace.enabled') {
    const code = 'CONFIG_KEY_UNSUPPORTED';
    const message =
      `Unsupported config key "${key}". ` +
      'Supported keys: marketplace.enabled';
    process.exitCode = 2;
    emitError(jsonMode, code, message);
    return {
      status: 'error',
      key,
      value: options.value,
      configPath: '',
      error: { code, message },
    };
  }

  if (parsedValue === null) {
    const code = 'CONFIG_VALUE_INVALID';
    const message =
      `Invalid value "${options.value}" for ${key}. ` +
      'Allowed values: true, false';
    process.exitCode = 2;
    emitError(jsonMode, code, message);
    return {
      status: 'error',
      key,
      value: options.value,
      configPath: '',
      error: { code, message },
    };
  }

  const config = await resolveRuntimeConfig(options.projectDir);
  config.marketplace.enabled = parsedValue;
  const configPath = await saveRuntimeConfig(config, options.projectDir);

  if (jsonMode) {
    printJson({
      status: 'ok',
      key,
      value: parsedValue,
      config_path: configPath,
    });
  } else {
    process.stdout.write(`Updated ${key}=${parsedValue}\n`);
    process.stdout.write(`  Config: ${configPath}\n`);
  }

  return {
    status: 'ok',
    key,
    value: String(parsedValue),
    configPath,
  };
}
