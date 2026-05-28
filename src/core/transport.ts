import { spawn } from 'node:child_process';

/**
 * Pluggable HTTP transport. Defaults to global `fetch` (Node/Bun), but can
 * shell out to `curl_chrome123` (curl-impersonate-chrome) when
 * `LINKEDIN_HTTP=curl-impersonate` is set. That binary sends a TLS ClientHello
 * that matches real Chrome — LinkedIn's anti-abuse gates on JA3, so this is
 * what gets us past the redirect-loop / 403 wall on Voyager calls.
 */

export interface HttpResponse {
  status: number;
  headers: Headers;
  text(): Promise<string>;
}

export type HttpRequestInit = {
  method: string;
  headers: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
};

function useCurlImpersonate(): boolean {
  return (
    process.env.LINKEDIN_HTTP === 'curl-impersonate' ||
    process.env.LINKEDIN_USE_CURL_IMPERSONATE === '1'
  );
}

export async function httpRequest(url: string, init: HttpRequestInit): Promise<HttpResponse> {
  if (useCurlImpersonate()) {
    return curlImpersonateRequest(url, init);
  }
  const res = await fetch(url, init as RequestInit);
  return res;
}

const CURL_BIN = process.env.LINKEDIN_CURL_IMPERSONATE_BIN ?? 'curl_chrome123';

function curlImpersonateRequest(url: string, init: HttpRequestInit): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const args: string[] = [
      '-sS',
      '-i', // include response headers in output
      '--compressed',
      '-X',
      init.method,
      '--max-time',
      '30',
    ];
    for (const [name, value] of Object.entries(init.headers)) {
      // curl-impersonate already sets sec-ch-ua, user-agent, sec-fetch-*, etc.
      // Skip any we redundantly set so we don't override the Chrome-matching
      // values it provides.
      if (
        name.toLowerCase() === 'user-agent' ||
        name.toLowerCase().startsWith('sec-') ||
        name.toLowerCase() === 'accept-encoding' ||
        name.toLowerCase() === 'accept-language' ||
        name.toLowerCase() === 'upgrade-insecure-requests'
      ) {
        continue;
      }
      args.push('-H', `${name}: ${value}`);
    }
    if (init.body !== undefined) {
      args.push('--data-binary', '@-');
    }
    args.push(url);

    const child = spawn(CURL_BIN, args, { stdio: ['pipe', 'pipe', 'pipe'] });

    const onAbort = () => child.kill('SIGTERM');
    init.signal?.addEventListener('abort', onAbort);

    const chunks: Buffer[] = [];
    let stderr = '';
    child.stdout.on('data', (d) => chunks.push(d));
    child.stderr.on('data', (d) => (stderr += d.toString()));

    child.on('error', (err) => {
      init.signal?.removeEventListener('abort', onAbort);
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        reject(
          new Error(
            `curl-impersonate binary "${CURL_BIN}" not found in PATH. Install it: \`nix profile install nixpkgs#curl-impersonate-chrome\` or set LINKEDIN_CURL_IMPERSONATE_BIN.`,
          ),
        );
      } else {
        reject(err);
      }
    });

    child.on('close', (code) => {
      init.signal?.removeEventListener('abort', onAbort);
      if (code !== 0) {
        reject(new Error(`${CURL_BIN} exited ${code}: ${stderr.trim()}`));
        return;
      }
      try {
        const parsed = parseRawHttpResponse(Buffer.concat(chunks));
        if (process.env.LINKEDIN_DEBUG === '1') {
          process.stderr.write(
            `[transport] ${init.method} ${url} -> ${parsed.status} location=${parsed.headers.get('location') ?? '-'}\n`,
          );
        }
        resolve(parsed);
      } catch (err) {
        reject(err);
      }
    });

    if (init.body !== undefined) {
      child.stdin.write(init.body);
    }
    child.stdin.end();
  });
}

function parseRawHttpResponse(raw: Buffer): HttpResponse {
  // curl -i includes one or more header blocks (one per redirect) then the body.
  // Take the last header block.
  let working = raw;
  let lastHeadersEnd = -1;
  let lastHeadersStart = 0;
  while (true) {
    const idx = working.indexOf('\r\n\r\n', lastHeadersStart);
    if (idx === -1) break;
    // If what follows is another HTTP status line, this was an intermediate response.
    const next = working.subarray(idx + 4);
    if (next.subarray(0, 5).toString('utf8') === 'HTTP/') {
      lastHeadersStart = idx + 4;
      continue;
    }
    lastHeadersEnd = idx;
    break;
  }
  if (lastHeadersEnd === -1) {
    throw new Error('Could not parse curl-impersonate response');
  }

  const headerBlock = working.subarray(lastHeadersStart, lastHeadersEnd).toString('utf8');
  const body = working.subarray(lastHeadersEnd + 4);

  const lines = headerBlock.split(/\r\n/);
  const statusLine = lines.shift() ?? '';
  const statusMatch = statusLine.match(/^HTTP\/[\d.]+\s+(\d+)/);
  const status = statusMatch ? Number(statusMatch[1]) : 0;

  const headers = new Headers();
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    if (name) headers.append(name, value);
  }

  return {
    status,
    headers,
    async text() {
      return body.toString('utf8');
    },
  };
}
