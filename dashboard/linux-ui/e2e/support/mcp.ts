import net from "node:net";

/**
 * Send a single control-API request to the daemon's UNIX control socket
 * and return the parsed response.
 * The daemon uses newline-delimited JSON framing.
 */
export function sendControlRequest(
  socketPath: string,
  request: unknown
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection({ path: socketPath }, () => {
      client.write(JSON.stringify(request) + "\n");
    });

    let buffer = "";
    client.setEncoding("utf8");

    client.on("data", (chunk: string) => {
      buffer += chunk;
      const newlineIdx = buffer.indexOf("\n");
      if (newlineIdx !== -1) {
        const line = buffer.slice(0, newlineIdx).trim();
        client.destroy();
        try {
          resolve(JSON.parse(line) as Record<string, unknown>);
        } catch (err) {
          reject(new Error(`Failed to parse daemon response: ${line}: ${err}`));
        }
      }
    });

    client.on("error", (err: Error) => reject(err));
    client.on("close", () => {
      if (buffer.trim()) {
        try {
          resolve(JSON.parse(buffer.trim()) as Record<string, unknown>);
        } catch {
          // already resolved or about to reject via error event
        }
      }
    });
  });
}
