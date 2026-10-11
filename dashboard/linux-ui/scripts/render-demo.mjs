import { createReadStream } from "node:fs";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { bundle } from "@remotion/bundler";
import { ensureBrowser, renderMedia, renderStill, selectComposition } from "@remotion/renderer";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dashboardDir = path.resolve(__dirname, "..");
const artifactDir = process.env.MERCURY_E2E_DEMO_ARTIFACT_DIR;

if (!artifactDir) {
  throw new Error("missing MERCURY_E2E_DEMO_ARTIFACT_DIR");
}

const manifestPath = path.join(artifactDir, "manifest.json");
const remotionEntry = path.join(dashboardDir, "remotion", "index.ts");
const SCENARIO_INTRO_FRAMES = 54;
const OVERVIEW_INTRO_FRAMES = 30;

function log(message) {
  process.stdout.write(`${message}\n`);
}

async function startArtifactServer(rootDir) {
  const server = createServer(async (req, res) => {
    try {
      const requestPath = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      const resolved = path.resolve(rootDir, `.${decodeURIComponent(requestPath)}`);
      if (!resolved.startsWith(rootDir)) {
        res.writeHead(403).end("forbidden");
        return;
      }

      const fileStat = await stat(resolved);
      if (!fileStat.isFile()) {
        res.writeHead(404).end("not found");
        return;
      }

      res.writeHead(200, {
        "Content-Length": fileStat.size,
        "Content-Type": guessContentType(resolved),
        "Cache-Control": "no-store"
      });
      createReadStream(resolved).pipe(res);
    } catch {
      res.writeHead(404).end("not found");
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("failed to bind artifact server");
  }

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: async () =>
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      })
  };
}

function guessContentType(file) {
  if (file.endsWith(".webm")) {
    return "video/webm";
  }
  if (file.endsWith(".mp4")) {
    return "video/mp4";
  }
  if (file.endsWith(".png")) {
    return "image/png";
  }
  if (file.endsWith(".json")) {
    return "application/json";
  }
  return "application/octet-stream";
}

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (!Array.isArray(manifest.scenarios) || manifest.scenarios.length === 0) {
  throw new Error(`no captured scenarios found in ${manifestPath}`);
}

await mkdir(path.join(artifactDir, "rendered"), { recursive: true });

await ensureBrowser({ logLevel: "warn" });

const assetServer = await startArtifactServer(artifactDir);

try {
  log("Bundling Remotion project...");
  const serveUrl = await bundle({
    entryPoint: remotionEntry,
    onProgress: () => undefined,
    ignoreRegisterRootWarning: true
  });

  for (const entry of manifest.scenarios) {
    const transcript = JSON.parse(await readFile(entry.transcriptPath, "utf8"));
    const inputEntry = {
      ...entry,
      introDurationInFrames: Math.max(entry.introDurationInFrames, SCENARIO_INTRO_FRAMES),
      rawVideoPublicPath: `${assetServer.baseUrl}/raw-videos/${entry.id}.webm`
    };
    const inputProps = { entry: inputEntry, transcript };
    const composition = await selectComposition({
      serveUrl,
      id: "mercury-demo-scenario",
      inputProps,
      logLevel: "warn"
    });

    const outputName = `${entry.id}.mp4`;
    const posterName = `${entry.id}.png`;
    const renderedMp4Path = path.join(artifactDir, "rendered", outputName);
    const renderedPosterPath = path.join(artifactDir, "rendered", posterName);

    log(`Rendering ${entry.id} -> ${outputName}`);
    await renderMedia({
      serveUrl,
      composition,
      inputProps,
      codec: "h264",
      outputLocation: renderedMp4Path,
      overwrite: true,
      logLevel: "warn"
    });
    await renderStill({
      serveUrl,
      composition,
      inputProps,
      output: renderedPosterPath,
      overwrite: true,
      logLevel: "warn",
      frame: Math.min(entry.posterFrame, composition.durationInFrames - 1)
    });

    entry.renderedMp4Path = renderedMp4Path;
    entry.renderedPosterPath = renderedPosterPath;
    entry.renderedVideoPublicPath = `/rendered/${outputName}`;
    entry.renderedPosterPublicPath = `/rendered/${posterName}`;
    entry.renderedVideoName = outputName;
    entry.renderedPosterName = posterName;
    entry.rawVideoSidecarName = `${entry.id}.webm`;
  }

  const overviewEntries = manifest.scenarios
    .filter((entry) => entry.includeInOverview)
    .map((entry) => ({
      id: entry.id,
      title: entry.title,
      summary: entry.summary,
      resultLabel: entry.resultLabel,
      rawVideoPublicPath: `${assetServer.baseUrl}/raw-videos/${entry.id}.webm`,
      trimBeforeFrames: entry.trimBeforeFrames,
      clipDurationInFrames: Math.min(entry.videoDurationInFrames, 8 * 24),
      introDurationInFrames: OVERVIEW_INTRO_FRAMES
    }));

  const overviewComposition = await selectComposition({
    serveUrl,
    id: "mercury-demo-overview",
    inputProps: { entries: overviewEntries },
    logLevel: "warn"
  });

  const overviewMp4Path = path.join(artifactDir, "rendered", "overview.mp4");
  const overviewPosterPath = path.join(artifactDir, "rendered", "overview.png");
  log("Rendering stitched overview...");
  await renderMedia({
    serveUrl,
    composition: overviewComposition,
    inputProps: { entries: overviewEntries },
    codec: "h264",
    outputLocation: overviewMp4Path,
    overwrite: true,
    logLevel: "warn"
  });
  await renderStill({
    serveUrl,
    composition: overviewComposition,
    inputProps: { entries: overviewEntries },
    output: overviewPosterPath,
    overwrite: true,
    logLevel: "warn",
    frame: Math.min(48, overviewComposition.durationInFrames - 1)
  });

  manifest.stitchedOverview = {
    renderedMp4Path: overviewMp4Path,
    renderedPosterPath: overviewPosterPath,
    renderedVideoPublicPath: "/rendered/overview.mp4",
    renderedPosterPublicPath: "/rendered/overview.png"
  };

  await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
  log(`Rendered demo artifacts in ${path.join(artifactDir, "rendered")}`);
} finally {
  await assetServer.close();
}
