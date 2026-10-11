import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const artifactDir = process.env.MERCURY_E2E_DEMO_ARTIFACT_DIR;

if (!artifactDir) {
  throw new Error("missing MERCURY_E2E_DEMO_ARTIFACT_DIR");
}

const manifestPath = path.join(artifactDir, "manifest.json");
const readmeDir = path.join(artifactDir, "readme");

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
await mkdir(readmeDir, { recursive: true });

const nameMap = {
  "ui-overview": "policy-studio-overview",
  "url-deny-website": "blocked-website",
  "network-port-deny": "blocked-port",
  "folder-deny": "blocked-folder",
  "exec-deny": "blocked-exec"
};

const embeddedIds = ["url-deny-website", "network-port-deny", "folder-deny"];
const sideClipIds = ["exec-deny"];

async function copyScenarioAsset(entry, baseName) {
  if (!entry.renderedMp4Path || !entry.renderedPosterPath || !entry.rawVideoPath) {
    throw new Error(`scenario ${entry.id} has not been rendered yet`);
  }

  const posterTarget = path.join(readmeDir, `${baseName}.png`);
  const videoTarget = path.join(readmeDir, `${baseName}.mp4`);
  const rawTarget = path.join(readmeDir, `${baseName}.webm`);

  await copyFile(entry.renderedPosterPath, posterTarget);
  await copyFile(entry.renderedMp4Path, videoTarget);
  await copyFile(entry.rawVideoPath, rawTarget);

  return {
    posterTarget,
    videoTarget,
    rawTarget
  };
}

const copied = {};

for (const entry of manifest.scenarios) {
  const baseName = nameMap[entry.id];
  if (!baseName) {
    continue;
  }
  copied[entry.id] = await copyScenarioAsset(entry, baseName);
}

if (!manifest.stitchedOverview) {
  throw new Error("stitched overview output missing from manifest");
}

await copyFile(manifest.stitchedOverview.renderedPosterPath, path.join(readmeDir, "overview.png"));
await copyFile(manifest.stitchedOverview.renderedMp4Path, path.join(readmeDir, "overview.mp4"));

const embeddedEntries = embeddedIds.map((id) =>
  manifest.scenarios.find((entry) => entry.id === id)
);
const sideEntries = sideClipIds.map((id) => manifest.scenarios.find((entry) => entry.id === id));

const snippet = [
  "## Mercury Demo Clips",
  "",
  ...embeddedEntries.flatMap((entry) => {
    if (!entry) {
      return [];
    }
    const baseName = nameMap[entry.id];
    return [
      `[![${entry.title}](./${baseName}.png)](./${baseName}.mp4)`,
      `${entry.summary} ${entry.eventEvidence}`,
      `Side artifacts: [rendered MP4](./${baseName}.mp4) · [raw Playwright WebM](./${baseName}.webm)`,
      ""
    ];
  }),
  "Full walkthrough: [overview.mp4](./overview.mp4)",
  "",
  ...sideEntries.flatMap((entry) => {
    if (!entry) {
      return [];
    }
    const baseName = nameMap[entry.id];
    return [
      `${entry.title}: [rendered MP4](./${baseName}.mp4) · [raw WebM](./${baseName}.webm)`,
      ""
    ];
  })
].join("\n");

await writeFile(path.join(readmeDir, "README.demo.generated.md"), snippet);
await writeFile(path.join(readmeDir, "asset-map.json"), JSON.stringify(copied, null, 2));

process.stdout.write(`README assets written to ${readmeDir}\n`);
