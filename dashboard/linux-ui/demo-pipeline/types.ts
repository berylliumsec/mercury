export type DemoScenarioId =
  | "ui-overview"
  | "url-deny-website"
  | "network-port-deny"
  | "folder-deny"
  | "exec-deny";

export type DemoTranscript = {
  kind: "command" | "note";
  displayCommand: string;
  command: string[];
  exitCode: number | null;
  stdout: string;
  stderr: string;
  expected: string;
  observed: string;
};

export type DemoManifestEntry = {
  id: DemoScenarioId;
  order: number;
  title: string;
  summary: string;
  resultLabel: string;
  eventEvidence: string;
  evidenceFilter: string;
  trimBeforeFrames: number;
  introDurationInFrames: number;
  videoDurationInFrames: number;
  posterFrame: number;
  includeInOverview: boolean;
  readmeEmbed: boolean;
  transcriptPath: string;
  rawVideoPath: string;
  rawVideoPublicPath: string;
  renderedMp4Path?: string;
  renderedPosterPath?: string;
  renderedVideoPublicPath?: string;
  renderedPosterPublicPath?: string;
  rawVideoSidecarName?: string;
  renderedVideoName?: string;
  renderedPosterName?: string;
};

export type DemoManifest = {
  schemaVersion: 1;
  generatedAt: string;
  scenarios: DemoManifestEntry[];
  stitchedOverview?: {
    renderedMp4Path: string;
    renderedPosterPath: string;
    renderedVideoPublicPath: string;
    renderedPosterPublicPath: string;
  };
};
