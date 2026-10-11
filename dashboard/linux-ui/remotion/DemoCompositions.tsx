import type { CSSProperties, ReactNode } from "react";

import {
  AbsoluteFill,
  Composition,
  OffthreadVideo,
  Series,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig
} from "remotion";

import type { DemoManifestEntry, DemoTranscript } from "../demo-pipeline/types";

type ScenarioClipProps = {
  entry: DemoManifestEntry;
  transcript: DemoTranscript;
};

type OverviewEntry = {
  id: string;
  title: string;
  summary: string;
  resultLabel: string;
  rawVideoPublicPath: string;
  trimBeforeFrames: number;
  clipDurationInFrames: number;
  introDurationInFrames: number;
};

type OverviewClipProps = {
  entries: OverviewEntry[];
};

const SURFACE: CSSProperties = {
  borderRadius: 28,
  border: "1px solid rgba(149, 167, 191, 0.18)",
  background: "linear-gradient(180deg, rgba(12, 18, 27, 0.92), rgba(7, 12, 20, 0.84))",
  boxShadow: "0 26px 70px rgba(0, 0, 0, 0.34)"
};

const LABEL_STYLE: CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  borderRadius: 999,
  padding: "10px 14px",
  fontSize: 20,
  fontWeight: 700,
  letterSpacing: "0.02em",
  background: "rgba(122, 184, 255, 0.16)",
  color: "#d8ebff"
};

function clipText(value: string, limit: number) {
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }

  return trimmed.length > limit ? `${trimmed.slice(0, limit - 1)}...` : trimmed;
}

function SectionLabel({ children }: { children: string }) {
  return (
    <span
      style={{
        fontSize: 12,
        letterSpacing: "0.14em",
        color: "#90a3bc",
        textTransform: "uppercase"
      }}
    >
      {children}
    </span>
  );
}

function SceneHeader({
  eyebrow,
  title,
  summary,
  visible
}: {
  eyebrow: string;
  title: string;
  summary: string;
  visible: number;
}) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const rise = spring({ fps, frame, config: { damping: 160 } });

  return (
    <div
      style={{
        position: "absolute",
        top: 24,
        left: 24,
        maxWidth: 540,
        color: "#f5f8ff",
        opacity: visible,
        transform: `translateY(${(1 - rise) * 16}px)`
      }}
    >
      <div
        style={{
          display: "grid",
          gap: 14,
          ...SURFACE,
          padding: 24,
          background: "linear-gradient(180deg, rgba(10, 16, 25, 0.82), rgba(6, 10, 16, 0.7))",
          boxShadow: "0 18px 48px rgba(0, 0, 0, 0.28)"
        }}
      >
        <span
          style={{
            ...LABEL_STYLE,
            width: "fit-content",
            fontSize: 14,
            padding: "8px 12px"
          }}
        >
          {eyebrow}
        </span>
        <h1 style={{ margin: 0, fontSize: 34, lineHeight: 1.04 }}>{title}</h1>
        <p
          style={{
            margin: 0,
            fontSize: 17,
            lineHeight: 1.45,
            color: "rgba(218, 231, 247, 0.88)"
          }}
        >
          {summary}
        </p>
      </div>
    </div>
  );
}

function InfoPane({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      style={{
        borderRadius: 18,
        padding: 14,
        border: "1px solid rgba(149, 167, 191, 0.16)",
        background: "rgba(7, 12, 20, 0.62)",
        display: "grid",
        gap: 8,
        alignContent: "start",
        minWidth: 0
      }}
    >
      <SectionLabel>{label}</SectionLabel>
      {children}
    </div>
  );
}

function BottomDock({
  entry,
  transcript,
  visible
}: {
  entry: DemoManifestEntry;
  transcript: DemoTranscript;
  visible: number;
}) {
  const outputText = clipText(
    [transcript.stdout.trim(), transcript.stderr.trim()].filter(Boolean).join("\n"),
    120
  );
  const commandText = clipText(transcript.displayCommand || "(dashboard interaction only)", 120);
  const observedText = clipText(transcript.observed, 104);
  const evidenceText = clipText(entry.eventEvidence, 96);
  const proofLabel = transcript.kind === "note" ? "Operator steps" : "Command proof";

  return (
    <div
      style={{
        position: "absolute",
        left: 24,
        right: 24,
        bottom: 24,
        opacity: visible,
        display: "grid",
        gap: 14,
        pointerEvents: "none"
      }}
    >
      <div
        style={{
          ...SURFACE,
          padding: 18,
          display: "grid",
          gridTemplateColumns: "minmax(260px, 0.8fr) minmax(0, 1.4fr)",
          gap: 16,
          background: "linear-gradient(180deg, rgba(10, 16, 26, 0.86), rgba(6, 10, 16, 0.8))"
        }}
      >
        <div style={{ display: "grid", gap: 8 }}>
          <span
            style={{
              ...LABEL_STYLE,
              width: "fit-content",
              fontSize: 16,
              padding: "8px 12px"
            }}
          >
            Mercury Demo
          </span>
          <div style={{ fontSize: 28, fontWeight: 800, lineHeight: 1.06 }}>{entry.title}</div>
          <div style={{ fontSize: 16, lineHeight: 1.45, color: "#d3deeb" }}>{entry.summary}</div>
        </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
            gap: 12
          }}
        >
          <InfoPane label={proofLabel}>
            <div
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 13,
                lineHeight: 1.45,
                whiteSpace: "pre-wrap",
                color: "#f3f6fc"
              }}
            >
              {commandText}
            </div>
          </InfoPane>
          <InfoPane label="Result">
            <div style={{ ...LABEL_STYLE, width: "fit-content", fontSize: 15 }}>
              {entry.resultLabel}
            </div>
            <div style={{ fontSize: 14, lineHeight: 1.45, color: "#d7e3f0" }}>{observedText}</div>
            {outputText ? (
              <div
                style={{
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 12,
                  lineHeight: 1.45,
                  color: "#dce7f5",
                  padding: 10,
                  borderRadius: 12,
                  background: "rgba(17, 25, 37, 0.92)",
                  border: "1px solid rgba(149, 167, 191, 0.14)"
                }}
              >
                {outputText}
                {`\nexit=${transcript.exitCode ?? "?"}`}
              </div>
            ) : null}
          </InfoPane>
          <InfoPane label="Evidence">
            <div style={{ fontSize: 14, color: "#e6eef9", lineHeight: 1.45 }}>{evidenceText}</div>
          </InfoPane>
        </div>
      </div>
    </div>
  );
}

export function ScenarioClip({ entry, transcript }: ScenarioClipProps) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const leadOpacity = interpolate(
    frame,
    [6, 20, entry.introDurationInFrames + 8, entry.introDurationInFrames + 28],
    [0, 1, 1, 0],
    {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp"
    }
  );
  const dockOpacity = interpolate(
    frame,
    [entry.introDurationInFrames + 20, entry.introDurationInFrames + 42],
    [0, 1],
    {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp"
    }
  );
  const videoRise = spring({
    fps,
    frame,
    config: { damping: 180 }
  });
  const videoOpacity = interpolate(frame, [0, 10], [0.86, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp"
  });

  return (
    <AbsoluteFill
      style={{
        background: "linear-gradient(180deg, rgba(7, 11, 18, 1), rgba(5, 8, 14, 1))",
        color: "#f4f7fd"
      }}
    >
      <AbsoluteFill style={{ padding: 20 }}>
        <div
          style={{
            ...SURFACE,
            overflow: "hidden",
            position: "relative",
            height: "100%",
            transform: `translateY(${(1 - videoRise) * 8}px)`,
            opacity: videoOpacity
          }}
        >
          <OffthreadVideo
            src={entry.rawVideoPublicPath}
            trimBefore={entry.trimBeforeFrames}
            muted
            style={{
              width: "100%",
              height: "100%",
              objectFit: "cover"
            }}
          />
          <div
            style={{
              position: "absolute",
              inset: 0,
              background:
                "linear-gradient(180deg, rgba(4, 7, 12, 0.36) 0%, rgba(4, 7, 12, 0.06) 24%, rgba(4, 7, 12, 0.12) 64%, rgba(4, 7, 12, 0.62) 100%)"
            }}
          />
          <SceneHeader
            eyebrow="Mercury Demo"
            title={entry.title}
            summary={entry.summary}
            visible={leadOpacity}
          />
          <BottomDock entry={entry} transcript={transcript} visible={dockOpacity} />
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
}

function ChapterBadge({
  title,
  summary,
  resultLabel
}: {
  title: string;
  summary: string;
  resultLabel: string;
}) {
  return (
    <div
      style={{
        ...SURFACE,
        padding: "16px 18px",
        display: "grid",
        gap: 8,
        maxWidth: 400,
        background: "linear-gradient(180deg, rgba(10, 16, 25, 0.8), rgba(6, 10, 16, 0.72))"
      }}
    >
      <span style={{ ...LABEL_STYLE, width: "fit-content", fontSize: 14, padding: "8px 12px" }}>
        Mercury Demo
      </span>
      <div style={{ fontSize: 24, fontWeight: 800, lineHeight: 1.08 }}>{title}</div>
      <div style={{ fontSize: 15, color: "#d3deeb", lineHeight: 1.4 }}>{summary}</div>
      <div style={{ fontSize: 14, color: "#b9c7d9" }}>{resultLabel}</div>
    </div>
  );
}

function OverviewSegment({ entry }: { entry: OverviewEntry }) {
  const frame = useCurrentFrame();
  const badgeOpacity = interpolate(
    frame,
    [entry.introDurationInFrames - 6, entry.introDurationInFrames + 14],
    [0, 1],
    {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp"
    }
  );
  const videoOpacity = interpolate(
    frame,
    [0, 8, entry.clipDurationInFrames - 12, entry.clipDurationInFrames - 1],
    [0.88, 1, 1, 0.94],
    {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp"
    }
  );

  return (
    <AbsoluteFill style={{ opacity: videoOpacity }}>
      <OffthreadVideo
        src={entry.rawVideoPublicPath}
        trimBefore={entry.trimBeforeFrames}
        muted
        style={{ width: "100%", height: "100%", objectFit: "cover" }}
      />
      <AbsoluteFill
        style={{
          background:
            "linear-gradient(180deg, rgba(4, 7, 12, 0.24) 0%, rgba(4, 7, 12, 0.04) 22%, rgba(4, 7, 12, 0.08) 60%, rgba(4, 7, 12, 0.52) 100%)"
        }}
      />
      <div
        style={{
          position: "absolute",
          left: 24,
          bottom: 24,
          opacity: badgeOpacity
        }}
      >
        <ChapterBadge title={entry.title} summary={entry.summary} resultLabel={entry.resultLabel} />
      </div>
    </AbsoluteFill>
  );
}

export function OverviewClip({ entries }: OverviewClipProps) {
  return (
    <AbsoluteFill style={{ background: "#04070d" }}>
      <Series>
        {entries.map((entry) => (
          <Series.Sequence key={`${entry.id}-clip`} durationInFrames={entry.clipDurationInFrames}>
            <OverviewSegment entry={entry} />
          </Series.Sequence>
        ))}
      </Series>
    </AbsoluteFill>
  );
}

export function DemoRoot() {
  return (
    <>
      <Composition
        id="mercury-demo-scenario"
        component={ScenarioClip}
        width={1280}
        height={720}
        fps={24}
        defaultProps={{
          entry: {
            id: "url-deny-website",
            order: 0,
            title: "Placeholder",
            summary: "Placeholder",
            resultLabel: "Placeholder",
            eventEvidence: "Placeholder",
            evidenceFilter: "placeholder",
            trimBeforeFrames: 8,
            introDurationInFrames: 48,
            videoDurationInFrames: 240,
            posterFrame: 96,
            includeInOverview: true,
            readmeEmbed: true,
            transcriptPath: "",
            rawVideoPath: "",
            rawVideoPublicPath: "/raw-videos/url-deny-website.webm"
          },
          transcript: {
            kind: "command",
            displayCommand: "placeholder",
            command: [],
            exitCode: 0,
            stdout: "placeholder",
            stderr: "",
            expected: "placeholder",
            observed: "placeholder"
          }
        }}
        calculateMetadata={({ props }) => ({
          durationInFrames: props.entry.videoDurationInFrames
        })}
      />
      <Composition
        id="mercury-demo-overview"
        component={OverviewClip}
        width={1280}
        height={720}
        fps={24}
        defaultProps={{
          entries: []
        }}
        calculateMetadata={({ props }) => ({
          durationInFrames: Math.max(
            props.entries.reduce((sum, entry) => sum + entry.clipDurationInFrames, 0),
            24
          )
        })}
      />
    </>
  );
}
