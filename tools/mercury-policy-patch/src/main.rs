use std::fs;

use anyhow::Context;
use clap::{Parser, Subcommand};
use mercury_policy_patch::render_policy_from_strings;

#[derive(Debug, Parser)]
#[command(name = "mercury-policy-patch")]
#[command(about = "Merge AI-generated policy patches into Mercury policy YAML")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Render {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        patch: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        create_profile: bool,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("mercury-policy-patch failed: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Render {
            policy,
            patch,
            output,
            create_profile,
        } => {
            let policy_raw = fs::read_to_string(&policy)
                .with_context(|| format!("read policy file {policy}"))?;
            let patch_raw =
                fs::read_to_string(&patch).with_context(|| format!("read patch file {patch}"))?;

            let rendered = render_policy_from_strings(&policy_raw, &patch_raw, create_profile)?;

            if let Some(output_path) = output {
                fs::write(&output_path, &rendered.yaml)
                    .with_context(|| format!("write rendered policy to {output_path}"))?;
            } else {
                print!("{}", rendered.yaml);
            }

            if !rendered.assumptions.is_empty() {
                for assumption in &rendered.assumptions {
                    eprintln!("assumption: {assumption}");
                }
            }

            if rendered.signature_removed {
                eprintln!(
                    "note: removed the input signature block; sign the rendered policy again before reload"
                );
            }
        }
    }

    Ok(())
}
