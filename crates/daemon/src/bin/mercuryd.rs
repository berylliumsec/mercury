use clap::Parser;
use rustls::crypto::CryptoProvider;

#[derive(Debug, Parser)]
#[command(name = "mercuryd")]
#[command(about = "AI runtime security daemon")]
struct Args {
    #[arg(long, default_value = "/etc/mercury/config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() {
    install_rustls_provider();
    let args = Args::parse();

    if let Err(err) = daemon::run_from_config_path(args.config).await {
        eprintln!("mercuryd failed: {err}");
        std::process::exit(1);
    }
}

fn install_rustls_provider() {
    if CryptoProvider::get_default().is_some() {
        return;
    }

    // Both ring and aws-lc-rs can be present transitively; install one explicitly.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
