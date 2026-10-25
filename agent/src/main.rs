//! tterm-agent: connects this computer to tTerm Web. See lib.rs.

use tterm_agent::{run, settings, Start};
use tterm_engine::link::Timing;

fn main() {
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().to_string()).collect();
    let settings = match settings(args) {
        Start::Exit(code) => std::process::exit(code),
        Start::Run(settings) => settings,
    };
    if nix::unistd::geteuid().is_root() {
        // The agent must never hold more privileges than the person at the
        // keyboard. There is deliberately no way around this check.
        eprintln!("Do not run the agent as root — run it as your own user.");
        std::process::exit(1);
    }
    std::process::exit(run(settings, Timing::default()));
}
