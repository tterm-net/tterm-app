//! The agent without its refusal to run as root, for checks that run as
//! root in a container: tTerm Web's own (tterm/tests/test_agents.py, with
//! TTERM_AGENT pointing here), as they ran agent.py through main_loop. The
//! same code but that one check. Examples are not part of a release.

use tterm_agent::{run, settings, Start};
use tterm_engine::link::Timing;

fn main() {
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().to_string()).collect();
    match settings(args) {
        Start::Exit(code) => std::process::exit(code),
        Start::Run(settings) => std::process::exit(run(settings, Timing::default())),
    }
}
