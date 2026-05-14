mod domain;
mod application;
mod infrastructure;
mod presentation;

use application::orchestrator::HardeningOrchestrator;
use presentation::cli;

fn main() {
    let orchestrator = HardeningOrchestrator::new();
    cli::run_interactive(&orchestrator);
}
