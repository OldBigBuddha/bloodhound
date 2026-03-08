use tokio::signal;
use tokio::sync::broadcast;

/// Create a shutdown signal handler that listens for SIGTERM.
/// Returns a broadcast sender that can be used to notify all tasks.
pub fn shutdown_signal() -> broadcast::Sender<()> {
    let (tx, _) = broadcast::channel(1);
    let tx_clone = tx.clone();

    tokio::spawn(async move {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("Failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                eprintln!("Received SIGTERM, initiating graceful shutdown...");
            }
            _ = sigint.recv() => {
                eprintln!("Received SIGINT, initiating graceful shutdown...");
            }
        }

        let _ = tx_clone.send(());
    });

    tx
}
