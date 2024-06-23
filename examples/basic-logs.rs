// cargo run --example basic-logs

use opentelemetry_appender_tracing::layer;
use opentelemetry_journald_logs_unofficial::JournaldLogExporter;
use opentelemetry_sdk::logs::LoggerProvider;
use tracing::info;
use tracing_subscriber::prelude::*;

fn init_logger() -> LoggerProvider {
    let exporter = JournaldLogExporter::builder()
        .identifier("opentelemetry-journal-exporter")
        .message_size_limit(4 * 1024)
        .attribute_prefix(Some("OTEL_".to_string()))
        .build()
        .expect("Failed to build JournaldLogExporter");

    LoggerProvider::builder()
        .with_simple_exporter(exporter)
        .build()
}

fn main() {
    let logger_provider = init_logger();
    let layer = layer::OpenTelemetryTracingBridge::new(&logger_provider);
    tracing_subscriber::registry().with(layer).init();

    // Generate a large message, this won't be logged (support to be added later)
    let large_message: String = "A".repeat(8000); // Adjust the size as needed
    info!(
        event_id = 1234,
        user_id = 5678,
        "large message: {}",
        large_message
    );
    info!(event_id = 1234, user_id = 5678, "small message");
}
