use anyhow::Result;
use opentelemetry::sdk::propagation::TraceContextPropagator;
use opentelemetry::{global, sdk::trace::Config, trace::TracerProvider};
use slog::{Logger, info, o};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt;

pub fn setup_tracing(name: &'static str, logger: &Logger) -> Result<()> {
    let logger = logger.new(o!("subsystem" => "vsock-tracer"));

    let exporter = vsock_exporter::Exporter::builder()
        .with_logger(&logger)
        .init();

    let config = Config::default();

    let builder = opentelemetry::sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry::runtime::TokioCurrentThread)
        .with_config(config);

    let provider = builder.build();

    let version = None;

    let tracer = provider.get_tracer(name, version);

    let _global_provider = global::set_tracer_provider(provider);

    let layer = OpenTelemetryLayer::new(tracer);

    let subscriber = Registry::default().with(layer);

    tracing::subscriber::set_global_default(subscriber)?;

    global::set_text_map_propagator(TraceContextPropagator::new());

    info!(logger, "tracing setup");

    Ok(())
}

#[macro_export]
macro_rules! trace_rpc_call {
    ($ctx:ident, $name:literal, $req:ident) => {
        // extract context from request context
        let parent_context = global::get_text_map_propagator(|propagator| {
            propagator.extract(&extract_carrier_from_ttrpc($ctx))
        });

        info!(sl(), "rpc call from shim to agent: {:?}", $name);

        // generate tracing span
        let rpc_span = span!(tracing::Level::INFO, $name, "mod"="rpc.rs", req=?$req);

        // assign parent span from external context
        rpc_span.set_parent(parent_context);
        let _enter = rpc_span.enter();
    };
}
