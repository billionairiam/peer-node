#[macro_use]
extern crate lazy_static;
use arc_swap::ArcSwap;
use slog::{BorrowedKV, Drain, KV, Key, OwnedKV, OwnedKVList, Record, o, record_static};
use std::collections::HashMap;
use std::io;
use std::io::Write;
use std::process;
use std::result;
use std::sync::Arc;

mod file_rotate;
mod log_writer;

pub use file_rotate::FileRotator;
pub use log_writer::LogWriter;

lazy_static! {
    pub static ref FILTER_RULE: ArcSwap<HashMap<String, slog::Level>> =
        ArcSwap::from(Arc::new(HashMap::new()));
    pub static ref LOGGERS: ArcSwap<HashMap<String, slog::Logger>> =
        ArcSwap::from(Arc::new(HashMap::new()));
}

const LOG_LEVELS: &[(&str, slog::Level)] = &[
    ("trace", slog::Level::Trace),
    ("debug", slog::Level::Debug),
    ("info", slog::Level::Info),
    ("warn", slog::Level::Warning),
    ("error", slog::Level::Error),
    ("critical", slog::Level::Critical),
];

const DEFAULT_SUBSYSTEM: &str = "root";

// Creates a logger which prints output as human readable text to the terminal
pub fn create_term_logger(level: slog::Level) -> (slog::Logger, slog_async::AsyncGuard) {
    let term_drain = slog_term::term_compact().fuse();

    let unique_drain = UniqueDrain::new(term_drain).fuse();

    FILTER_RULE.rcu(|inner| {
        let mut updater_inner = HashMap::new();
        updater_inner.clone_from(inner);
        for v in updater_inner.values_mut() {
            *v = level;
        }
        updater_inner
    });

    let filter_drain = RuntimeComponentLevelFilter::new(unique_drain, level).fuse();

    let (async_drain, guard) = slog_async::Async::new(filter_drain)
        .thread_name("slog-async-logger".into())
        .build_with_guard();

    let logger = slog::Logger::root(async_drain.fuse(), o!("subsystem" => DEFAULT_SUBSYSTEM));

    (logger, guard)
}

pub enum LogDestination {
    File(Box<dyn Write + Send + Sync>),
    Journal,
}

pub fn create_logger<W>(
    name: &str,
    source: &str,
    level: slog::Level,
    writer: W,
) -> (slog::Logger, slog_async::AsyncGuard)
where
    W: Write + Send + Sync + 'static,
{
    create_logger_with_destination(name, source, level, LogDestination::File(Box::new(writer)))
}

pub fn create_logger_with_destination(
    name: &str,
    source: &str,
    level: slog::Level,
    destination: LogDestination,
) -> (slog::Logger, slog_async::AsyncGuard) {
    let is_journal_destination = matches!(destination, LogDestination::Journal);

    let drain: Box<dyn Drain<Ok = (), Err = slog::Never> + Send> = match destination {
        LogDestination::File(writer) => {
            let json_drain = slog_json::Json::new(writer)
                .add_default_keys()
                .build()
                .fuse();

            Box::new(json_drain)
        }
        LogDestination::Journal => {
            let journal_drain = slog_journald::JournaldDrain.ignore_res();

            Box::new(journal_drain)
        }
    };

    let unique_drain = UniqueDrain::new(drain).fuse();

    FILTER_RULE.rcu(|inner| {
        let mut updated_inner = HashMap::new();
        updated_inner.clone_from(inner);
        for v in updated_inner.values_mut() {
            *v = level;
        }
        updated_inner
    });

    let filter_drain = RuntimeComponentLevelFilter::new(unique_drain, level).fuse();

    let (async_drain, guard) = slog_async::Async::new(filter_drain)
        .thread_name("slog-async-logger".into())
        .build_with_guard();

    let base_logger = slog::Logger::root(
        async_drain.fuse(),
        o!(
            "version" => env!("CARGO_PKG_VERSION"),
            "subsystem" => DEFAULT_SUBSYSTEM,
            "pid" => process::id().to_string(),
            "name" => name.to_string(),
            "source" => source.to_string(),
        ),
    );

    let logger = if is_journal_destination {
        base_logger.new(o!("SYSLOG_IDENTIFIER" => "peernode"))
    } else {
        base_logger
    };

    (logger, guard)
}

pub fn get_log_levels() -> Vec<&'static str> {
    let result: Vec<&str> = LOG_LEVELS.iter().map(|v| v.0).collect();

    result
}

pub fn level_name_to_slog_level(level_name: &str) -> Result<slog::Level, String> {
    for tuple in LOG_LEVELS {
        if tuple.0 == level_name {
            return Ok(tuple.1);
        }
    }

    Err("invalid level name".to_string())
}

pub fn slog_level_to_level_name(level: slog::Level) -> Result<&'static str, &'static str> {
    for tuple in LOG_LEVELS {
        if tuple.1 == level {
            return Ok(tuple.0);
        }
    }

    Err("invalid slog level")
}

pub fn register_component_logger(component_name: &str) {
    let component = String::from(component_name);
    LOGGERS.rcu(|inner| {
        let mut updated_inner = HashMap::new();
        updated_inner.clone_from(inner);
        updated_inner.insert(
            component_name.to_string(),
            slog_scope::logger()
                .new(slog::o!("component" => component.clone(), "subsystem" => component.clone())),
        );
        updated_inner
    });
}

pub fn register_subsystem_logger(component_name: &str, subsystem_name: &str) {
    let subsystem = String::from(subsystem_name);
    LOGGERS.rcu(|inner| {
        let mut updated_inner = HashMap::new();
        updated_inner.clone_from(inner);
        updated_inner.insert(
            subsystem_name.to_string(),
            // This will update the original `subsystem` field.
            inner
                .get(component_name)
                .unwrap_or(&slog_scope::logger())
                .new(slog::o!("subsystem" => subsystem.clone())),
        );
        updated_inner
    });
}

#[derive(Debug)]
struct HashSerializer {
    fields: HashMap<String, String>,
}

impl HashSerializer {
    fn new() -> HashSerializer {
        HashSerializer {
            fields: HashMap::new(),
        }
    }

    fn add_field(&mut self, key: String, value: String) {
        self.fields.entry(key).or_insert(value);
    }

    fn remove_field(&mut self, key: &str) {
        self.fields.remove(key);
    }
}

impl KV for HashSerializer {
    fn serialize(&self, _record: &Record, serializer: &mut dyn slog::Serializer) -> slog::Result {
        for (key, value) in self.fields.iter() {
            serializer.emit_str(Key::from(key.to_string()), &value)?;
        }

        Ok(())
    }
}

impl slog::Serializer for HashSerializer {
    fn emit_arguments(&mut self, key: Key, val: &core::fmt::Arguments) -> slog::Result {
        self.add_field(format!("{}", key), format!("{}", val));
        Ok(())
    }
}

struct UniqueDrain<D> {
    drain: D,
}

impl<D> UniqueDrain<D> {
    fn new(drain: D) -> Self {
        UniqueDrain { drain }
    }
}

impl<D> Drain for UniqueDrain<D>
where
    D: Drain,
{
    type Ok = ();
    type Err = io::Error;

    fn log(
        &self,
        record: &Record,
        values: &OwnedKVList,
    ) -> std::result::Result<Self::Ok, Self::Err> {
        let mut logger_serializer = HashSerializer::new();
        let _ = values.serialize(record, &mut logger_serializer);

        let mut record_serializer = HashSerializer::new();
        let _ = record.kv().serialize(record, &mut record_serializer);

        for (key, _) in record_serializer.fields.iter() {
            logger_serializer.remove_field(key);
        }

        let record_owned_kv = OwnedKV(record_serializer);
        let record_static = record_static!(record.level(), "");
        let new_record = Record::new(&record_static, record.msg(), BorrowedKV(&record_owned_kv));

        let logger_owned_kv = OwnedKV(logger_serializer);

        let result = self
            .drain
            .log(&new_record, &OwnedKVList::from(logger_owned_kv));

        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to drain log".to_string(),
            )),
        }
    }
}

struct RuntimeComponentLevelFilter<D> {
    drain: D,
    log_level: slog::Level,
}

impl<D> RuntimeComponentLevelFilter<D> {
    fn new(drain: D, log_level: slog::Level) -> Self {
        RuntimeComponentLevelFilter { drain, log_level }
    }
}

impl<D> Drain for RuntimeComponentLevelFilter<D>
where
    D: Drain,
{
    type Ok = Option<D::Ok>;
    type Err = Option<D::Err>;

    fn log(&self, record: &Record, values: &OwnedKVList) -> result::Result<Self::Ok, Self::Err> {
        let component_level_config = FILTER_RULE.load();

        let mut log_serializer = HashSerializer::new();
        let _ = values.serialize(record, &mut log_serializer);

        let mut record_serializer = HashSerializer::new();
        record
            .kv()
            .serialize(record, &mut record_serializer)
            .expect("log record serialization failed");

        let mut component = None;
        for (k, v) in record_serializer
            .fields
            .iter()
            .chain(log_serializer.fields.iter())
        {
            if k == "component" {
                component = Some(v.to_string());
                break;
            }
        }
        let according_level = component_level_config
            .get(&component.unwrap_or(DEFAULT_SUBSYSTEM.to_string()))
            .unwrap_or(&self.log_level);
        if record.level().is_at_least(*according_level) {
            let _ = self.drain.log(record, values);
        }

        Ok(None)
    }
}
