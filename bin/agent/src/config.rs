use anyhow::{self, Result, bail};
use serde::Deserialize;
use std::env;
use std::{str::FromStr, time};
use strum_macros::{Display, EnumString};
use tracing::instrument;

const DEFAULT_LOG_LEVEL: slog::Level = slog::Level::Info;

const DEFAULT_CDH_API_TIMEOUT: time::Duration = time::Duration::from_secs(50);

const ERR_INVALID_LOG_LEVEL: &str = "invalid log level";

const LOG_LEVEL_ENV_VAR: &str = "AGENT_LOG_LEVEL";

const TRACING_ENV_VAR: &str = "AGENT_TRACING";

#[derive(Clone, Copy, Debug, Default, Display, Deserialize, EnumString, PartialEq)]
#[strum(serialize_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum GuestComponentsFeatures {
    All,
    Attestation,
    #[default]
    Resource,
}

#[derive(Clone, Copy, Debug, Default, Display, Deserialize, EnumString, PartialEq, Eq)]
#[strum(serialize_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum GuestComponentsProcs {
    None,
    #[default]
    ApiServerRest,
    AttestationAgent,
    ConfidentialDataHub,
}

#[derive(Debug)]
pub struct AgentConfig {
    pub log_level: slog::Level,
    pub cdh_api_timeout: time::Duration,
    pub log_vport: i32,
    pub tracing: bool,
    pub https_proxy: String,
    pub no_proxy: String,
    pub guest_components_rest_api: GuestComponentsFeatures,
    pub guest_components_procs: GuestComponentsProcs,
}

#[derive(Debug, Deserialize)]
pub struct AgentConfigBuilder {
    pub log_level: Option<String>,
    pub cdh_api_timeout: Option<time::Duration>,
    pub log_vport: Option<i32>,
    pub tracing: Option<bool>,
    pub https_proxy: Option<String>,
    pub no_proxy: Option<String>,
    pub guest_components_rest_api: Option<GuestComponentsFeatures>,
    pub guest_components_procs: Option<GuestComponentsProcs>,
}

macro_rules! config_override {
    ($builder:ident, $config:ident, $field:ident) => {
        if let Some(v) = $builder.$field {
            $config.$field = v;
        }
    };

    ($builder:ident, $config:ident, $field:ident, $func:ident) => {
        if let Some(v) = $builder.$field {
            $config.$field = $func(&v)?;
        }
    };
}

impl Default for AgentConfig {
    fn default() -> Self {
        let mut agent = AgentConfig {
            log_level: DEFAULT_LOG_LEVEL,
            cdh_api_timeout: DEFAULT_CDH_API_TIMEOUT,
            log_vport: 0,
            tracing: false,
            https_proxy: String::from(""),
            no_proxy: String::from(""),
            guest_components_rest_api: GuestComponentsFeatures::default(),
            guest_components_procs: GuestComponentsProcs::default(),
        };

        agent.override_config_from_envs();

        agent
    }
}

impl FromStr for AgentConfig {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let agent_config_builder: AgentConfigBuilder =
            toml::from_str(s).map_err(anyhow::Error::new)?;
        let mut agent_config: AgentConfig = Default::default();

        config_override!(
            agent_config_builder,
            agent_config,
            log_level,
            logrus_to_slog_level
        );
        config_override!(agent_config_builder, agent_config, cdh_api_timeout);
        config_override!(agent_config_builder, agent_config, log_vport);
        config_override!(agent_config_builder, agent_config, tracing);
        config_override!(agent_config_builder, agent_config, https_proxy);
        config_override!(agent_config_builder, agent_config, no_proxy);
        config_override!(
            agent_config_builder,
            agent_config,
            guest_components_rest_api
        );
        config_override!(agent_config_builder, agent_config, guest_components_procs);

        Ok(agent_config)
    }
}

impl AgentConfig {
    #[instrument]
    pub fn override_config_from_envs(&mut self) {
        if let Ok(level) = env::var(LOG_LEVEL_ENV_VAR) {
            if let Ok(level) = logrus_to_slog_level(&level) {
                self.log_level = level;
            }
        }

        if let Ok(value) = env::var(TRACING_ENV_VAR) {
            let name_value = format!("{}={}", TRACING_ENV_VAR, value);

            self.tracing = get_bool_value(&name_value).unwrap_or(false);
        }
    }
}

#[instrument]
fn logrus_to_slog_level(logrus_level: &str) -> Result<slog::Level> {
    let levle = match logrus_level {
        "fatal" | "panic" => slog::Level::Critical,
        "critic" => slog::Level::Critical,
        "error" => slog::Level::Error,
        "warn" | "warning" => slog::Level::Warning,
        "info" => slog::Level::Info,
        "debug" => slog::Level::Debug,
        "trace" => slog::Level::Trace,
        _ => bail!(ERR_INVALID_LOG_LEVEL),
    };

    Ok(levle)
}

#[instrument]
fn get_bool_value(param: &str) -> Result<bool> {
    let fields: Vec<&str> = param.split('=').collect();
    if fields.len() != 2 {
        return Ok(false);
    }

    let v = fields[1];

    v.parse::<bool>()
        .or_else(|_e| v.parse::<u64>().or(Ok(0)).map(|v| !matches!(v, 0)))
}
