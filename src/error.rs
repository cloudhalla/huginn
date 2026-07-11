use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum HuginnError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Platform error in {context}: {source}")]
    Platform {
        source: Box<dyn std::error::Error + Send + Sync>,
        context: String,
    },

    #[error("Collector '{name}' failed: {reason}")]
    Collector { name: String, reason: String },

    #[error("Insufficient privileges: {0}")]
    InsufficientPrivileges(String),

    #[error("Output error: {0}")]
    Output(String),

    #[error("Template error: {0}")]
    Template(String),
}

#[allow(dead_code)]
impl HuginnError {
    pub fn platform(
        source: impl std::error::Error + Send + Sync + 'static,
        context: impl Into<String>,
    ) -> Self {
        Self::Platform {
            source: Box::new(source),
            context: context.into(),
        }
    }

    pub fn collector(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Collector {
            name: name.into(),
            reason: reason.into(),
        }
    }

    pub fn output(msg: impl Into<String>) -> Self {
        Self::Output(msg.into())
    }

    pub fn template(msg: impl Into<String>) -> Self {
        Self::Template(msg.into())
    }
}
