use crate::error::HuginnError;
use crate::models::report::Report;

const HTML_TEMPLATE: &str = include_str!("../../templates/report.html.jinja");
const CSS_CONTENT: &str = include_str!("../../templates/report.css");
const JS_CONTENT: &str = include_str!("../../templates/report.js");

pub fn render(report: &Report) -> Result<String, HuginnError> {
    let mut env = minijinja::Environment::new();
    env.add_template("report", HTML_TEMPLATE)
        .map_err(|e| HuginnError::template(e.to_string()))?;

    let tmpl = env
        .get_template("report")
        .map_err(|e| HuginnError::template(e.to_string()))?;

    let risk_level = match report.summary.risk_score {
        70..=100 => "critical",
        50..=69 => "high",
        30..=49 => "medium",
        1..=29 => "low",
        _ => "info",
    };

    tmpl.render(minijinja::context! {
        report => report,
        css => CSS_CONTENT,
        js => JS_CONTENT,
        risk_level => risk_level,
    })
    .map_err(|e| HuginnError::template(e.to_string()))
}
