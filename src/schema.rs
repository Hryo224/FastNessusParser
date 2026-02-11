use serde::Deserialize;
use std::borrow::Cow;

#[derive(Debug, Deserialize)]
pub struct ReportHost<'a> {
    #[serde(rename = "@name")]
    pub name: Cow<'a, str>,
    #[serde(rename = "HostProperties")]
    pub properties: HostProperties<'a>,
    #[serde(rename = "ReportItem", default)]
    pub items: Vec<ReportItem<'a>>,
}

#[derive(Debug, Deserialize)]
pub struct HostProperties<'a> {
    #[serde(rename = "tag", default)]
    pub tags: Vec<HostTag<'a>>,
}

#[derive(Debug, Deserialize)]
pub struct HostTag<'a> {
    #[serde(rename = "@name")]
    pub name: Cow<'a, str>,
    #[serde(rename = "$value")]
    pub value: Cow<'a, str>,
}

#[derive(Debug, Default, Clone)]
pub struct HostContext {
    pub name: String,
    pub ip: Option<String>,
    pub os: Option<String>,
    pub mac: Option<String>,
    pub netbios: Option<String>,
    pub fqdn: Option<String>,
    pub system_type: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub cred_scan: Option<String>,
    pub policy_used: Option<String>,
}

impl HostContext {
    pub fn from_report_host(host: &ReportHost) -> Self {
        let mut ctx = HostContext {
            name: host.name.to_string(),
            ..Default::default()
        };

        for tag in &host.properties.tags {
            match tag.name.as_ref() {
                "host-ip" => ctx.ip = Some(tag.value.to_string()),
                "operating-system" => ctx.os = Some(tag.value.to_string()),
                "mac-address" => ctx.mac = Some(tag.value.to_string()),
                "netbios-name" => ctx.netbios = Some(tag.value.to_string()),
                "host-fqdn" => ctx.fqdn = Some(tag.value.to_string()),
                "system-type" => ctx.system_type = Some(tag.value.to_string()),
                "HOST_START" => ctx.start = Some(tag.value.to_string()),
                "HOST_END" => ctx.end = Some(tag.value.to_string()),
                "Credentialed_Scan" => ctx.cred_scan = Some(tag.value.to_string()),
                "policy-used" => ctx.policy_used = Some(tag.value.to_string()),
                _ => {}
            }
        }
        ctx
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ReportItem<'a> {
    #[serde(rename = "@port")]
    pub port: u16,
    #[serde(rename = "@svc_name")]
    pub svc_name: Cow<'a, str>,
    #[serde(rename = "@protocol")]
    pub protocol: Cow<'a, str>,
    #[serde(rename = "@severity")]
    pub severity: u8,
    #[serde(rename = "@pluginID")]
    pub plugin_id: Cow<'a, str>,
    #[serde(rename = "@pluginName")]
    pub plugin_name: Cow<'a, str>,
    #[serde(rename = "@pluginFamily")]
    pub plugin_family: Cow<'a, str>,

    pub description: Option<Cow<'a, str>>,
    pub synopsis: Option<Cow<'a, str>>,
    pub solution: Option<Cow<'a, str>>,
    #[serde(rename = "plugin_output")]
    pub plugin_output: Option<Cow<'a, str>>,

    pub fname: Option<Cow<'a, str>>,
    pub plugin_type: Option<Cow<'a, str>>,
    pub risk_factor: Option<Cow<'a, str>>,
    pub script_version: Option<Cow<'a, str>>,
    pub stig_severity: Option<Cow<'a, str>>,
    pub agent: Option<Cow<'a, str>>,

    #[serde(default)]
    pub unsupported_by_vendor: bool,
    #[serde(default)]
    pub default_account: bool,
    #[serde(default)]
    pub in_the_news: bool,
    #[serde(default)]
    pub thorough_tests: bool,
    #[serde(default)]
    pub potential_vulnerability: bool,

    #[serde(rename = "plugin_modification_date")]
    pub plugin_mod_date: Option<Cow<'a, str>>,
    #[serde(rename = "plugin_publication_date")]
    pub plugin_pub_date: Option<Cow<'a, str>>,
    #[serde(rename = "patch_publication_date")]
    pub patch_pub_date: Option<Cow<'a, str>>,
    #[serde(rename = "vuln_publication_date")]
    pub vuln_pub_date: Option<Cow<'a, str>>,

    #[serde(default, rename = "cve")]
    pub cve: Vec<Cow<'a, str>>,
    #[serde(default, rename = "bid")]
    pub bid: Vec<Cow<'a, str>>,
    #[serde(default, rename = "xref")]
    pub xref: Vec<Cow<'a, str>>,
    #[serde(default, rename = "see_also")]
    pub see_also: Vec<Cow<'a, str>>,
    #[serde(default, rename = "cpe")]
    pub cpe: Vec<Cow<'a, str>>,
    #[serde(default, rename = "iava")]
    pub iava: Vec<Cow<'a, str>>,

    #[serde(default)]
    pub exploit_available: bool,
    pub exploitability_ease: Option<Cow<'a, str>>,
    #[serde(default)]
    pub exploited_by_malware: bool,
    #[serde(default)]
    pub exploited_by_nessus: bool,
    #[serde(default, rename = "metasploit_name")]
    pub metasploit_name: Vec<Cow<'a, str>>,
    #[serde(default, rename = "canvas_package")]
    pub canvas_package: Vec<Cow<'a, str>>,
    #[serde(default, rename = "core_impact_name")]
    pub core_impact_name: Vec<Cow<'a, str>>,

    pub cvss_base_score: Option<f64>,
    pub cvss_vector: Option<Cow<'a, str>>,
    pub cvss3_base_score: Option<f64>,
    pub cvss3_vector: Option<Cow<'a, str>>,
    pub cvss3_impact_score: Option<f64>,
    #[serde(rename = "vpr_score")]
    pub vpr_score: Option<f64>,

    pub attachment: Option<Cow<'a, str>>,

    #[serde(rename = "cm:compliance-check-name")]
    pub comp_check_name: Option<Cow<'a, str>>,
    #[serde(rename = "cm:compliance-check-id")]
    pub comp_check_id: Option<Cow<'a, str>>,
    #[serde(rename = "cm:compliance-result")]
    pub comp_result: Option<Cow<'a, str>>,
    #[serde(rename = "cm:compliance-actual-value")]
    pub comp_actual_value: Option<Cow<'a, str>>,
    #[serde(rename = "cm:compliance-policy-value")]
    pub comp_policy_value: Option<Cow<'a, str>>,
    #[serde(rename = "cm:compliance-info")]
    pub comp_info: Option<Cow<'a, str>>,
    #[serde(rename = "cm:compliance-solution")]
    pub comp_solution: Option<Cow<'a, str>>,
    #[serde(rename = "cm:compliance-reference")]
    pub comp_reference: Option<Cow<'a, str>>,
    #[serde(rename = "cm:compliance-audit-file")]
    pub comp_audit_file: Option<Cow<'a, str>>,
    #[serde(rename = "compliance")]
    pub compliance_blob: Option<Cow<'a, str>>,
}
