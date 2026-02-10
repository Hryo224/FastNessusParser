use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct ReportHost {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "HostProperties")]
    pub properties: HostProperties,
    #[serde(rename = "ReportItem", default)]
    pub items: Vec<ReportItem>,
}

#[derive(Debug, Deserialize)]
pub struct HostProperties {
    #[serde(rename = "tag", default)]
    pub tags: Vec<HostTag>,
}

#[derive(Debug, Deserialize)]
pub struct HostTag {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct ScanMetadata {
    pub report_name: Option<String>,
    pub policy_name: Option<String>,
    pub scanner_name: Option<String>,
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
    pub all_tags: HashMap<String, String>,
}

impl HostContext {
    pub fn from_report_host(host: &ReportHost) -> Self {
        let mut ctx = HostContext {
            name: host.name.clone(),
            all_tags: HashMap::new(),
            ..Default::default()
        };

        for tag in &host.properties.tags {
            ctx.all_tags.insert(tag.name.clone(), tag.value.clone());

            let val = Some(tag.value.clone());
            match tag.name.as_str() {
                "host-ip" => ctx.ip = val,
                "operating-system" => ctx.os = val,
                "mac-address" => ctx.mac = val,
                "netbios-name" => ctx.netbios = val,
                "host-fqdn" => ctx.fqdn = val,
                "system-type" => ctx.system_type = val,
                "HOST_START" => ctx.start = val,
                "HOST_END" => ctx.end = val,
                "Credentialed_Scan" => ctx.cred_scan = val,
                "policy-used" => ctx.policy_used = val,
                _ => {}
            }
        }
        ctx
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct NessusFinding {
    pub host_properties: HashMap<String, String>,

    pub host_name: String,
    pub host_ip: Option<String>,
    pub host_os: Option<String>,
    pub host_mac: Option<String>,
    pub netbios: Option<String>,
    pub fqdn: Option<String>,
    pub sys_type: Option<String>,
    pub cred_scan: Option<String>,
    pub policy: Option<String>,
    pub scan_start: Option<String>,
    pub scan_end: Option<String>,

    pub port: u32,
    pub severity: u32,
    pub protocol: String,
    pub plugin_id: String,
    pub plugin_name: String,
    pub family: String,
    pub service: String,
    pub desc: Option<String>,
    pub synopsis: Option<String>,
    pub solution: Option<String>,
    pub output: Option<String>,
    pub attachment: Option<String>,

    pub fname: Option<String>,
    pub p_type: Option<String>,
    pub script_ver: Option<String>,
    pub stig: Option<String>,
    pub agent: Option<String>,
    pub risk: Option<String>,

    pub cvss_base: Option<f64>,
    pub cvss_vec: Option<String>,
    pub cvss3_base: Option<f64>,
    pub cvss3_vec: Option<String>,
    pub cvss3_imp: Option<f64>,
    pub vpr: Option<f64>,

    pub cve: Option<String>,
    pub cpe: Option<String>,
    pub bid: Option<String>,
    pub xref: Option<String>,
    pub iava: Option<String>,
    pub see_also: Option<String>,

    pub unsupported: bool,
    pub def_acct: bool,
    pub in_news: bool,
    pub thorough: bool,
    pub potential: bool,

    pub exploit_av: bool,
    pub exploit_ease: Option<String>,
    pub malware: bool,
    pub nessus_exp: bool,
    pub metasploit: bool,
    pub canvas: bool,
    pub core_impact: bool,

    pub comp_check: Option<String>,
    pub comp_id: Option<String>,
    pub comp_res: Option<String>,
    pub comp_actual: Option<String>,
    pub comp_policy: Option<String>,
    pub comp_info: Option<String>,
    pub comp_sol: Option<String>,
    pub comp_ref: Option<String>,
    pub audit_file: Option<String>,
    pub comp_blob: Option<String>,

    pub pub_date: Option<String>,
    pub mod_date: Option<String>,
    pub patch_date: Option<String>,
    pub vuln_date: Option<String>,

    pub scan_dur: Option<i64>,
    pub scan_start_ts: Option<i64>,
    pub scan_end_ts: Option<i64>,
    pub os_fam: String,
    pub is_vm: bool,
    pub host_type: String,
    pub is_web: bool,
    pub is_db: bool,
    pub is_rdp: bool,
    pub is_smb: bool,
    pub vuln_age: Option<i64>,
    pub pub_age: Option<i64>,
    pub patch_lag: Option<i64>,
    pub cvss_sev: String,
    pub rem_exploit: bool,
    pub complex_atk: bool,
    pub priv_req: bool,
    pub user_int: bool,

    pub ssl_exp: Option<String>,
    pub ssl_days: Option<i64>,
    pub java_ver: Option<String>,
    pub php_ver: Option<String>,
    pub db_inst: Option<String>,
    pub ext_users: Option<String>,
    pub unsupp_os: bool,
    pub ext_cve: Option<String>,
    pub ext_cpe: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ReportItem {
    #[serde(rename = "@port")]
    pub port: u16,
    #[serde(rename = "@svc_name")]
    pub svc_name: String,
    #[serde(rename = "@protocol")]
    pub protocol: String,
    #[serde(rename = "@severity")]
    pub severity: u8,
    #[serde(rename = "@pluginID")]
    pub plugin_id: String,
    #[serde(rename = "@pluginName")]
    pub plugin_name: String,
    #[serde(rename = "@pluginFamily")]
    pub plugin_family: String,

    pub description: Option<String>,
    pub synopsis: Option<String>,
    pub solution: Option<String>,
    #[serde(rename = "plugin_output")]
    pub plugin_output: Option<String>,

    pub fname: Option<String>,
    pub plugin_type: Option<String>,
    pub risk_factor: Option<String>,
    pub script_version: Option<String>,
    pub stig_severity: Option<String>,
    pub agent: Option<String>,

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
    pub plugin_mod_date: Option<String>,
    #[serde(rename = "plugin_publication_date")]
    pub plugin_pub_date: Option<String>,
    #[serde(rename = "patch_publication_date")]
    pub patch_pub_date: Option<String>,
    #[serde(rename = "vuln_publication_date")]
    pub vuln_pub_date: Option<String>,

    #[serde(default, rename = "cve")]
    pub cve: Vec<String>,
    #[serde(default, rename = "bid")]
    pub bid: Vec<String>,
    #[serde(default, rename = "xref")]
    pub xref: Vec<String>,
    #[serde(default, rename = "see_also")]
    pub see_also: Vec<String>,
    #[serde(default, rename = "cpe")]
    pub cpe: Vec<String>,
    #[serde(default, rename = "iava")]
    pub iava: Vec<String>,

    #[serde(default)]
    pub exploit_available: bool,
    pub exploitability_ease: Option<String>,
    #[serde(default)]
    pub exploited_by_malware: bool,
    #[serde(default)]
    pub exploited_by_nessus: bool,
    #[serde(default, rename = "metasploit_name")]
    pub metasploit_name: Vec<String>,
    #[serde(default, rename = "canvas_package")]
    pub canvas_package: Vec<String>,
    #[serde(default, rename = "core_impact_name")]
    pub core_impact_name: Vec<String>,

    pub cvss_base_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub cvss3_base_score: Option<f64>,
    pub cvss3_vector: Option<String>,
    pub cvss3_impact_score: Option<f64>,
    #[serde(rename = "vpr_score")]
    pub vpr_score: Option<f64>,

    pub attachment: Option<String>,

    #[serde(rename = "cm:compliance-check-name")]
    pub comp_check_name: Option<String>,
    #[serde(rename = "cm:compliance-check-id")]
    pub comp_check_id: Option<String>,
    #[serde(rename = "cm:compliance-result")]
    pub comp_result: Option<String>,
    #[serde(rename = "cm:compliance-actual-value")]
    pub comp_actual_value: Option<String>,
    #[serde(rename = "cm:compliance-policy-value")]
    pub comp_policy_value: Option<String>,
    #[serde(rename = "cm:compliance-info")]
    pub comp_info: Option<String>,
    #[serde(rename = "cm:compliance-solution")]
    pub comp_solution: Option<String>,
    #[serde(rename = "cm:compliance-reference")]
    pub comp_reference: Option<String>,
    #[serde(rename = "cm:compliance-audit-file")]
    pub comp_audit_file: Option<String>,
    #[serde(rename = "compliance")]
    pub compliance_blob: Option<String>,
}
