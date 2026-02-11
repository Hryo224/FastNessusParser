use crate::schema::{HostContext, ReportItem};
use chrono::{NaiveDate, NaiveDateTime};
use regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

static RE_IPV4: OnceLock<Regex> = OnceLock::new();
static RE_OS_WIN: OnceLock<Regex> = OnceLock::new();
static RE_OS_NIX: OnceLock<Regex> = OnceLock::new();
static RE_VM: OnceLock<Regex> = OnceLock::new();
static RE_SSL_DATE: OnceLock<Regex> = OnceLock::new();
static RE_JAVA: OnceLock<Regex> = OnceLock::new();
static RE_PHP: OnceLock<Regex> = OnceLock::new();
static RE_DB_INST: OnceLock<Regex> = OnceLock::new();
static RE_USERS: OnceLock<Regex> = OnceLock::new();
static CVE_REGEX: OnceLock<Regex> = OnceLock::new();
static CPE_REGEX: OnceLock<Regex> = OnceLock::new();

const TARGET_PLUGINS: &[&str] = &["20811", "22869", "83991", "45590", "19506"];

macro_rules! get_regex {
    ($lock:ident, $re:expr) => {
        $lock.get_or_init(|| Regex::new($re).expect("Invalid regex"))
    };
}

/// Data calculated ONCE per host
pub struct HostDerived {
    pub scan_duration: Option<i64>,
    pub scan_start_ts: Option<i64>,
    pub scan_end_ts: Option<i64>,
    pub os_family: &'static str,
    pub is_vm: bool,
    pub host_type: &'static str,
}

impl HostDerived {
    pub fn analyze(h: &HostContext) -> Self {
        const FMT_DT: &str = "%a %b %d %H:%M:%S %Y";

        let parse_dt = |s: &Option<String>| {
            s.as_deref()
                .and_then(|t| NaiveDateTime::parse_from_str(t, FMT_DT).ok())
        };
        let t_start: Option<NaiveDateTime> = parse_dt(&h.start);
        let t_end: Option<NaiveDateTime> = parse_dt(&h.end);

        let scan_duration: Option<i64> = t_start.zip(t_end).map(|(s, e)| (e - s).num_seconds());
        let scan_start_ts: Option<i64> = t_start.map(|t| t.and_utc().timestamp());
        let scan_end_ts: Option<i64> = t_end.map(|t| t.and_utc().timestamp());

        let os_str: &str = h.os.as_deref().unwrap_or("");
        let os_family: &str = if get_regex!(RE_OS_WIN, r"(?i)windows").is_match(os_str) {
            "Windows"
        } else if get_regex!(RE_OS_NIX, r"(?i)(linux|unix|bsd|ubuntu|centos|rhel)").is_match(os_str)
        {
            "Linux"
        } else if os_str.to_lowercase().contains("cisco") {
            "Cisco"
        } else {
            "Other"
        };

        let is_vm: bool =
            get_regex!(RE_VM, r"(?i)(vmware|virtualbox|hyper-v|qemu|xen)").is_match(os_str);

        let host_type: &str =
            if get_regex!(RE_IPV4, r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").is_match(&h.name) {
                "IP"
            } else {
                "Hostname"
            };

        HostDerived {
            scan_duration,
            scan_start_ts,
            scan_end_ts,
            os_family,
            is_vm,
            host_type,
        }
    }
}

#[derive(Default)]
pub struct DerivedContext {
    pub is_web: bool,
    pub is_db: bool,
    pub is_rdp: bool,
    pub is_smb: bool,
    pub vuln_age_days: Option<i64>,
    pub pub_age_days: Option<i64>,
    pub patch_lag_days: Option<i64>,
    pub cvss_severity: &'static str,
    pub remotely_exploitable: bool,
    pub complex_attack: bool,
    pub privilege_required: bool,
    pub user_interaction: bool,
    pub ssl_expiry: Option<String>,
    pub ssl_days_left: Option<i64>,
    pub java_version: Option<String>,
    pub php_version: Option<String>,
    pub db_instances: Option<String>,
    pub extracted_users: Option<String>,
    pub unsupported_os: bool,
    pub extracted_cves: Option<String>,
    pub extracted_cpes: Option<String>,
}

impl DerivedContext {
    pub fn calculate(h_ctx: &HostContext, _h_data: &HostDerived, i: &ReportItem) -> Self {
        let now: NaiveDate = chrono::Utc::now().naive_utc().date();
        const FMT_D: &str = "%Y/%m/%d";

        let is_web: bool = matches!(i.port, 80 | 443 | 8080)
            || i.svc_name.contains("www")
            || i.svc_name.contains("http");
        let is_db: bool = matches!(i.port, 1433 | 3306 | 5432 | 1521);
        let is_rdp: bool = i.port == 3389;
        let is_smb: bool = matches!(i.port, 445 | 139);

        let parse_d = |s: &Option<Cow<'_, str>>| {
            s.as_deref()
                .and_then(|t| NaiveDate::parse_from_str(t, FMT_D).ok())
        };
        let vuln_date: Option<NaiveDate> = parse_d(&i.vuln_pub_date);
        let pub_date: Option<NaiveDate> = parse_d(&i.plugin_pub_date);
        let patch_date: Option<NaiveDate> = parse_d(&i.patch_pub_date);

        let vuln_age_days: Option<i64> = vuln_date.map(|d| (now - d).num_days());
        let pub_age_days: Option<i64> = pub_date.map(|d| (now - d).num_days());
        let patch_lag_days: Option<i64> =
            vuln_date.zip(patch_date).map(|(v, p)| (p - v).num_days());

        let score: f64 = i.cvss_base_score.unwrap_or(0.0);
        let cvss_severity: &str = match score {
            s if s >= 9.0 => "Critical",
            s if s >= 7.0 => "High",
            s if s >= 4.0 => "Medium",
            s if s > 0.0 => "Low",
            _ => "None",
        };

        let vec: String = i.cvss_vector.as_deref().unwrap_or("").to_uppercase();
        let remotely_exploitable: bool = vec.contains("AV:N");
        let complex_attack: bool = vec.contains("AC:H");
        let privilege_required: bool = !vec.contains("AU:N") && !vec.contains("PR:N");
        let user_interaction: bool = vec.contains("UI:R");

        let mut ssl_expiry: Option<String> = None;
        let mut ssl_days_left: Option<i64> = None;
        let mut java_version: Option<String> = None;
        let mut php_version: Option<String> = None;
        let mut db_instances: Option<String> = None;
        let mut extracted_users: Option<String> = None;

        if let Some(out) = &i.plugin_output {
            if i.plugin_id == "10863" {
                let re: &Regex = get_regex!(RE_SSL_DATE, r"Not After\s*:\s*(.*)$");
                if let Some(cap) = re.captures(out) {
                    if let Ok(d) =
                        NaiveDateTime::parse_from_str(cap[1].trim(), "%b %d %H:%M:%S %Y %Z")
                    {
                        ssl_expiry = Some(d.to_string());
                        ssl_days_left = Some((d.date() - now).num_days());
                    }
                }
            }

            if out.contains("Java") {
                let re: &Regex = get_regex!(RE_JAVA, r"version\s+(\d+(\.\d+)+)");
                if let Some(cap) = re.captures(out) {
                    java_version = Some(cap[1].to_string());
                }
            }

            if i.svc_name.contains("php") || (i.port == 80 && i.plugin_family == "CGI Abuses") {
                let re: &Regex = get_regex!(RE_PHP, r"PHP/(\d+\.\d+\.\d+)");
                if let Some(cap) = re.captures(out) {
                    php_version = Some(cap[1].to_string());
                }
            }

            if is_db {
                let re: &Regex = get_regex!(RE_DB_INST, r"Instance Name\s*:\s*(\w+)");
                let dbs: Vec<String> = re.captures_iter(out).map(|c| c[1].to_string()).collect();
                if !dbs.is_empty() {
                    db_instances = Some(dbs.join(","));
                }
            }

            if matches!(i.plugin_id.as_ref(), "10892" | "10398") {
                let re: &Regex = get_regex!(RE_USERS, r"(?m)^\s*-\s*([a-zA-Z0-9_]+)$");
                let users: Vec<String> = re.captures_iter(out).map(|c| c[1].to_string()).collect();
                if !users.is_empty() {
                    extracted_users = Some(users.join(","));
                }
            }
        }

        let os_str: &str = h_ctx.os.as_deref().unwrap_or("");
        let unsupported_os: bool = os_str.to_lowercase().contains("unsupported")
            || ["2003", "XP", "2008"]
                .iter()
                .any(|old| os_str.contains(*old));

        let mut extracted_cves: Option<String> = None;
        let mut extracted_cpes: Option<String> = None;

        if let Some(txt) = &i.plugin_output {
            if TARGET_PLUGINS.contains(&i.plugin_id.as_ref()) {
                let re_cve: &Regex = get_regex!(CVE_REGEX, r"CVE-\d{4}-\d{4,}");
                let cves: Vec<&str> = re_cve.find_iter(txt).map(|m| m.as_str()).collect();
                if !cves.is_empty() {
                    extracted_cves = Some(cves.join(","));
                }

                let re_cpe: &Regex = get_regex!(CPE_REGEX, r"cpe:/[a-zA-Z0-9:._~%-]+");
                let cpes: Vec<&str> = re_cpe.find_iter(txt).map(|m| m.as_str()).collect();
                if !cpes.is_empty() {
                    extracted_cpes = Some(cpes.join(","));
                }
            }
        }

        DerivedContext {
            is_web,
            is_db,
            is_rdp,
            is_smb,
            vuln_age_days,
            pub_age_days,
            patch_lag_days,
            cvss_severity,
            remotely_exploitable,
            complex_attack,
            privilege_required,
            user_interaction,
            ssl_expiry,
            ssl_days_left,
            java_version,
            php_version,
            db_instances,
            extracted_users,
            unsupported_os,
            extracted_cves,
            extracted_cpes,
        }
    }
}
