use anyhow::Result;
use arrow::array::*;
use arrow::datatypes::*;
use arrow::record_batch::RecordBatch;
use std::sync::Arc;

use crate::schema::{HostContext, ReportItem};
use crate::transform::{DerivedContext, HostDerived};

macro_rules! def_builder {
    (
        $(
            $name:ident : $b_type:ident [ $dt:expr ] 
            { nullable: $null:literal, cap: $cap:expr }
        ),* $(,)?
    ) => {
        pub struct NessusArrowBuilder {
            $( $name: $b_type, )*
        }

        impl NessusArrowBuilder {
            pub fn new(c: usize) -> Self {
                Self {
                    $( $name: def_builder!(@init $b_type, c, $cap), )*
                }
            }

            pub fn finish(mut self) -> Result<RecordBatch> {
                let schema = Schema::new(vec![
                    $( Field::new(stringify!($name), $dt, $null) ),*
                ]);
                RecordBatch::try_new(Arc::new(schema), vec![
                    $( Arc::new(self.$name.finish()) as ArrayRef ),*
                ]).map_err(Into::into)
            }
        }
    };

    (@init StringBuilder, $c:ident, $mult:expr) => { 
        StringBuilder::with_capacity($c, $c * $mult) 
    };

    (@init $t:ident, $c:ident, $mult:expr) => { 
        <$t>::with_capacity($c) 
    };
}

def_builder! {
    host_name: StringBuilder [DataType::Utf8] { nullable: false, cap: 20 },
    host_ip:   StringBuilder [DataType::Utf8] { nullable: true,  cap: 15 },
    host_os:   StringBuilder [DataType::Utf8] { nullable: true,  cap: 20 },
    host_mac:  StringBuilder [DataType::Utf8] { nullable: true,  cap: 17 },
    netbios:   StringBuilder [DataType::Utf8] { nullable: true,  cap: 15 },
    fqdn:      StringBuilder [DataType::Utf8] { nullable: true,  cap: 30 },
    sys_type:  StringBuilder [DataType::Utf8] { nullable: true,  cap: 10 },
    cred_scan: StringBuilder [DataType::Utf8] { nullable: true,  cap: 5 },
    policy:    StringBuilder [DataType::Utf8] { nullable: true,  cap: 20 },
    scan_start: StringBuilder [DataType::Utf8] { nullable: true, cap: 30 },
    scan_end:   StringBuilder [DataType::Utf8] { nullable: true, cap: 30 },

    port:          UInt32Builder [DataType::UInt32] { nullable: false, cap: 0 },
    severity:      UInt32Builder [DataType::UInt32] { nullable: false, cap: 0 },
    protocol:      StringBuilder [DataType::Utf8]   { nullable: false, cap: 5 },
    plugin_id:     StringBuilder [DataType::Utf8]   { nullable: false, cap: 10 },
    plugin_name:   StringBuilder [DataType::Utf8]   { nullable: false, cap: 50 },
    plugin_family: StringBuilder [DataType::Utf8]   { nullable: false, cap: 20 },
    svc_name:      StringBuilder [DataType::Utf8]   { nullable: false, cap: 10 },

    desc:       StringBuilder [DataType::Utf8] { nullable: true, cap: 100 },
    synopsis:   StringBuilder [DataType::Utf8] { nullable: true, cap: 50 },
    solution:   StringBuilder [DataType::Utf8] { nullable: true, cap: 100 },
    output:     StringBuilder [DataType::Utf8] { nullable: true, cap: 200 },
    attachment: StringBuilder [DataType::Utf8] { nullable: true, cap: 50 },
    fname:      StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    p_type:     StringBuilder [DataType::Utf8] { nullable: true, cap: 10 },
    script_ver: StringBuilder [DataType::Utf8] { nullable: true, cap: 10 },
    stig:       StringBuilder [DataType::Utf8] { nullable: true, cap: 10 },
    agent:      StringBuilder [DataType::Utf8] { nullable: true, cap: 10 },
    risk:       StringBuilder [DataType::Utf8] { nullable: true, cap: 10 },

    cvss_base: Float64Builder [DataType::Float64] { nullable: true, cap: 0 },
    cvss_vec:  StringBuilder  [DataType::Utf8]    { nullable: true, cap: 30 },
    cvss3_base: Float64Builder [DataType::Float64] { nullable: true, cap: 0 },
    cvss3_vec:  StringBuilder  [DataType::Utf8]    { nullable: true, cap: 30 },
    cvss3_imp:  Float64Builder [DataType::Float64] { nullable: true, cap: 0 },
    vpr:        Float64Builder [DataType::Float64] { nullable: true, cap: 0 },

    cve:      StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    cpe:      StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    bid:      StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    xref:     StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    iava:     StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    see_also: StringBuilder [DataType::Utf8] { nullable: true, cap: 50 },

    unsupported: BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    def_acct:    BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    in_news:     BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    thorough:    BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    potential:   BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    exploit_av:  BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    malware:     BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    nessus_exp:  BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    metasploit:  BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    canvas:      BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    core_impact: BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },

    exploit_ease: StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    comp_check:   StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    comp_id:      StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    comp_res:     StringBuilder [DataType::Utf8] { nullable: true, cap: 10 },
    comp_actual:  StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    comp_policy:  StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    comp_info:    StringBuilder [DataType::Utf8] { nullable: true, cap: 50 },
    comp_sol:     StringBuilder [DataType::Utf8] { nullable: true, cap: 50 },
    comp_ref:     StringBuilder [DataType::Utf8] { nullable: true, cap: 50 },
    audit_file:   StringBuilder [DataType::Utf8] { nullable: true, cap: 30 },
    comp_blob:    StringBuilder [DataType::Utf8] { nullable: true, cap: 100 },
    pub_date:     StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    mod_date:     StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    patch_date:   StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    vuln_date:    StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },

    scan_dur:      Int64Builder [DataType::Int64] { nullable: true, cap: 0 },
    scan_start_ts: Int64Builder [DataType::Int64] { nullable: true, cap: 0 },
    scan_end_ts:   Int64Builder [DataType::Int64] { nullable: true, cap: 0 },
    os_fam:        StringBuilder [DataType::Utf8]    { nullable: false, cap: 10 },
    is_vm:         BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    host_type:     StringBuilder [DataType::Utf8]    { nullable: false, cap: 10 },
    is_web:        BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    is_db:         BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    is_rdp:        BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    is_smb:        BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    vuln_age:      Int64Builder [DataType::Int64] { nullable: true, cap: 0 },
    pub_age:       Int64Builder [DataType::Int64] { nullable: true, cap: 0 },
    patch_lag:     Int64Builder [DataType::Int64] { nullable: true, cap: 0 },
    cvss_sev:      StringBuilder [DataType::Utf8] { nullable: false, cap: 10 },
    rem_exploit:   BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    complex_atk:   BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    priv_req:      BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    user_int:      BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },

    // --- Regex ---
    ssl_exp:   StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    ssl_days:  Int64Builder  [DataType::Int64] { nullable: true, cap: 0 },
    java_ver:  StringBuilder [DataType::Utf8] { nullable: true, cap: 10 },
    php_ver:   StringBuilder [DataType::Utf8] { nullable: true, cap: 10 },
    db_inst:   StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    ext_users: StringBuilder [DataType::Utf8] { nullable: true, cap: 50 },
    unsupp_os: BooleanBuilder [DataType::Boolean] { nullable: false, cap: 0 },
    ext_cve:   StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
    ext_cpe:   StringBuilder [DataType::Utf8] { nullable: true, cap: 20 },
}

impl NessusArrowBuilder {
    pub fn append(&mut self, h: &HostContext, hd: &HostDerived, i: &ReportItem, d: &DerivedContext) {
        self.host_name.append_value(&h.name);
        self.host_ip.append_option(h.ip.as_ref());
        self.host_os.append_option(h.os.as_ref());
        self.host_mac.append_option(h.mac.as_ref());
        self.netbios.append_option(h.netbios.as_ref());
        self.fqdn.append_option(h.fqdn.as_ref());
        self.sys_type.append_option(h.system_type.as_ref());
        self.cred_scan.append_option(h.cred_scan.as_ref());
        self.policy.append_option(h.policy_used.as_ref());
        self.scan_start.append_option(h.start.as_ref());
        self.scan_end.append_option(h.end.as_ref());

        self.port.append_value(i.port as u32);
        self.severity.append_value(i.severity as u32);
        self.protocol.append_value(&i.protocol);
        self.plugin_id.append_value(&i.plugin_id);
        self.plugin_name.append_value(&i.plugin_name);
        self.plugin_family.append_value(&i.plugin_family);
        self.svc_name.append_value(&i.svc_name);
        self.desc.append_option(i.description.as_deref());
        self.synopsis.append_option(i.synopsis.as_deref());
        self.solution.append_option(i.solution.as_deref());
        self.output.append_option(i.plugin_output.as_deref());
        self.attachment.append_option(i.attachment.as_deref());

        self.fname.append_option(i.fname.as_deref());
        self.p_type.append_option(i.plugin_type.as_deref());
        self.script_ver.append_option(i.script_version.as_deref());
        self.stig.append_option(i.stig_severity.as_deref());
        self.agent.append_option(i.agent.as_deref());
        self.risk.append_option(i.risk_factor.as_deref());

        self.cvss_base.append_option(i.cvss_base_score);
        self.cvss_vec.append_option(i.cvss_vector.as_deref());
        self.cvss3_base.append_option(i.cvss3_base_score);
        self.cvss3_vec.append_option(i.cvss3_vector.as_deref());
        self.cvss3_imp.append_option(i.cvss3_impact_score);
        self.vpr.append_option(i.vpr_score);

        if i.cve.is_empty() { self.cve.append_null(); } else { self.cve.append_value(i.cve.join(",")); }
        if i.cpe.is_empty() { self.cpe.append_null(); } else { self.cpe.append_value(i.cpe.join(",")); }
        if i.bid.is_empty() { self.bid.append_null(); } else { self.bid.append_value(i.bid.join(",")); }
        if i.xref.is_empty() { self.xref.append_null(); } else { self.xref.append_value(i.xref.join(",")); }
        if i.iava.is_empty() { self.iava.append_null(); } else { self.iava.append_value(i.iava.join(",")); }
        if i.see_also.is_empty() { self.see_also.append_null(); } else { self.see_also.append_value(i.see_also.join(",")); }

        self.unsupported.append_value(i.unsupported_by_vendor);
        self.def_acct.append_value(i.default_account);
        self.in_news.append_value(i.in_the_news);
        self.thorough.append_value(i.thorough_tests);
        self.potential.append_value(i.potential_vulnerability);
        self.exploit_av.append_value(i.exploit_available);
        self.malware.append_value(i.exploited_by_malware);
        self.nessus_exp.append_value(i.exploited_by_nessus);
        self.metasploit.append_value(!i.metasploit_name.is_empty());
        self.canvas.append_value(!i.canvas_package.is_empty());
        self.core_impact.append_value(!i.core_impact_name.is_empty());

        self.exploit_ease.append_option(i.exploitability_ease.as_deref());
        self.comp_check.append_option(i.comp_check_name.as_deref());
        self.comp_id.append_option(i.comp_check_id.as_deref());
        self.comp_res.append_option(i.comp_result.as_deref());
        self.comp_actual.append_option(i.comp_actual_value.as_deref());
        self.comp_policy.append_option(i.comp_policy_value.as_deref());
        self.comp_info.append_option(i.comp_info.as_deref());
        self.comp_sol.append_option(i.comp_solution.as_deref());
        self.comp_ref.append_option(i.comp_reference.as_deref());
        self.audit_file.append_option(i.comp_audit_file.as_deref());
        self.comp_blob.append_option(i.compliance_blob.as_deref());
        self.pub_date.append_option(i.plugin_pub_date.as_deref());
        self.mod_date.append_option(i.plugin_mod_date.as_deref());
        self.patch_date.append_option(i.patch_pub_date.as_deref());
        self.vuln_date.append_option(i.vuln_pub_date.as_deref());

        self.scan_dur.append_option(hd.scan_duration);
        self.scan_start_ts.append_option(hd.scan_start_ts);
        self.scan_end_ts.append_option(hd.scan_end_ts);
        self.os_fam.append_value(hd.os_family);
        self.is_vm.append_value(hd.is_vm);
        self.host_type.append_value(hd.host_type);
        self.is_web.append_value(d.is_web);
        self.is_db.append_value(d.is_db);
        self.is_rdp.append_value(d.is_rdp);
        self.is_smb.append_value(d.is_smb);
        self.vuln_age.append_option(d.vuln_age_days);
        self.pub_age.append_option(d.pub_age_days);
        self.patch_lag.append_option(d.patch_lag_days);
        self.cvss_sev.append_value(d.cvss_severity);
        self.rem_exploit.append_value(d.remotely_exploitable);
        self.complex_atk.append_value(d.complex_attack);
        self.priv_req.append_value(d.privilege_required);
        self.user_int.append_value(d.user_interaction);
        self.ssl_exp.append_option(d.ssl_expiry.as_ref());
        self.ssl_days.append_option(d.ssl_days_left);
        self.java_ver.append_option(d.java_version.as_ref());
        self.php_ver.append_option(d.php_version.as_ref());
        self.db_inst.append_option(d.db_instances.as_ref());
        self.ext_users.append_option(d.extracted_users.as_ref());
        self.unsupp_os.append_value(d.unsupported_os);
        self.ext_cve.append_option(d.extracted_cves.as_ref());
        self.ext_cpe.append_option(d.extracted_cpes.as_ref());
    }
}