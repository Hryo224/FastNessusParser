use anyhow::{Context, Result};
use memmap2::MmapOptions;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rayon::prelude::*;
use std::fs::File;
use std::io::Read;

use crate::schema::{HostContext, NessusFinding, ReportHost, ScanMetadata};
use crate::transform::DerivedContext;

const CHUNK_SIZE: usize = 2000;

pub fn parse_scan_metadata(path: &str) -> Result<ScanMetadata> {
    let mut file: File = File::open(path)?;
    let mut buf: [u8; 51200] = [0u8; 50 * 1024];
    let n: usize = file.read(&mut buf)?;
    let data: &[u8] = &buf[..n];

    let mut reader: Reader<&[u8]> = Reader::from_reader(data);
    let mut meta: ScanMetadata = ScanMetadata::default();
    let mut buf: Vec<u8> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Report" => {
                for attr in e.attributes() {
                    if let Ok(a) = attr {
                        if a.key.as_ref() == b"name" {
                            meta.report_name = Some(String::from_utf8_lossy(&a.value).to_string());
                        }
                    }
                }
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"ReportHost" => break,
            Ok(Event::Eof) => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(meta)
}

pub fn parse_nessus_native(path: &str) -> Result<Vec<NessusFinding>> {
    let file: File = File::open(path).with_context(|| format!("Failed to open {}", path))?;
    let mmap: memmap2::Mmap = unsafe { MmapOptions::new().map(&file)? };

    let host_ranges: Vec<(usize, usize)> =
        find_host_ranges(&mmap).context("Failed to index Nessus XML")?;

    let chunks: Vec<Vec<NessusFinding>> = host_ranges
        .par_chunks(CHUNK_SIZE)
        .map(|chunk_ranges| -> Result<Vec<NessusFinding>> {
            let mut chunk_findings = Vec::with_capacity(chunk_ranges.len() * 10);

            for &(start, end) in chunk_ranges {
                let slice: &[u8] = &mmap[start..end];
                let host: ReportHost = quick_xml::de::from_reader(slice)?;
                let h: HostContext = HostContext::from_report_host(&host);

                for i in &host.items {
                    let d: DerivedContext = DerivedContext::calculate(&h, i);

                    chunk_findings.push(NessusFinding {
                        host_properties: h.all_tags.clone(),

                        host_name: h.name.clone(),
                        host_ip: h.ip.clone(),
                        host_os: h.os.clone(),
                        host_mac: h.mac.clone(),
                        netbios: h.netbios.clone(),
                        fqdn: h.fqdn.clone(),
                        sys_type: h.system_type.clone(),
                        cred_scan: h.cred_scan.clone(),
                        policy: h.policy_used.clone(),
                        scan_start: h.start.clone(),
                        scan_end: h.end.clone(),

                        port: i.port as u32,
                        severity: i.severity as u32,
                        protocol: i.protocol.clone(),
                        plugin_id: i.plugin_id.clone(),
                        plugin_name: i.plugin_name.clone(),
                        family: i.plugin_family.clone(),
                        service: i.svc_name.clone(),
                        desc: i.description.clone(),
                        synopsis: i.synopsis.clone(),
                        solution: i.solution.clone(),
                        output: i.plugin_output.clone(),
                        attachment: i.attachment.clone(),

                        fname: i.fname.clone(),
                        p_type: i.plugin_type.clone(),
                        script_ver: i.script_version.clone(),
                        stig: i.stig_severity.clone(),
                        agent: i.agent.clone(),
                        risk: i.risk_factor.clone(),

                        cvss_base: i.cvss_base_score,
                        cvss_vec: i.cvss_vector.clone(),
                        cvss3_base: i.cvss3_base_score,
                        cvss3_vec: i.cvss3_vector.clone(),
                        cvss3_imp: i.cvss3_impact_score,
                        vpr: i.vpr_score,

                        cve: if i.cve.is_empty() {
                            None
                        } else {
                            Some(i.cve.join(","))
                        },
                        cpe: if i.cpe.is_empty() {
                            None
                        } else {
                            Some(i.cpe.join(","))
                        },
                        bid: if i.bid.is_empty() {
                            None
                        } else {
                            Some(i.bid.join(","))
                        },
                        xref: if i.xref.is_empty() {
                            None
                        } else {
                            Some(i.xref.join(","))
                        },
                        iava: if i.iava.is_empty() {
                            None
                        } else {
                            Some(i.iava.join(","))
                        },
                        see_also: if i.see_also.is_empty() {
                            None
                        } else {
                            Some(i.see_also.join(","))
                        },

                        unsupported: i.unsupported_by_vendor,
                        def_acct: i.default_account,
                        in_news: i.in_the_news,
                        thorough: i.thorough_tests,
                        potential: i.potential_vulnerability,

                        exploit_av: i.exploit_available,
                        exploit_ease: i.exploitability_ease.clone(),
                        malware: i.exploited_by_malware,
                        nessus_exp: i.exploited_by_nessus,
                        metasploit: !i.metasploit_name.is_empty(),
                        canvas: !i.canvas_package.is_empty(),
                        core_impact: !i.core_impact_name.is_empty(),

                        comp_check: i.comp_check_name.clone(),
                        comp_id: i.comp_check_id.clone(),
                        comp_res: i.comp_result.clone(),
                        comp_actual: i.comp_actual_value.clone(),
                        comp_policy: i.comp_policy_value.clone(),
                        comp_info: i.comp_info.clone(),
                        comp_sol: i.comp_solution.clone(),
                        comp_ref: i.comp_reference.clone(),
                        audit_file: i.comp_audit_file.clone(),
                        comp_blob: i.compliance_blob.clone(),

                        pub_date: i.plugin_pub_date.clone(),
                        mod_date: i.plugin_mod_date.clone(),
                        patch_date: i.patch_pub_date.clone(),
                        vuln_date: i.vuln_pub_date.clone(),

                        scan_dur: d.scan_duration,
                        scan_start_ts: d.scan_start_ts,
                        scan_end_ts: d.scan_end_ts,
                        os_fam: d.os_family.to_string(),
                        is_vm: d.is_vm,
                        host_type: d.host_type.to_string(),
                        is_web: d.is_web,
                        is_db: d.is_db,
                        is_rdp: d.is_rdp,
                        is_smb: d.is_smb,
                        vuln_age: d.vuln_age_days,
                        pub_age: d.pub_age_days,
                        patch_lag: d.patch_lag_days,
                        cvss_sev: d.cvss_severity.to_string(),
                        rem_exploit: d.remotely_exploitable,
                        complex_atk: d.complex_attack,
                        priv_req: d.privilege_required,
                        user_int: d.user_interaction,

                        ssl_exp: d.ssl_expiry,
                        ssl_days: d.ssl_days_left,
                        java_ver: d.java_version,
                        php_ver: d.php_version,
                        db_inst: d.db_instances,
                        ext_users: d.extracted_users,
                        unsupp_os: d.unsupported_os,
                        ext_cve: d.extracted_cves,
                        ext_cpe: d.extracted_cpes,
                    });
                }
            }
            Ok(chunk_findings)
        })
        .collect::<Result<Vec<Vec<_>>>>()?;

    Ok(chunks.into_iter().flatten().collect())
}

fn find_host_ranges(data: &[u8]) -> Result<Vec<(usize, usize)>> {
    let mut reader: Reader<&[u8]> = Reader::from_reader(data);
    reader.trim_text(true);

    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(4096);
    let mut current_start: Option<usize> = None;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let start_pos: usize = reader.buffer_position();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"ReportHost" => {
                current_start = Some(start_pos);
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"ReportHost" => {
                if let Some(start) = current_start {
                    ranges.push((start, reader.buffer_position()));
                    current_start = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "XML syntax error at byte {}: {}",
                    start_pos,
                    e
                ));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(ranges)
}
