// Port of the service half of snort3 detection/fp_utils.cc —
// buffer_map statics (get_service / get_num_services / clear_buffer_map /
// update_buffer_map / add_default_services) and guess_service — plus
// add_service_to_otn + add_service_to_otn_helper from parser/parse_conf.cc.
// All compiled VERBATIM in tools/rules_harness; transcribed from the
// compiled copies (NOT from scratch greps), pinned by the replay's R12
// SVC lines.
#![allow(dead_code)]

use std::collections::HashMap;

use crate::detection::treenodes::{OptTreeNode, SignatureServiceInfo};
use crate::framework::ips_option::CursorActionType;
use crate::log::messages::{LogEngine, WARN_RULES};
use crate::target_based::snort_protocols::ProtocolReference;
use crate::utils::cfmt::Arg;

pub type SvcList = Vec<String>;

/// fp_utils.cc file-static: std::unordered_map<std::string, SvcList> buffer_map
#[derive(Default)]
pub struct BufferMap {
    m: HashMap<String, SvcList>,
}

impl BufferMap {
    /// const char* get_service(buf): first svc of the list, miss -> None
    pub fn get_service(&self, buf: &str) -> Option<&str> {
        self.m.get(buf).and_then(|l| l.first()).map(|s| s.as_str())
    }

    /// unsigned get_num_services(buf)
    pub fn get_num_services(&self, buf: &str) -> usize {
        self.m.get(buf).map(|l| l.len()).unwrap_or(0)
    }

    /// void clear_buffer_map()
    pub fn clear(&mut self) {
        self.m.clear();
    }

    /// void update_buffer_map(const char** bufs, const char* svc)
    pub fn update(&mut self, bufs: &[&str], svc: &str) {
        for b in bufs {
            self.m.entry((*b).to_string()).or_default().push(svc.to_string());
        }
    }
}

/// fp_utils.cc guess_service(opt): pinned prefix table, exact order.
pub fn guess_service(opt: &str) -> Option<&'static str> {
    if opt.starts_with("http_") {
        return Some("http");
    }
    if opt.starts_with("cip_") || opt.starts_with("enip_") {
        return Some("cip");
    }
    if opt.starts_with("dce_") {
        return Some("netbios-ssn");
    }
    if opt.starts_with("dnp3_") {
        return Some("dnp3");
    }
    if opt.starts_with("gtp_") {
        return Some("gtp");
    }
    if opt.starts_with("mms_") {
        return Some("mms");
    }
    if opt.starts_with("modbus_") {
        return Some("modbus");
    }
    if opt.starts_with("s7commplus_") {
        return Some("s7commplus");
    }
    if opt.starts_with("sip_") {
        return Some("sip");
    }
    if opt.starts_with("socks_") {
        return Some("socks");
    }
    if opt.starts_with("ssl_") {
        return Some("ssl");
    }
    None
}

pub struct ServiceBridge<'a> {
    pub proto_ref: &'a mut ProtocolReference,
    pub service_extension: &'a HashMap<String, Vec<String>>,
    pub buffer_map: &'a mut BufferMap,
}

/// parse_conf.cc add_service_to_otn_helper (file-static): proto_ref->add
/// then any_of dedup by snort_protocol_id.
pub fn add_service_to_otn_helper(br: &mut ServiceBridge<'_>, otn: &mut OptTreeNode, svc_name: &str) {
    let svc_id = br.proto_ref.add(svc_name);
    if otn.sigInfo.services.iter().any(|si| si.snort_protocol_id == svc_id) {
        return; // already added
    }
    otn.sigInfo.services.push(SignatureServiceInfo {
        service: svc_name.to_string(),
        snort_protocol_id: svc_id,
    });
}

/// parse_conf.cc add_service_to_otn (verbatim).
pub fn add_service_to_otn(
    log: &mut LogEngine,
    br: &mut ServiceBridge<'_>,
    otn: &mut OptTreeNode,
    svc_name: &str,
) {
    if svc_name == "file" && otn.sigInfo.services.is_empty() {
        // well-known services supporting file_data
        // applies to both alert file and service:file rules
        let buf = "file_data";
        add_default_services(log, br, otn, buf);
    }

    add_service_to_otn_helper(br, otn, svc_name);
    if let Some(exts) = br.service_extension.get(svc_name) {
        let exts = exts.clone();
        for svc in exts.iter() {
            add_service_to_otn_helper(br, otn, svc);
        }
    }
    let _ = log;
}

/// fp_utils.cc add_default_services(sc, buf, otn)
pub fn add_default_services(
    log: &mut LogEngine,
    br: &mut ServiceBridge<'_>,
    otn: &mut OptTreeNode,
    buf: &str,
) {
    let list: SvcList = match br.buffer_map.m.get(buf) {
        None => return,
        Some(l) => l.clone(),
    };
    for svc in list.iter() {
        add_service_to_otn(log, br, otn, svc);
    }
}

/// fp_utils.cc validate_services(sc, otn). `opts` mirrors the otn->opt_func
/// walk: (ips_opt name, cursor_type) pairs in list order (only chains with
/// a non-null ips_opt reach the body; skipped upstream by `continue`).
pub fn validate_services(
    log: &mut LogEngine,
    br: &mut ServiceBridge<'_>,
    otn: &mut OptTreeNode,
    opts: &[(String, CursorActionType)],
) {
    let mut svc = String::new();
    let mut multi_svc_buf = String::new();
    let mut guess: Option<&'static str> = None;

    for (opt_name, cat) in opts.iter() {
        if *cat <= CursorActionType::CatAdjust {
            if guess.is_none() {
                guess = guess_service(opt_name);
            }
            continue;
        }
        let n = br.buffer_map.get_num_services(opt_name);
        if n == 0 {
            continue;
        }
        if n > 1 {
            multi_svc_buf = opt_name.clone();
            continue;
        }
        // n == 1: get_service hits (presence checked); null impossible
        let opt_svc = br.buffer_map.get_service(opt_name).unwrap_or("").to_string();
        if br.service_extension.contains_key(&opt_svc) {
            multi_svc_buf = opt_name.clone();
            continue;
        }
        if !svc.is_empty() && svc != opt_svc {
            log.parse_warning(
                WARN_RULES,
                "%u:%u:%u has mixed service buffers (%s and %s)",
                &[
                    Arg::U(otn.sigInfo.gid as u64),
                    Arg::U(otn.sigInfo.sid as u64),
                    Arg::U(otn.sigInfo.rev as u64),
                    Arg::S(Some(svc.clone().into())),
                    Arg::S(Some(opt_svc.clone().into())),
                ],
            );
        }
        svc = opt_svc;
    }

    if !svc.is_empty() || !multi_svc_buf.is_empty() || guess.is_some() {
        otn.set_service_only();
    }

    if otn.sigInfo.services.len() == 1 && !svc.is_empty() && otn.sigInfo.services[0].service != svc
    {
        log.parse_warning(
            WARN_RULES,
            "%u:%u:%u has service:%s with %s buffer",
            &[
                Arg::U(otn.sigInfo.gid as u64),
                Arg::U(otn.sigInfo.sid as u64),
                Arg::U(otn.sigInfo.rev as u64),
                Arg::S(Some(otn.sigInfo.services[0].service.clone().into())),
                Arg::S(Some(svc.clone().into())),
            ],
        );
    }
    if otn.sigInfo.services.is_empty() && !svc.is_empty() {
        log.parse_warning(
            WARN_RULES,
            "%u:%u:%u has no service with %s buffer",
            &[
                Arg::U(otn.sigInfo.gid as u64),
                Arg::U(otn.sigInfo.sid as u64),
                Arg::U(otn.sigInfo.rev as u64),
                Arg::S(Some(svc.clone().into())),
            ],
        );
        let svcx = svc.clone();
        add_service_to_otn(log, br, otn, &svcx);
    }
    if otn.sigInfo.services.is_empty() && !multi_svc_buf.is_empty() {
        log.parse_warning(
            WARN_RULES,
            "%u:%u:%u has no service with %s",
            &[
                Arg::U(otn.sigInfo.gid as u64),
                Arg::U(otn.sigInfo.sid as u64),
                Arg::U(otn.sigInfo.rev as u64),
                Arg::S(Some(multi_svc_buf.clone().into())),
            ],
        );
        let msb = multi_svc_buf.clone();
        add_default_services(log, br, otn, &msb);
    }
    if let Some(g) = guess
        && otn.sigInfo.services.is_empty() {
            log.parse_warning(
            WARN_RULES,
            "%u:%u:%u has no service with %s option",
            &[
                Arg::U(otn.sigInfo.gid as u64),
                Arg::U(otn.sigInfo.sid as u64),
                Arg::U(otn.sigInfo.rev as u64),
                Arg::S(Some(g.into())),
            ],
        );
        add_service_to_otn(log, br, otn, g);
        }
}
