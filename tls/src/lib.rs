//! Process-local network observation, with optional exact-leaf TLS trust.
//! The optional pin supplies an anchor only when the server's complete DER leaf
//! matches a locally generated certificate. Security.framework still evaluates
//! validity and policy; no success result is fabricated and no system trust changes.
#![allow(non_snake_case)]
use std::ffi::{c_char, c_int, c_void, CStr};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex, OnceLock,
};
use std::time::{SystemTime, UNIX_EPOCH};

static OUTPUT: OnceLock<Option<Mutex<File>>> = OnceLock::new();
static EVENTS: AtomicUsize = AtomicUsize::new(0);
static PINNED_LEAF: OnceLock<Option<Vec<u8>>> = OnceLock::new();

extern "C" {
    fn __error() -> *mut c_int;
    fn getaddrinfo(
        node: *const c_char,
        service: *const c_char,
        hints: *const c_void,
        result: *mut *mut c_void,
    ) -> c_int;
    fn connect(fd: c_int, addr: *const u8, len: u32) -> c_int;
    fn connectx(
        fd: c_int,
        endpoints: *const Endpoints,
        assoc: u32,
        flags: u32,
        iov: *const c_void,
        iovcnt: u32,
        len: *mut usize,
        conn: *mut u32,
    ) -> c_int;
}
#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SSLSetPeerDomainName(context: *mut c_void, name: *const c_char, len: usize) -> i32;
    fn SSLHandshake(context: *mut c_void) -> i32;
    fn SecTrustEvaluate(trust: *mut c_void, result: *mut u32) -> i32;
    fn SecTrustSetAnchorCertificates(trust: *mut c_void, anchors: *const c_void) -> i32;
    fn SecTrustSetAnchorCertificatesOnly(trust: *mut c_void, only: u8) -> i32;
    fn SecTrustGetCertificateAtIndex(trust: *mut c_void, index: isize) -> *const c_void;
    fn SecCertificateCopyData(certificate: *const c_void) -> *const c_void;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFDataGetLength(data: *const c_void) -> isize;
    fn CFDataGetBytePtr(data: *const c_void) -> *const u8;
    fn CFArrayCreate(
        allocator: *const c_void,
        values: *const *const c_void,
        count: isize,
        callbacks: *const c_void,
    ) -> *const c_void;
    fn CFRelease(object: *const c_void);
    static kCFTypeArrayCallBacks: u8;
}

unsafe fn apply_exact_leaf_anchor(trust: *mut c_void) -> bool {
    let pin = PINNED_LEAF.get_or_init(|| {
        let path = std::env::var_os("WRATH_TLS_LEAF_DER")?;
        let bytes = std::fs::read(path).ok()?;
        if bytes.len() < 256 || bytes.len() > 32768 {
            return None;
        }
        Some(bytes)
    });
    let Some(pin) = pin else {
        return false;
    };
    let leaf = SecTrustGetCertificateAtIndex(trust, 0);
    if leaf.is_null() {
        return false;
    }
    let der = SecCertificateCopyData(leaf);
    if der.is_null() {
        return false;
    }
    let len = CFDataGetLength(der);
    let equal = len == pin.len() as isize
        && std::slice::from_raw_parts(CFDataGetBytePtr(der), len as usize) == pin;
    CFRelease(der);
    if !equal {
        return false;
    }
    let anchors = CFArrayCreate(
        std::ptr::null(),
        &leaf,
        1,
        (&kCFTypeArrayCallBacks as *const u8).cast(),
    );
    if anchors.is_null() {
        return false;
    }
    let status = SecTrustSetAnchorCertificates(trust, anchors);
    CFRelease(anchors);
    status == 0 && SecTrustSetAnchorCertificatesOnly(trust, 1) == 0
}

#[repr(C)]
struct Endpoints {
    srcif: u32,
    srcaddr: *const u8,
    srclen: u32,
    dstaddr: *const u8,
    dstlen: u32,
}

fn record(message: String) {
    if EVENTS.fetch_add(1, Ordering::Relaxed) >= 4000 {
        return;
    }
    let saved_errno = unsafe { *__error() };
    let output = OUTPUT.get_or_init(|| {
        let path = std::env::var_os("WRATH_NETWORK_LOG")?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .ok()
            .map(Mutex::new)
    });
    if let Some(output) = output {
        if let Ok(mut file) = output.lock() {
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let _ = writeln!(file, "{time} {message}");
        }
    }
    unsafe {
        *__error() = saved_errno;
    }
}

fn hostname(bytes: &[u8]) -> String {
    if bytes.len() > 253
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b".-:_".contains(b))
    {
        return "redacted".into();
    }
    let name = String::from_utf8_lossy(bytes);
    if name == "localhost"
        || name.ends_with(".localhost")
        || name.ends_with(".wow.test")
        || name.ends_with(".battle.net")
        || name.ends_with(".blizzard.com")
        || name.parse::<std::net::IpAddr>().is_ok()
    {
        name.into_owned()
    } else {
        "external_hostname".into()
    }
}

unsafe fn endpoint(addr: *const u8, len: u32) -> String {
    if addr.is_null() || len < 8 {
        return "unknown".into();
    }
    let data = std::slice::from_raw_parts(addr, len.min(128) as usize);
    let port = u16::from_be_bytes([data[2], data[3]]);
    match data[1] {
        2 => format!("{}.{}.{}.{}:{port}", data[4], data[5], data[6], data[7]),
        30 if data.len() >= 24 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[8..24]);
            format!("[{}]:{port}", std::net::Ipv6Addr::from(octets))
        }
        _ => "non_internet_socket".into(),
    }
}

unsafe extern "C" fn probe_getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const c_void,
    result: *mut *mut c_void,
) -> c_int {
    let host = if node.is_null() {
        "null".into()
    } else {
        hostname(CStr::from_ptr(node).to_bytes())
    };
    let rc = getaddrinfo(node, service, hints, result);
    record(format!("dns host={host} result={rc}"));
    rc
}
unsafe extern "C" fn probe_connect(fd: c_int, addr: *const u8, len: u32) -> c_int {
    let target = endpoint(addr, len);
    let rc = connect(fd, addr, len);
    let errno = *__error();
    record(format!(
        "connect fd={fd} target={target} result={rc} errno={errno}"
    ));
    rc
}
unsafe extern "C" fn probe_connectx(
    fd: c_int,
    ep: *const Endpoints,
    assoc: u32,
    flags: u32,
    iov: *const c_void,
    iovcnt: u32,
    len: *mut usize,
    conn: *mut u32,
) -> c_int {
    let target = if ep.is_null() {
        "unknown".into()
    } else {
        endpoint((*ep).dstaddr, (*ep).dstlen)
    };
    let rc = connectx(fd, ep, assoc, flags, iov, iovcnt, len, conn);
    let errno = *__error();
    record(format!(
        "connectx fd={fd} target={target} result={rc} errno={errno}"
    ));
    rc
}
unsafe extern "C" fn probe_peer(ctx: *mut c_void, name: *const c_char, len: usize) -> i32 {
    let host = if name.is_null() || len > 253 {
        "redacted".into()
    } else {
        hostname(std::slice::from_raw_parts(name.cast(), len))
    };
    let rc = SSLSetPeerDomainName(ctx, name, len);
    record(format!("tls_peer context={ctx:p} host={host} result={rc}"));
    rc
}
unsafe extern "C" fn probe_handshake(ctx: *mut c_void) -> i32 {
    let rc = SSLHandshake(ctx);
    if rc != -9803 {
        record(format!("tls_handshake context={ctx:p} result={rc}"));
    }
    rc
}
unsafe extern "C" fn probe_evaluate(trust: *mut c_void, result: *mut u32) -> i32 {
    let mut rc = SecTrustEvaluate(trust, result);
    if rc == 0 && !result.is_null() && *result == 5 && apply_exact_leaf_anchor(trust) {
        rc = SecTrustEvaluate(trust, result);
        record(format!(
            "exact_leaf_evaluated trust={trust:p} status={rc} result={}",
            *result
        ));
    }
    let value = if result.is_null() || rc != 0 {
        u32::MAX
    } else {
        *result
    };
    record(format!(
        "trust_evaluate trust={trust:p} status={rc} result={value}"
    ));
    rc
}
unsafe extern "C" fn probe_anchors(trust: *mut c_void, anchors: *const c_void) -> i32 {
    let rc = SecTrustSetAnchorCertificates(trust, anchors);
    record(format!(
        "trust_anchors trust={trust:p} supplied={} status={rc}",
        !anchors.is_null()
    ));
    rc
}
unsafe extern "C" fn probe_anchors_only(trust: *mut c_void, only: u8) -> i32 {
    let rc = SecTrustSetAnchorCertificatesOnly(trust, only);
    record(format!(
        "trust_anchors_only trust={trust:p} only={only} status={rc}"
    ));
    rc
}

#[repr(C)]
struct Interpose {
    replacement: *const c_void,
    original: *const c_void,
}
unsafe impl Sync for Interpose {}
macro_rules! interpose {
    ($name:ident,$replacement:ident,$original:ident) => {
        #[used]
        #[link_section = "__DATA,__interpose"]
        static $name: Interpose = Interpose {
            replacement: $replacement as *const c_void,
            original: $original as *const c_void,
        };
    };
}
interpose!(DNS, probe_getaddrinfo, getaddrinfo);
interpose!(CONNECT, probe_connect, connect);
interpose!(CONNECTX, probe_connectx, connectx);
interpose!(PEER, probe_peer, SSLSetPeerDomainName);
interpose!(HANDSHAKE, probe_handshake, SSLHandshake);
interpose!(EVALUATE, probe_evaluate, SecTrustEvaluate);
interpose!(ANCHORS, probe_anchors, SecTrustSetAnchorCertificates);
interpose!(
    ANCHORS_ONLY,
    probe_anchors_only,
    SecTrustSetAnchorCertificatesOnly
);

extern "C" fn init() {
    record("probe_ready".into());
}
#[used]
#[link_section = "__DATA,__mod_init_func"]
static INIT: extern "C" fn() = init;
