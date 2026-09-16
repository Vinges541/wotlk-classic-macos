//! Expose the launcher's ephemeral ticket through the client's existing preference API.
use super::{c_void, Interpose};
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::OnceLock;
use std::time::Duration;

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFDataCreate(allocator: *const c_void, bytes: *const u8, size: isize) -> *const c_void;
    fn CFPreferencesCopyAppValue(key: *const c_void, app: *const c_void) -> *const c_void;
    fn CFStringGetCString(value: *const c_void, buffer: *mut u8, size: isize, encoding: u32) -> u8;
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        size: isize,
        encoding: u32,
        external: u8,
    ) -> *const c_void;
}

#[repr(C)]
struct CssmData {
    length: usize,
    data: *mut u8,
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn CSSM_DecryptData(
        context: u64,
        input: *const CssmData,
        input_count: u32,
        output: *mut CssmData,
        output_count: u32,
        output_length: *mut usize,
        remaining: *mut CssmData,
    ) -> i32;
    fn malloc(size: usize) -> *mut c_void;
}

const TOKEN_MARKER: &[u8; 64] = b"WrathClassic-IPC-Ticket-Only-000WrathClassic-IPC-Ticket-Only-000";

// The Mac launcher preference reader expects NSData and passes it to legacy CSSM.
// This marker belongs exclusively to our in-memory preference override. Adapt
// only that marker; forward every actual ciphertext to Security.framework.
unsafe extern "C" fn launcher_decrypt(
    context: u64,
    input: *const CssmData,
    input_count: u32,
    output: *mut CssmData,
    output_count: u32,
    output_length: *mut usize,
    remaining: *mut CssmData,
) -> i32 {
    if input_count == 1
        && !input.is_null()
        && (*input).length == TOKEN_MARKER.len()
        && !(*input).data.is_null()
        && std::slice::from_raw_parts((*input).data, (*input).length) == TOKEN_MARKER
    {
        if let Some(Some(login)) = TICKET.get() {
            if output_count != 1
                || output.is_null()
                || output_length.is_null()
                || remaining.is_null()
            {
                return -1;
            }
            if (*output).data.is_null() {
                // The client's CSSM allocator/free callbacks use libc malloc/free.
                (*output).data = malloc(login.ticket.len()).cast();
                (*output).length = login.ticket.len();
            }
            if (*output).data.is_null() || (*output).length < login.ticket.len() {
                return -1;
            }
            std::ptr::copy_nonoverlapping(
                login.ticket.as_ptr(),
                (*output).data,
                login.ticket.len(),
            );
            (*output).length = login.ticket.len();
            *output_length = login.ticket.len();
            (*remaining).length = 0;
            (*remaining).data = std::ptr::null_mut();
            super::record("launcher_ticket_unwrapped".into());
            return 0;
        }
    }
    CSSM_DecryptData(
        context,
        input,
        input_count,
        output,
        output_count,
        output_length,
        remaining,
    )
}

#[used]
#[link_section = "__DATA,__interpose"]
static LAUNCHER_DECRYPT: Interpose = Interpose {
    replacement: launcher_decrypt as *const c_void,
    original: CSSM_DecryptData as *const c_void,
};

struct Login {
    ticket: Vec<u8>,
    account: Vec<u8>,
}
static TICKET: OnceLock<Option<Login>> = OnceLock::new();

fn receive() -> Option<Login> {
    let path = std::env::var_os("WRATH_LOGIN_SOCKET")?;
    let stream = UnixStream::connect(path).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut bytes = Vec::new();
    stream.take(1025).read_to_end(&mut bytes).ok()?;
    if bytes.len() < 45
        || bytes.len() > 684
        || bytes[43] != b'\n'
        || !bytes.starts_with(b"HP-")
        || !bytes[3..43].iter().all(u8::is_ascii_hexdigit)
        || bytes[44..].iter().any(|b| matches!(b, 0 | 10 | 13))
        || std::str::from_utf8(&bytes[44..]).is_err()
    {
        return None;
    }
    super::record("launcher_ticket_received".into());
    Some(Login {
        ticket: bytes[..43].to_vec(),
        account: bytes[44..].to_vec(),
    })
}

unsafe extern "C" fn launcher_preference(key: *const c_void, app: *const c_void) -> *const c_void {
    let mut domain = [0u8; 128];
    let local_login = !app.is_null()
        && std::env::var_os("WRATH_LOGIN_SOCKET").is_some()
        && CFStringGetCString(app, domain.as_mut_ptr(), domain.len() as isize, 0x08000100) != 0
        && domain.starts_with(b"net.battle\0");
    if !key.is_null() && local_login {
        let mut name = [0u8; 128];
        if CFStringGetCString(key, name.as_mut_ptr(), name.len() as isize, 0x08000100) != 0 {
            let name = &name[..name.iter().position(|b| *b == 0).unwrap_or(name.len())];
            if name == b"Launch Options/WoW/CONNECTION_STRING" {
                super::record("launcher_local_endpoint_supplied".into());
                let value = b"localhost.:1119";
                return CFStringCreateWithBytes(
                    std::ptr::null(),
                    value.as_ptr(),
                    value.len() as isize,
                    0x08000100,
                    0,
                );
            }
            if name == b"Launch Options/WoW/WEB_TOKEN" || name == b"Launch Options/WoW/GAME_ACCOUNT"
            {
                if let Some(login) = TICKET.get_or_init(receive) {
                    if name.ends_with(b"WEB_TOKEN") {
                        super::record("launcher_web_token_supplied".into());
                        return CFDataCreate(
                            std::ptr::null(),
                            TOKEN_MARKER.as_ptr(),
                            TOKEN_MARKER.len() as isize,
                        );
                    }
                    let value = &login.account;
                    super::record("launcher_game_account_supplied".into());
                    return CFStringCreateWithBytes(
                        std::ptr::null(),
                        value.as_ptr(),
                        value.len() as isize,
                        0x08000100,
                        0,
                    );
                }
                // Never use an unrelated Battle.net credential if IPC fails.
                return std::ptr::null();
            }
        }
    }
    CFPreferencesCopyAppValue(key, app)
}

#[used]
#[link_section = "__DATA,__interpose"]
static LAUNCHER_PREFERENCE: Interpose = Interpose {
    replacement: launcher_preference as *const c_void,
    original: CFPreferencesCopyAppValue as *const c_void,
};
