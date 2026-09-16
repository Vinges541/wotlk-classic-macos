"""One opt-in game account per server, stored only in the macOS login Keychain."""
import ctypes as C
import hashlib
import json
import platform


def service(profile):
    legacy = profile["LegacyServerOptions"]
    endpoint = [legacy["Address"].lower().rstrip("."), int(legacy["Port"]), str(legacy["Build"])]
    digest = hashlib.sha256(json.dumps(endpoint).encode()).hexdigest()
    return ("dev.wotlk-classic-macos.account." + digest).encode()


class Keychain:
    def __init__(self):
        if platform.system() != "Darwin":
            raise RuntimeError("Saved login requires macOS Keychain.")
        self.sec = C.CDLL("/System/Library/Frameworks/Security.framework/Security")
        self.cf = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.cf.CFRelease.argtypes = [C.c_void_p]
        signatures = {
            "SecKeychainFindGenericPassword": [C.c_void_p, C.c_uint32, C.c_char_p, C.c_uint32, C.c_char_p, C.POINTER(C.c_uint32), C.POINTER(C.c_void_p), C.POINTER(C.c_void_p)],
            "SecKeychainAddGenericPassword": [C.c_void_p, C.c_uint32, C.c_char_p, C.c_uint32, C.c_char_p, C.c_uint32, C.c_void_p, C.POINTER(C.c_void_p)],
            "SecKeychainItemModifyAttributesAndData": [C.c_void_p, C.c_void_p, C.c_uint32, C.c_void_p],
            "SecKeychainItemFreeContent": [C.c_void_p, C.c_void_p],
            "SecKeychainItemDelete": [C.c_void_p],
        }
        for name, args in signatures.items():
            fn = getattr(self.sec, name)
            fn.argtypes, fn.restype = args, C.c_int32

    @staticmethod
    def check(status):
        if status:
            raise RuntimeError(f"Keychain operation failed (OSStatus {status}).")

    def find(self, name, read=False):
        length, data, item = C.c_uint32(), C.c_void_p(), C.c_void_p()
        status = self.sec.SecKeychainFindGenericPassword(
            None, len(name), name, 7, b"default",
            C.byref(length) if read else None, C.byref(data) if read else None,
            C.byref(item),
        )
        if status == -25300:
            return None, None
        self.check(status)
        try:
            value = C.string_at(data, length.value) if read else None
        finally:
            if data:
                self.sec.SecKeychainItemFreeContent(None, data)
        return item, value

    def read(self, name):
        item, value = self.find(name, read=True)
        if item is None:
            return None
        try:
            result = json.loads(value)
            if not isinstance(result, dict) or set(result) != {"username", "password"} or not all(isinstance(v, str) and v for v in result.values()):
                raise ValueError
            self.validate(result["username"], result["password"])
            return result
        except (ValueError, TypeError):
            raise RuntimeError("Saved game account is invalid; save it again.") from None
        finally:
            self.cf.CFRelease(item)

    @staticmethod
    def validate(username, password):
        if (not username.strip() or not password or len(username.upper().encode("utf-8")) > 640
                or len(password) > 4096 or any(c in username for c in "\x00\r\n")):
            raise ValueError("Enter a nonempty game account and password.")

    def save(self, name, username, password):
        self.validate(username, password)
        value = json.dumps({"username": username.strip(), "password": password}).encode()
        item, _ = self.find(name)
        try:
            if item is None:
                self.check(self.sec.SecKeychainAddGenericPassword(None, len(name), name, 7, b"default", len(value), value, None))
            else:
                self.check(self.sec.SecKeychainItemModifyAttributesAndData(item, None, len(value), value))
        finally:
            if item:
                self.cf.CFRelease(item)

    def delete(self, name):
        item, _ = self.find(name)
        if item:
            try:
                self.check(self.sec.SecKeychainItemDelete(item))
            finally:
                self.cf.CFRelease(item)
