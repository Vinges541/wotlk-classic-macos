using System.Diagnostics;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

if (args.Length == 1 && args[0] == "self-test")
{
    if (!OperatingSystem.IsWindows()) return 2;
    Credentials.SelfTest();
    Console.WriteLine("Windows Credential Manager and DPAPI round trips passed.");
    return 0;
}

if (args.Length != 2 || args[0] is not ("remember" or "forget" or "run"))
{
    Console.Error.WriteLine("Usage: WrathLogin remember|forget|run installation.json");
    return 2;
}
if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("Windows is required.");
    return 2;
}
try
{
    using var config = JsonDocument.Parse(File.ReadAllText(args[1]));
    var root = config.RootElement;
    var endpoint = root.GetProperty("server").GetString()!.ToLowerInvariant().TrimEnd('.') + ":" + root.GetProperty("auth_port").GetInt32();
    var credentialName = "WotLKClassicHermes/" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(endpoint)));
    if (args[0] == "remember")
    {
        Console.Write("Server account: ");
        var username = Console.ReadLine()?.Trim() ?? "";
        Console.Write("Password: ");
        var password = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace) { if (password.Length > 0) password.Length--; }
            else if (!char.IsControl(key.KeyChar)) password.Append(key.KeyChar);
        }
        Console.WriteLine();
        if (username.Length == 0 || password.Length == 0 || Encoding.UTF8.GetByteCount(username) > 640)
            throw new InvalidOperationException("Enter a nonempty account and password.");
        Credentials.Save(credentialName, username, password.ToString());
        password.Clear();
        Console.WriteLine("Account saved in Windows Credential Manager.");
        return 0;
    }
    if (args[0] == "forget")
    {
        Credentials.Delete(credentialName);
        Console.WriteLine("Saved account removed.");
        return 0;
    }
    using var mutex = new Mutex(false, @"Local\WotLKClassicHermesLauncher");
    bool acquired;
    try { acquired = mutex.WaitOne(0); } catch (AbandonedMutexException) { acquired = true; }
    if (!acquired) throw new InvalidOperationException("Another launcher is running.");
    try
    {
        var executable = Path.Combine(root.GetProperty("target").GetString()!, "_classic_", "WowClassic.exe");
        if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable))).ToLowerInvariant() != root.GetProperty("hashes").GetProperty("client").GetString())
            throw new InvalidOperationException("Client hash mismatch.");
        var start = new ProcessStartInfo(executable) { WorkingDirectory = Path.GetDirectoryName(executable)!, UseShellExecute = false };
        // This path is also substituted by the build-specific PE patcher.
        const string loginPath = @"Software\WotLK HermesProxy\Battle.net\Launch Options\WoW";
        var saved = Credentials.Read(credentialName);
        using var registry = Registry.CurrentUser.CreateSubKey(loginPath, true);
        void ClearTicket()
        {
            foreach (var name in new[] { "WEB_TOKEN", "GAME_ACCOUNT", "CONNECTION_STRING" }) registry.DeleteValue(name, false);
        }
        ClearTicket();
        try
        {
            if (saved is not null)
            {
                var locale = root.GetProperty("locale").GetString()!;
                if (!Regex.IsMatch(locale, "^[a-z]{2}[A-Z]{2}$")) throw new InvalidOperationException("Invalid locale.");
                using var certificate = X509CertificateLoader.LoadPkcs12FromFile(root.GetProperty("certificate_pfx").GetString()!, null);
                var pinned = certificate.GetCertHash(HashAlgorithmName.SHA256);
                using var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false };
                handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert is not null && CryptographicOperations.FixedTimeEquals(cert.GetCertHash(HashAlgorithmName.SHA256), pinned);
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
                var body = JsonSerializer.Serialize(new { inputs = new[] {
                    new { input_id = "account_name", value = saved.Value.User },
                    new { input_id = "password", value = saved.Value.Password } } });
                using var response = await http.PostAsync($"https://127.0.0.1:8081/bnetserver/login/Wn64/54261/{locale}/", new StringContent(body, Encoding.UTF8, "application/json"));
                response.EnsureSuccessStatusCode();
                var raw = await response.Content.ReadAsByteArrayAsync();
                if (raw.Length > 65536) throw new InvalidOperationException("Invalid login response.");
                using var result = JsonDocument.Parse(raw);
                var ticket = result.RootElement.GetProperty("login_ticket").GetString()!;
                if (result.RootElement.GetProperty("authentication_state").GetString() != "DONE" || !Regex.IsMatch(ticket, "^HP-[0-9A-Fa-f]{40}$"))
                    throw new InvalidOperationException("Server rejected saved credentials.");
                // Current-user DPAPI, as consumed by the Windows launcher-login path.
                registry.SetValue("WEB_TOKEN", Credentials.Protect(Encoding.UTF8.GetBytes(ticket)), RegistryValueKind.Binary);
                registry.SetValue("GAME_ACCOUNT", saved.Value.User.ToUpperInvariant(), RegistryValueKind.String);
                registry.SetValue("CONNECTION_STRING", "127.0.0.1:1119", RegistryValueKind.String);
                start.ArgumentList.Add("-launcherlogin");
            }
            using var game = Process.Start(start) ?? throw new InvalidOperationException("Client did not start.");
            var exited = game.WaitForExitAsync();
            await Task.WhenAny(exited, Task.Delay(TimeSpan.FromMinutes(2)));
            ClearTicket();
            await exited;
            return game.ExitCode;
        }
        finally { ClearTicket(); }
    }
    finally { mutex.ReleaseMutex(); }
}
catch
{
    // Exceptions from HTTP or credential APIs must never print secrets or response bodies.
    Console.Error.WriteLine("Login/launch failed. Check the bridge, or save your server account again.");
    return 1;
}

static class Credentials
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct Credential
    {
        public uint Flags, Type;
        public string TargetName, Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint BlobSize;
        public IntPtr Blob;
        public uint Persist, AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias, UserName;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Blob { public int Length; public IntPtr Data; }
    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CredWriteW(ref Credential value, uint flags);
    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CredReadW(string target, uint type, uint flags, out IntPtr value);
    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CredDeleteW(string target, uint type, uint flags);
    [DllImport("advapi32")] static extern void CredFree(IntPtr value);
    [DllImport("crypt32", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32")] static extern IntPtr LocalFree(IntPtr value);
    public static void SelfTest()
    {
        var name = "WotLKClassicHermes/Test/" + Guid.NewGuid();
        try
        {
            Save(name, "test-account", "synthetic-test-value");
            var saved = Read(name);
            if (saved?.User != "test-account" || saved?.Password != "synthetic-test-value") throw new InvalidOperationException("Credential round trip failed");
            Delete(name);
            if (Read(name) is not null) throw new InvalidOperationException("Credential delete failed");
            var encrypted = Protect(Encoding.UTF8.GetBytes("synthetic-ticket"));
            var ptr = Marshal.AllocHGlobal(encrypted.Length);
            try
            {
                Marshal.Copy(encrypted, 0, ptr, encrypted.Length);
                var input = new Blob { Length = encrypted.Length, Data = ptr };
                if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out var output)) throw new InvalidOperationException("DPAPI decrypt failed");
                try
                {
                    if (Marshal.PtrToStringUTF8(output.Data, output.Length) != "synthetic-ticket") throw new InvalidOperationException("DPAPI round trip failed");
                }
                finally { LocalFree(output.Data); }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }
        finally { Delete(name); }
    }
    public static void Save(string name, string user, string password)
    {
        var bytes = Encoding.Unicode.GetBytes(password);
        if (bytes.Length > 2560) throw new InvalidOperationException("Password too long.");
        var ptr = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            var value = new Credential { Type = 1, TargetName = name, UserName = user, BlobSize = (uint)bytes.Length, Blob = ptr, Persist = 2, Comment = "WotLK private server account", TargetAlias = "" };
            if (!CredWriteW(ref value, 0)) throw new InvalidOperationException("Credential write failed.");
        }
        finally { CryptographicOperations.ZeroMemory(bytes); Marshal.Copy(bytes, 0, ptr, bytes.Length); Marshal.FreeHGlobal(ptr); }
    }
    public static (string User, string Password)? Read(string name)
    {
        if (!CredReadW(name, 1, 0, out var ptr))
        {
            if (Marshal.GetLastWin32Error() == 1168) return null;
            throw new InvalidOperationException("Credential read failed.");
        }
        try
        {
            var value = Marshal.PtrToStructure<Credential>(ptr);
            return (value.UserName, Marshal.PtrToStringUni(value.Blob, (int)value.BlobSize / 2)!);
        }
        finally { CredFree(ptr); }
    }
    public static void Delete(string name)
    {
        if (!CredDeleteW(name, 1, 0) && Marshal.GetLastWin32Error() != 1168) throw new InvalidOperationException("Credential delete failed.");
    }
    public static byte[] Protect(byte[] data)
    {
        var ptr = Marshal.AllocHGlobal(data.Length);
        try
        {
            Marshal.Copy(data, 0, ptr, data.Length);
            var input = new Blob { Length = data.Length, Data = ptr };
            if (!CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out var output)) throw new InvalidOperationException("Ticket protection failed.");
            try { var result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, result.Length); return result; }
            finally { LocalFree(output.Data); }
        }
        finally { CryptographicOperations.ZeroMemory(data); Marshal.Copy(data, 0, ptr, data.Length); Marshal.FreeHGlobal(ptr); }
    }
}
