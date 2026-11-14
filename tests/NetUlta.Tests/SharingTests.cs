using NetUlta;
using System.Text;
using System.Text.Json;

static class SharingTests
{
    static void Check(bool ok, string name) { if (!ok) throw new Exception(name); Console.WriteLine("PASS: " + name); }
    static bool Reject(Action work) { try { work(); return false; } catch (UserFault) { return true; } }
    public static void Run()
    {
        string key = Convert.ToBase64String(new byte[32]);
        string config = "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = 127.0.0.1:1\n";
        var i = new Invitation(1, Guid.NewGuid().ToString("N"), "Synthetic recipient", "192.0.2.10", 22,
            "SHA256:" + key.TrimEnd('='), new string('x', 200), "", "", false, "127.0.0.1", 12345, "fixture:awg0", key, config);
        const string password = "synthetic password only";
        var encrypted = InvitationFile.Encrypt(i, password);
        Check(InvitationFile.Decrypt(encrypted, password) == i, "invitation encrypted roundtrip");
        Check(!Encoding.UTF8.GetString(encrypted).Contains(i.Host) && !Encoding.UTF8.GetString(encrypted).Contains("PrivateKey"), "invitation encrypts endpoints and credentials");
        Check(!encrypted.SequenceEqual(InvitationFile.Encrypt(i, password)), "invitation uses fresh salt and nonce");
        Check(Reject(() => InvitationFile.Decrypt(encrypted, "incorrect password")), "wrong invitation password rejected");
        var envelope = JsonSerializer.Deserialize<InvitationEnvelope>(encrypted)!;
        var cipher = Convert.FromBase64String(envelope.Ciphertext); cipher[0] ^= 1;
        var altered = JsonSerializer.SerializeToUtf8Bytes(envelope with { Ciphertext = Convert.ToBase64String(cipher) });
        Check(Reject(() => InvitationFile.Decrypt(altered, password)), "tampered invitation rejected");
        Check(Reject(() => InvitationFile.Decrypt(JsonSerializer.SerializeToUtf8Bytes(envelope with { Version = 99 }), password)), "unknown envelope version rejected");
        Check(Reject(() => InvitationFile.Encrypt(i, "short")), "weak invitation password refused");
        Check(Reject(() => InvitationFile.Encrypt(i with { VpnConfig = config + "PostUp = malicious\n" }, password)), "VPN hooks cannot enter invitation");
        Check(Reject(() => InvitationFile.Encrypt(i with { Fingerprint = "" }, password)), "unpinned invitation rejected");
        Check(Reject(() => InvitationFile.Decrypt(new byte[300000], password)), "oversized invitation rejected");
        Check(Reject(() => InvitationFile.Decrypt(Encoding.UTF8.GetBytes(new string(' ', 100) + "{}"), password)), "missing envelope fields rejected");
        Check(typeof(Invitation).GetProperties().All(p => !new[] { "ProtectedCredential", "GatewayAccountId", "GatewayTunnelId", "ApiToken", "Password", "AutoConnect", "ZapretPath" }.Contains(p.Name)), "transfer schema excludes owner administration and machine settings");
    }
}
