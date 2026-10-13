# Security

tauri-audit only reads files. It never executes your project code, makes network calls, or writes outside the paths you pass with `-o`, `--badge` and `--write-baseline`.

If you find a way to make it do otherwise, or a rule that gives dangerously wrong advice, open a private security advisory on the GitHub repository (Security tab). Please do not post exploit details in a public issue first.

Reports of missed risks or false positives are normal bugs: use public issues for those.
