# GUI translations

The GUI starts in English on every launch. Use the top-right selector to change
language without restarting or changing connection/action parameters. The CLI
and all diagnostic/flashing code remain unchanged.

Each UTF-8 `locales/<language-tag>.json` contains:

```json
{
  "name": "Language name shown in the selector",
  "translator": "Optional translator credit in the header and GUI log",
  "title_credit": "Optional credit appended to the window title",
  "strings": {
    "Detect VIN": "Translation of Detect VIN"
  },
  "logs": [
    {
      "source": "Found gateway {0} | VIN: {1}",
      "translation": "Translated gateway {0} | VIN: {1}"
    }
  ],
  "log_values": {
    "PRESENT": "Translated PRESENT"
  }
}
```

`strings` uses the original English text as the key. Preserve `%s` placeholders
in dialog messages. `logs` matches complete messages, optionally following an
`[HH:MM:SS]` timestamp; numbered fields must be sequential in the source and may
be reordered in the translation. Preserve every field. Templates are escaped
before matching, so they cannot supply regex code. `log_values` translates only
exact captured status values, never arbitrary substrings inside paths/commands.

Translated log messages retain their original English line prefixed with `[EN]`.
Unmatched logs, protocol dumps, remote script output and third-party errors stay
unchanged. Switching languages re-renders the original in-memory history.

`en.json` has no translator credit. The supplied `zh-CN.json` credits:
**抖音：小白科技杂物社 · BiliBili：小白151 · GitHub：JackieZ123430**.
Other languages can provide their own optional credits. English presentation
suppresses credits even if they are accidentally added to `en.json`.

Add a JSON file and restart the source GUI, or rebuild with `build_exe.bat`.
`MGU-SSH.spec` bundles the whole directory relative to `i18n.py`, including for
PyInstaller's one-folder layout. No additional runtime dependencies are needed.

Run the offline checks from the repository root:

```sh
python -m unittest discover -s tests -v
```

GUI tests use Tk and mocked operations: they do not contact a gateway or vehicle.
