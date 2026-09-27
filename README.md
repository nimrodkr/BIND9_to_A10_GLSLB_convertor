# BIND9 to A10 GSLB Converter

Convert BIND9 DNS zone files into A10 GSLB CLI configuration. The combined converter handles forward zones and IPv4 reverse zones, writes one aggregated CLI file, and produces a conversion report. A Tkinter desktop GUI is also included.

> **Review before deployment:** Generated CLI is a starting point. Review it against your A10 software version, partition and naming conventions, and test it in a non-production environment before applying it. The scripts include example A10 values; update them to match your environment.

## Features

- Detects forward and IPv4 reverse zones from each zone file's `$ORIGIN`.
- Converts supported records into A10 GSLB CLI configuration.
- Combines converted zones into a single CLI file.
- Writes per-zone CLI files for troubleshooting when enabled.
- Produces a text report and CSV summary with converted, skipped, or failed zones.
- Provides a GUI for choosing folders and setting A10 names and device details.

IPv6 reverse zones are currently skipped by the combined converter. Unsupported records and parse issues may be reported; inspect the report and generated CLI before use.

## Files

| File | Purpose |
| --- | --- |
| `GUI_bind_to_a10_gslb.py` | Tkinter GUI for the combined converter. Keep it beside the converter script. |
| `combined_bind_to_a10_gslb_converter.py` | Main combined converter; supports command-line execution and can be imported by the GUI. |
| `CLI_bind_to_a10_gslb_converter.py` | Earlier reverse-zone-focused command-line converter. |

For normal use, start with the combined converter and its GUI. The other two scripts are retained as earlier alternatives and may have different behavior.

## Requirements

- Python 3.9 or newer is recommended.
- The combined converter uses only Python's standard library.
- The GUI requires Tkinter. On some Linux distributions, Tkinter is a separate operating-system package.

No connection to an A10 device is made. The program generates CLI text files for you to review and apply separately.

## Quick start: GUI

Place the two combined scripts in the same directory
- GUI_bind_to_a10_gslb.py
- combined_bind_to_a10_gslb_converter.py
Create a directory such as "zones" and place your BIND9 config .zone files in it (see sample zones)
Then run:

```bash
python3 GUI_bind_to_a10_gslb.py
```

In the window:

1. Select the input folder containing your BIND zone files.
2. Choose output and report folders.
3. Review the class-list, partition, site, device, and policy values.
4. Choose whether to write per-zone CLI files, then click **RUN**.
5. Review the conversion summary, report, and CLI output before using them.

The input folder must contain `.zone` files directly inside it; files in nested folders are not scanned.

## Quick start: command line

The converter's default input, output, and report folders are `zones/`, `output/`, and `reports/` beside the converter script. Create `zones/` and put your `.zone` files there, then run:

```bash
python3 CLI_bind_to_a10_gslb_converter.py
```

The CLI script uses those default paths and has no command-line options. To use different paths or A10 values from Python, import `convert()` and pass the corresponding keyword arguments; see the function definition in the script.

## Output

The combined converter writes:

- `output/combined_zones.cli` — aggregated A10 CLI configuration.
- `output/<zone-name>.cli` — per-zone CLI files when the debug option is enabled (enabled by default in the CLI script).
- `reports/conversion_report.txt` — human-readable results and warnings.
- `reports/conversion_summary.csv` — one status row per input zone.

The GUI lets you choose the output and report folders. It uses the same converter and output formats.

## Configuration defaults

The converter defines example values near the top of `combined_bind_to_a10_gslb_converter_v01.py`, including the class list, partition, site, device name and IP, and policy names. Change these defaults in the script when running the CLI directly. In the GUI, enter the appropriate values before conversion.

The service port, protocol, service-IP prefix, TTL, and output mode are also converter defaults. The GUI currently uses these values without exposing them as fields.

## Zone file notes

- Provide standard BIND master-file text with a `$ORIGIN` directive.
- Each input filename must end in `.zone` (case-sensitive), and the file must be directly in the selected input folder.
- Forward zones and IPv4 reverse zones (`in-addr.arpa`) are handled by the combined converter.
- IPv6 reverse zones (`ip6.arpa`) are skipped.
- Review warnings and failed or skipped entries in `conversion_report.txt` and `conversion_summary.csv`.

## Safety and privacy

Zone files can contain internal hostnames, addresses, and other sensitive network information. Do not commit real zone files or generated configurations to a public repository. Use sanitized sample data if you want to demonstrate the converter. Review every generated command before applying it to an A10 device.

## License

No license is currently specified. Add a `LICENSE` file before others reuse, modify, or redistribute this project.
