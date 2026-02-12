# Memory Dump Forensics Tool

A Python-based memory dump analysis tool built on top of the Volatility3 framework. This tool provides automated analysis of memory dumps with rich terminal output and comprehensive forensic capabilities.

## Features

### Core Analysis
- Process enumeration and analysis
- Network connection detection
- Operating system information extraction
- Command line argument reconstruction

### Advanced Forensics
- Windows services analysis
- DLL mapping and inspection
- Malicious memory section detection (using Malfind)
- Registry hive analysis
- Suspicious pattern detection

### Tool Features
- Rich terminal output with formatted tables
- Progress tracking for long operations
- Comprehensive logging
- Asynchronous operation for better performance
- Type-annotated codebase for reliability

## Requirements

- Python 3.8+
- Volatility3 framework
- Rich library for terminal output

## Installation

1. Clone this repository:
```bash
git clone https://github.com/AlephNullSK/memory-forensics-triage.git
cd memory-forensics-triage
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install volatility3 rich
```

## Usage

Basic usage:
```bash
python memory_forensics.py path/to/memory_dump
```

The tool will automatically:
1. Analyze the memory dump
2. Display progress bars for each analysis phase
3. Output formatted results to the terminal
4. Log all operations to `memory_analysis.log`

## Output Example

The tool provides detailed information in several categories:

```
=== Memory Dump Analysis Results ===

[Operating System Information]
- OS Version
- System Architecture
- Installation Time
- Other system details

[Process Information]
- Running processes
- Process hierarchy
- Start/Exit times
- Thread counts

[Network Information]
- Active connections
- Listening ports
- Connection states

[Services Information]
- Running services
- Service configurations
- Associated processes

[DLL Analysis]
- Loaded modules
- Base addresses
- File paths

[Suspicious Memory Sections]
- Potentially malicious regions
- Memory protection analysis
- Hexdumps of suspicious sections

[Registry Analysis]
- Active hives
- Last written times
- Registry paths
```

## Legal Considerations

This tool is intended for:
- Legitimate forensic investigation
- Incident response
- Security research
- Educational purposes

**Important:** Ensure you have proper authorization before analyzing any memory dumps. Unauthorized forensic analysis may be illegal in your jurisdiction.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

### Areas for Contribution
- Additional analysis modules
- Performance improvements
- Output format options
- New detection capabilities
- Documentation improvements

## Future Plans

- [ ] Timeline analysis
- [ ] String search capabilities
- [ ] File handles analysis
- [ ] User session information
- [ ] Environment variable analysis
- [ ] Export to common forensics formats

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Volatility Foundation for the Volatility3 framework
- Contributors to the Rich library
- All contributors to this project

## Security

If you discover any security-related issues, please email security@alephnull.sk instead of using the issue tracker.

## Contact

- Author: Aleph Null s.r.o.
- Website: https://alephnull.sk

## Disclaimer

This tool is provided "as is" without warranty of any kind. Use at your own risk. The authors are not responsible for any damage caused by the use of this tool.
