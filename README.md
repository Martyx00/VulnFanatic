# VulnFanatic (3.2)

Author: **Martin Petran**

_Binary Ninja assistant plugin for vulnerability research._

## Description:
This plugin aims to assist during the vulnerability research process by providing a capability to scan the binary for potential occurrences of known vulnerabilities such as Use-after-free, buffer overflow or format string related issues. Along with the scanner, this plugin also includes a simple highlighter tool which should provide further aid during the follow-up manual analysis of the issues found by teh scanner.

### Highlighter

The highlighter part of the plugin can be used after selecting an instruction. This feature allows you to highlight Assembly and HLIL blocks that lead to current block. Another feature also allows you to highlight either HLIL or Assembly variables. This provides ability to trace all points of interest for given variables.

### Scanner 

Scanner is using set of rules to perform basic analysis to detect any potentially vulnerable function calls. Issues that are found by this component are marked with tags that reflect the priority for a follow-up manual analysis. Following are the priority categories:

* 🔴 High - Detected conditions are likely to lead to vulnerability.
* 🟠 Medium - Detected conditions could theoretically lead to vulnerability.
* 🟡 Low - Detected conditions are unlikely to lead to vulnerability.
* 🔵 Info - Detected conditions were not clear enough to determine if the call is secure or not.

Example of discovered issue:

![Sample](https://github.com/Martyx00/VulnFanatic/blob/master/static/sample.png?raw=true "Sample")

Please note that by no means this plugin provides a zero effort way to find vulnerabilities. However, it should assist you in prioritizing specific places in binaries which are worth investigating.

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 2263

## License

This plugin is released under an Apache license.
