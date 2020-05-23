
# VulnFanatic (v2.0)
Author: **Martin Petran**

_Assistant plugin for vulnerability research._

## Description:
This plugin aims to assist during the vulnerability research process by providing a full tracing of sources of parameters to selected functions. It also provides a scanning capability which uses the function tracer and applies several rules to detect potentially dangerous function calls. 

### Highlighter

The highlighter part of the plugin can be used by selecting a function call and using the option `[VulnFanatic] Highlight parameters` to highlight important parts which influence the parameters to the highlighted function call. To remove this highlight use option `[VulnFanatic] Clear highlighted parameters`.

### Scanner 

Scanner is using set of rules and function tracker to perform basic analysis to detect any potentially vulnerable function calls. Issues that are found by this component are marked with tags that reflect the priority for a follow-up manual analysis. Following are the priority categories:

* 🔴 High - Detected conditions are likely to lead to vulnerability.
* 🟠 Medium - Detected conditions could theoretically lead to vulnerability.
* 🟡 Low - Detected conditions are unlikely to lead to vulnerability.
* 🔵 Info - Detected conditions were not clear enough to determine if the call is secure or not.

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 2000

## License

This plugin is released under an Apache license.
