
# VulnFanatic (2.1)
Author: **Martin Petran**

_Binary Ninja assistant plugin for vulnerability research._

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

Example of discovered issue:

![Sample](https://github.com/Martyx00/VulnFanatic/blob/master/static/sample.png?raw=true "Sample")


## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 2263

## License

This plugin is released under an Apache license.

## Support

Help improve the plugin by creating a new issue for whatever troubles you!

*or*

<a href="https://www.buymeacoffee.com/VulnFanatic" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>