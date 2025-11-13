# PSFree WebKit Exploit & Lapse Kernel Exploit for PS4

A PSFree & Lapse exploit for PS4 firmware 9.00
> ⚠️ This repository is for research and educational purposes only.

## Overview
This repository is a research-focused fork of [PSFree](https://github.com/kmeps4/PSFree) that aims to improve the reliability and success rate of existing public exploit code. The project’s main motivation is twofold:

1. **increase stability and success rate** through timing, error-handling and reliability improvements.

2. **reduce platform compatibility requirements** by converting the existing `.mjs` modular structure into plain `.js`. The result is less modular structure but is more portable codebase.

Through these changes, the original modular `.mjs` structure has been refactored into a single-file `.js` implementation designed to execute in a more sequential, `C-like` flow. This approach improves readability, simplifies debugging and ensures consistent execution timing across environments.

<p align="center">
  <img src="psfree_lapse.png" alt="PSFree" width="486" height="587"/>
</p>

---

## **Legal Notice & Disclaimer:**

- This repository does not host, or distribute any exploit hosting services
- Jailbreaking, circumventing security, or deploying exploits may be illegal in some jurisdictions.  
- It is your responsibility to ensure compliance with local laws.  
- The developer assumes **no responsibility** for any potential damage, data loss, or issues that may occur on your PlayStation console as a result of using this repository.  
- Use it at your own risk and only on your own devices.

## Major Changes

- **Removed all** `.mjs` **files** — converted the codebase to plain `.js` to improve cross-platform compatibility and simplify loading requirements.
- **Refactored for more sequential** `C-like` **execution** — code reorganized to follow a linear flow for easier reasoning, deterministic timing, and simpler debugging.
- **Rewrote** `Number.isInteger()` **implementation** — The original exploit implementation relied on `Number.isInteger()`, which I guess not fully supported in the PS4’s WebKit-based JavaScript environment (situated between `ES5` and `Partial ES6` compliance). To ensure consistent behavior across these runtimes, the function was rewritten using fundamental type and arithmetic checks. This guarantees proper integer validation even in restricted or legacy WebKit engines.
- **Improved GC handling with short delay** — added a small wait (≈50 ms) to certain `gc()` paths to stabilize memory reclamation timing.
- **Added initialization checks for variable operations** — guard checks ensure variables are initialized before use to prevent undefined-state failures.
- **Reordered and cleaned global variable initializations** — made global setup deterministic and reduced race conditions at startup.
- **Added parentheses to some of the logic expressions** — explicit grouping was added to prevent operator-precedence ambiguities and reduce logic errors.
- **Removed debugging logs** — cleaned up and commented out debugging logs to reduce side effects and improve runtime consistency.
- **Embedded** `.elf/.bin` **assets as hex arrays inside JS** — binary resources converted to in-file hex arrays to avoid read/load errors in constrained environments.
- **Replaced** `XMLHttpRequest()` **with** `fetch()`**/file reads** — modernized file-loading code for better compatibility and promise-based control flow.

## ToDo List

- Find an alternative (semi-modular) way to add firmware support

## Notes:

> All payload binaries (`*.bin`, `*.elf`) were intentionally excluded.
> Step-by-step jailbreak instructions were omitted for legal and ethical compliance.  
> No modifications that alter the exploit logic in ways affecting device security outside test context.

## Contributing

Contributions are welcome! Feel free to open pull requests for bug fixes, UI improvements, or additional features.

## License
This project continues under the same open-source license as the original PSFree repository (**AGPL-3.0**).  
Please review the [LICENSE](LICENSE) before redistributing or modifying the code.

## Acknowledgments

Special thanks to:

* [kmeps4](https://github.com/kmeps4) and [Al-Azif](https://github.com/Al-Azif) for their PSFree projects which inspired several improvements in this repo.

## Contact

For questions or issues, please open a GitHub issue on this repository.
