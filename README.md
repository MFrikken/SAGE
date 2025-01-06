<img src="src/resources/icons/sage-icon.png" width="128">

# SAST Assessment and Gathering Engine (SAGE)

SAGE is a simple Rust-based JSON parser especially designed for **Static Application Security Testing** (SAST) report files. It aims to make assessing your software security scans more comprehendable and efficient.


## Installation

*No officially released version yet*


## Usage

SAGE does not scan your codebase for security issues itself. It is a command-line tool that processes pre-generated SAST scan report files. It parses the vulnerabilities and their weaknesses from the report and loads them into an embedded database for easier analysis.

An example sast report file can be found [here](gl-sast-report.json).

To analyze a SAST report, run the executable from the command line and provide the path to your report file: 
```bash
SAGE.exe path/to/sast-report.json
```
### Note:
Commands for browsing the parsed data are currently under development and will be added in future updates.

## Contributing

Found a bug or have a feature request? Feel free to send me a direct message, and I'll open a ticket for it. Community contributions are also highly appreciated!

To contribute: 
1. Fork this repository.
2. Create a new branch for your feature or bug fix:
    ```bash
    git checkout -b feature/your-feature-name
    ```
3. Commit your changes with a descriptive message:
    ```bash
    git commit -m "Your message..."
    ```
4. Push to your fork:
    ```bash
    git push origin feature/your-feature-name
    ```
5. Open a pull request on the main repository.

### Guidelines

- Align your contributions with the project's goals and scope.
- Ensure your code adheres to Rust's coding standards.
- Avoid using `unwrap()` to prevent runtime panics; use safer alternatives like `match`, `if let`, or `?`.
- Do not use explicit lifetimes in this project, as they are unnecessary within its scope and can make the code more complex than required.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.