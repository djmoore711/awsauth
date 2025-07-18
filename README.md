# AWS Auth CLI

A command-line tool to manage AWS IAM user credentials.

## Quick Start

### Installation

To use the `awsauth` CLI, you can build it from source. Standalone executables for various operating systems are not yet provided but may be available in future releases.

### Building from Source

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/djmoore711/awsauth.git
    cd awsauth
    ```
2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```
3.  **Install dependencies:**
    ```bash
    .venv/bin/pip install .
    ```

### Usage

Once installed, open your terminal and run:

```bash
awsauth --help
```

This will display the available commands. For detailed help on any command, use `awsauth <command> --help`.

**Examples:**

*   **Check all profiles:**
    ```bash
    awsauth check
    ```
    or
    ```bash
    awsauth check all
    ```

*   **Check a specific profile:**
    ```bash
    awsauth check default
    ```

*   **Get status of all profiles:**
    ```bash
    awsauth status
    ```

*   **Get status of a specific profile:**
    ```bash
    awsauth status default
    ```

### Uninstallation

To uninstall `awsauth` when installed from source, deactivate your virtual environment and remove the project directory:

```bash
deactivate # if your virtual environment is active
rm -rf ~/Code/awsauth
```

If you installed a standalone executable (not yet provided, but for future reference), simply remove the executable file from your system.

1.  **Locate the executable:** Find where you placed the `awsauth` executable (e.g., `/usr/local/bin/awsauth`).
2.  **Delete the file:**
    *   **macOS/Linux:**
        ```bash
        rm /path/to/awsauth
        ```
    *   **Windows:** Delete the `awsauth.exe` file from File Explorer, or use the `del` command in Command Prompt:
        ```cmd
        del C:\path\to\awsauth.exe
        ```
    **Caution:** Be careful when using `rm` or `del` as they permanently delete files. Ensure you are deleting the correct file.

