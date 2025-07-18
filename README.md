# AWS Auth CLI

A command-line tool to manage AWS IAM user credentials.

## Quick Start

### Download & Install

1.  **Download the executable:**
    *   For macOS: [Link to macOS executable] (Replace with actual download link)
    *   For Windows: [Link to Windows executable] (Replace with actual download link)
    *   For Linux: [Link to Linux executable] (Replace with actual download link)
2.  **Place in your PATH:** Move the downloaded `awsauth` executable to a directory included in your system's `PATH` (e.g., `/usr/local/bin` on macOS/Linux, or a directory added to PATH on Windows).

### Usage

Once installed, open your terminal and run:

```bash
awsauth --help
```

This will display the available commands: `check`, `status`, `rotate-key`, and `change-password`.

### Uninstallation

To uninstall `awsauth`, simply remove the executable file from your system.

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

## Building from Source (Optional)


If you prefer to build from source or contribute:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/awsauth.git # Replace with actual repo URL
    cd awsauth
    ```
2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```
3.  **Install dependencies:**
    ```bash
    pip install .
    ```
4.  **Run tests:**
    ```bash
    pytest
    ```
5.  **Run the application:**
    ```bash
    .venv/bin/awsauth --help
    ```