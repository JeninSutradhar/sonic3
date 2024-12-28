# Sonic3
A GUI application Built with Go and the Fyne UI toolkit for file compression, decompression, archiving, and extraction, designed for speed and efficiency.

<p align="center">
  <img src="https://github.com/user-attachments/assets/3129879a-d070-4029-b6f1-dd34c1258c60" alt="Screenshot_20241228_102517" width=400>
</p>


## Features

*   **Multiple Operation Modes:**
    *   **Compress:** Compress individual files or directories.
    *   **Decompress:** Decompress supported compressed files.
    *   **Archive:** Create archives (ZIP, TAR.GZ, TAR.XZ) from multiple files and directories.
    *   **Extract:** Extract files from supported archives.
*   **Wide Range of Compression Algorithms:**
    *   Gzip
    *   Zstandard (Zstd)
    *   LZ4
    *   S2 (Snappy)
    *   No Compression
*   **Supported Archive Formats:**
    *   ZIP
    *   TAR.GZ
    *   TAR.XZ
    *   *(7z - Placeholder, planned for future implementation)*
*   **Encryption:** Secure your compressed or archived files with password-based encryption using Argon2 for key derivation and AES-GCM for symmetric encryption.
*   **Checksum Verification:** Calculate and verify file integrity using MD5 or CRC32 checksums.
*   **Cross-Platform:** Runs on Windows, macOS, and Linux.

## Screenshots


## Getting Started

### Prerequisites

*   [Go](https://go.dev/dl/) (version 1.18 or higher)

### Installation

**Method 1: Download Pre-built Binaries (Recommended)**

Go to the [Releases](https://github.com/jeninsutradhar/sonic3/releases) page and download the appropriate executable for your operating system.

**Method 2: Build from Source**

1. Clone the repository:
    ```bash
    git clone https://github.com/jeninsutradhar/sonic3.git
    cd sonic3
    ```
2. Build the application:
    ```bash
    go build -v ./...
    ```
    This will create an executable file named `archiver` (or `archiver.exe` on Windows) in the project directory.

### Usage

1. Run the executable file.
2. Select the desired **Mode** of operation (Compress, Decompress, Archive, Extract).
3. Choose the **Algorithm** for compression (if applicable).
4. Select the **Archive Format** (if you are archiving or extracting).
5. Choose the **Checksum Algorithm** for integrity verification.
6. Click the "Select Input File(s)" or "Select Input Folder(s)" button to choose the files or directories you want to process.
7. Click the "Select Output Path" or "Select Output Folder" button to specify where the output file or extracted files should be saved.
8. Enter a **Password** if you want to encrypt the output.
9. Configure advanced settings like "Compress Directory," "Number of Routines," and algorithm-specific parameters if needed.
10. Click the "Start" button to begin the operation.
11. A progress bar will show the status of the operation. Logs and completion messages will be displayed in the output area.

## Configuration Options

*   **Mode:** The operation to perform (Compress, Decompress, Archive, Extract).
*   **Algorithm:** The compression algorithm to use (for compress and archive modes).
*   **Archive Format:** The format of the archive to create or extract (for archive and extract modes).
*   **Checksum Algorithm:** The algorithm used to calculate and verify file integrity.
*   **Input:** The file(s) or folder(s) to process.
*   **Output:** The destination path for the output file or extracted files.
*   **Password:** A password to encrypt/decrypt the output.
*   **Compress Directory:** (For Compress mode) Check this option to compress an entire directory into a single compressed file.
*   **Number of Routines:** The number of CPU threads to use for parallel processing (may improve performance).
*   **Zstd Level:** The compression level for the Zstandard algorithm (higher levels offer better compression but may take longer).
*   **Argon2 Memory (KB):** The amount of memory (in kilobytes) used by the Argon2 key derivation function. Higher values increase security but require more resources.
*   **Argon2 Time:** The number of iterations used by the Argon2 key derivation function. Higher values increase security but take longer.
*   **Argon2 Threads:** The number of threads used by the Argon2 key derivation function.

## Contributing

Contributions are welcome! Please feel free to open issues for bug reports or feature requests, or submit pull requests with your improvements.
***
**⚠️ WARNING: This project is currently under active development.**
Please be aware that this software is still in development and may contain bugs or unexpected behavior. There can be a risk of:

*   **Data Corruption:** Files may be corrupted during compression, decompression, archiving, or extraction.
*   **Incompatibility:** Compressed or archived files created with this application may not be compatible with other archivers or decompression tools.
***

## License
This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

*   Built using the excellent [Fyne](https://fyne.io/) UI toolkit.
*   Uses the following great Go libraries for compression:
    *   [klauspost/compress](https://github.com/klauspost/compress) for Zstandard and S2.
    *   [pierrec/lz4/v4](https://github.com/pierrec/lz4/v4) for LZ4.
    *   [ulikunitz/xz](https://github.com/ulikunitz/xz) for XZ.
*   Uses [golang.org/x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2) for secure password hashing.
 
