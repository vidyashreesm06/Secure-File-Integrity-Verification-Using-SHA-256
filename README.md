[README(1).md](https://github.com/user-attachments/files/32505783/README.1.md)
# Secure File Integrity Verification Using SHA-256

A Streamlit-based file integrity verification system that uses the
SHA-256 cryptographic hashing algorithm to detect file modification or
tampering.

## Features

-   Register original files and generate SHA-256 hashes.
-   Store file details and hashes in an Excel database.
-   Verify files by comparing their current hash with the original hash.
-   Detect modified files.
-   Show exact modified lines for supported text files.
-   Calculate hash-bit differences.
-   Demonstrate the SHA-256 avalanche effect.
-   Generate SHA-256 hashes for text or files.
-   Visualize SHA-256 padding, 512-bit blocks, message schedule, and 64
    rounds.
-   View and download the Excel file database.
-   Dashboard showing file integrity status.

## Technology Stack

-   Python 3.11.9
-   Streamlit
-   SHA-256
-   hashlib
-   OpenPyXL
-   Pandas
-   Microsoft Excel
-   Visual Studio Code

## Project Structure

``` text
FILE_Integration/
│
├── app.py
├── file_database.xlsx
├── original_files/
└── README.md
```

`file_database.xlsx` and the `original_files` folder are created/updated
by the application.

## Installation

### 1. Create and activate virtual environment

``` powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install required packages

``` powershell
python -m pip install streamlit pandas openpyxl
```

## Run the Application

``` powershell
python -m streamlit run app.py
```

Open the Local URL displayed by Streamlit, normally:

``` text
http://localhost:8501
```

## Application Modules

### 1. Dashboard

Displays the total number of registered files and their integrity
status.

### 2. Register File

Uploads an original file, calculates its SHA-256 hash, stores the
original file, and records the information in the Excel database.

### 3. Verify File

Calculates the current SHA-256 hash and compares it with the stored
original hash.

-   Same hash → File is Authentic
-   Different hash → File is Modified

For supported text files, the application also displays the exact
changed lines.

### 4. SHA-256 Hash Generator

Generates a SHA-256 hash from either text input or an uploaded file.

### 5. Avalanche Effect

Demonstrates how changing a small part of the input can produce a
significantly different SHA-256 hash. It displays the number and
percentage of different hash bits.

### 6. SHA-256 Internal Process

Provides an educational visualization of:

``` text
Input
  ↓
Bytes
  ↓
Padding
  ↓
512-bit Blocks
  ↓
Message Schedule W[0] - W[63]
  ↓
64 Rounds
  ↓
256-bit Hash
```

The internal implementation is also checked against Python's standard
SHA-256 result.

### 7. File Database

Displays registered file information and provides an option to download
the Excel database.

## Supported Line Comparison Files

Exact line-level comparison is available for common text files such as:

-   TXT
-   CSV
-   Python
-   Java
-   C/C++
-   HTML
-   CSS
-   JavaScript
-   JSON
-   XML
-   Markdown
-   SQL
-   LOG

For binary files such as images, videos, ZIP files, and executables,
SHA-256 can still detect modification, but line-level comparison is not
applicable.

## How File Verification Works

``` text
Original File
     ↓
SHA-256
     ↓
Original Hash
     ↓
Excel Database
     ↓
Current File
     ↓
SHA-256
     ↓
Current Hash
     ↓
Compare
   /     \
Same    Different
 ↓          ↓
Authentic  Modified
             ↓
       Line Comparison
```

## Important Note

SHA-256 is a cryptographic hashing algorithm, not an encryption
algorithm. It produces a fixed 256-bit hash and does not provide a
method for decrypting or recovering the original file.

## Project Purpose

The project demonstrates how cryptographic hashing can be used to
maintain and verify file integrity and how SHA-256 processes data
internally.
