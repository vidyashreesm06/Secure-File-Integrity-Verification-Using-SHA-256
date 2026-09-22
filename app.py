import streamlit as st
import hashlib
import os
import re
import time
import difflib
import pandas as pd

from openpyxl import Workbook, load_workbook
from datetime import datetime


# =========================================================
# CONFIGURATION
# =========================================================

EXCEL_FILE = "file_database.xlsx"
ORIGINALS_FOLDER = "original_files"

os.makedirs(ORIGINALS_FOLDER, exist_ok=True)


# =========================================================
# SHA-256 CONSTANTS
# =========================================================

INITIAL_HASH = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19
]


K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEBFE3, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x8CC70208,
    0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70,
    0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585,
    0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C,
    0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F,
    0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814,
    0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
    0xC67178F2
]


# =========================================================
# SHA-256 INTERNAL FUNCTIONS
# =========================================================

def right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def ch(x, y, z):
    return (x & y) ^ (~x & z)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x):
    return (
        right_rotate(x, 2)
        ^ right_rotate(x, 13)
        ^ right_rotate(x, 22)
    )


def sigma1(x):
    return (
        right_rotate(x, 6)
        ^ right_rotate(x, 11)
        ^ right_rotate(x, 25)
    )


def small_sigma0(x):
    return (
        right_rotate(x, 7)
        ^ right_rotate(x, 18)
        ^ (x >> 3)
    )


def small_sigma1(x):
    return (
        right_rotate(x, 17)
        ^ right_rotate(x, 19)
        ^ (x >> 10)
    )


def sha256_padding(data):

    data = bytearray(data)

    original_length = len(data) * 8

    # Add 1 bit
    data.append(0x80)

    # Add zero bits until length is 448 mod 512
    while (len(data) * 8) % 512 != 448:
        data.append(0)

    # Add original length as 64-bit big endian
    data += original_length.to_bytes(8, "big")

    return bytes(data)


def create_message_schedule(block):

    W = []

    # First 16 words
    for i in range(16):

        word = int.from_bytes(
            block[i * 4:(i + 1) * 4],
            "big"
        )

        W.append(word)

    # Remaining 48 words
    for i in range(16, 64):

        value = (
            small_sigma1(W[i - 2])
            + W[i - 7]
            + small_sigma0(W[i - 15])
            + W[i - 16]
        ) & 0xFFFFFFFF

        W.append(value)

    return W


def educational_sha256(data):

    padded_data = sha256_padding(data)

    blocks = [
        padded_data[i:i + 64]
        for i in range(0, len(padded_data), 64)
    ]

    H = INITIAL_HASH.copy()

    all_blocks = []

    for block_number, block in enumerate(blocks, start=1):

        W = create_message_schedule(block)

        a, b, c, d, e, f, g, h = H

        rounds = []

        for t in range(64):

            T1 = (
                h
                + sigma1(e)
                + ch(e, f, g)
                + K[t]
                + W[t]
            ) & 0xFFFFFFFF

            T2 = (
                sigma0(a)
                + maj(a, b, c)
            ) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF

            rounds.append({
                "round": t + 1,
                "W": W[t],
                "K": K[t],
                "a": a,
                "b": b,
                "c": c,
                "d": d,
                "e": e,
                "f": f,
                "g": g,
                "h": h,
                "T1": T1,
                "T2": T2
            })

        H = [
            (H[0] + a) & 0xFFFFFFFF,
            (H[1] + b) & 0xFFFFFFFF,
            (H[2] + c) & 0xFFFFFFFF,
            (H[3] + d) & 0xFFFFFFFF,
            (H[4] + e) & 0xFFFFFFFF,
            (H[5] + f) & 0xFFFFFFFF,
            (H[6] + g) & 0xFFFFFFFF,
            (H[7] + h) & 0xFFFFFFFF
        ]

        all_blocks.append({
            "block": block_number,
            "data": block,
            "W": W,
            "rounds": rounds,
            "H": H.copy()
        })

    final_hash = "".join(
        f"{value:08x}" for value in H
    )

    return final_hash, padded_data, all_blocks


# =========================================================
# DATABASE
# =========================================================

def create_database():

    if not os.path.exists(EXCEL_FILE):

        workbook = Workbook()

        sheet = workbook.active
        sheet.title = "File Database"

        headers = [
            "File ID",
            "File Name",
            "File Size (KB)",
            "SHA-256 Hash",
            "Registered Date",
            "Last Verified",
            "Status",
            "Original File Path",
            "Verification Count"
        ]

        sheet.append(headers)

        workbook.save(EXCEL_FILE)


def calculate_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()


def safe_filename(filename):

    return re.sub(
        r'[<>:"/\\|?*]',
        "_",
        filename
    )


def register_file(filename, filesize, file_hash, file_data):

    workbook = load_workbook(EXCEL_FILE)
    sheet = workbook["File Database"]

    # Check duplicate filename
    for row in sheet.iter_rows(min_row=2, values_only=True):

        if row[1] == filename:
            return False

    file_id = sheet.max_row

    current_time = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    stored_filename = (
        str(file_id)
        + "_"
        + safe_filename(filename)
    )

    original_path = os.path.join(
        ORIGINALS_FOLDER,
        stored_filename
    )

    # Save original file
    with open(original_path, "wb") as f:
        f.write(file_data)

    sheet.append([
        file_id,
        filename,
        round(filesize / 1024, 2),
        file_hash,
        current_time,
        "Not Verified",
        "Registered",
        original_path,
        0
    ])

    workbook.save(EXCEL_FILE)

    return True


def get_file_record(filename):

    workbook = load_workbook(EXCEL_FILE)
    sheet = workbook["File Database"]

    for row in sheet.iter_rows(min_row=2):

        if row[1].value == filename:

            return {
                "row": row,
                "original_hash": row[3].value,
                "original_path": row[7].value,
                "verification_count": row[8].value or 0
            }

    return None


def verify_file(filename, current_hash):

    workbook = load_workbook(EXCEL_FILE)
    sheet = workbook["File Database"]

    for row in sheet.iter_rows(min_row=2):

        if row[1].value == filename:

            original_hash = row[3].value

            current_time = datetime.now().strftime(
                "%d-%m-%Y %H:%M:%S"
            )

            row[5].value = current_time

            old_count = row[8].value or 0
            row[8].value = old_count + 1

            if original_hash == current_hash:

                row[6].value = "Authentic"

                workbook.save(EXCEL_FILE)

                return True, original_hash, row[7].value

            else:

                row[6].value = "Modified"

                workbook.save(EXCEL_FILE)

                return False, original_hash, row[7].value

    return None, None, None


def read_database():

    workbook = load_workbook(EXCEL_FILE)

    sheet = workbook["File Database"]

    return list(sheet.values)


# =========================================================
# LINE-BY-LINE COMPARISON
# =========================================================

def is_text_file(filename):

    text_extensions = [
        ".txt",
        ".csv",
        ".py",
        ".java",
        ".c",
        ".cpp",
        ".html",
        ".css",
        ".js",
        ".json",
        ".xml",
        ".md",
        ".sql",
        ".log"
    ]

    extension = os.path.splitext(
        filename
    )[1].lower()

    return extension in text_extensions


def compare_text_files(original_data, current_data):

    try:

        original_text = original_data.decode(
            "utf-8"
        )

        current_text = current_data.decode(
            "utf-8"
        )

    except UnicodeDecodeError:

        return None

    original_lines = original_text.splitlines()
    current_lines = current_text.splitlines()

    matcher = difflib.SequenceMatcher(
        None,
        original_lines,
        current_lines
    )

    changes = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():

        if tag == "equal":
            continue

        # Replacement
        if tag == "replace":

            max_lines = max(
                i2 - i1,
                j2 - j1
            )

            for offset in range(max_lines):

                original_index = i1 + offset
                current_index = j1 + offset

                original_line = (
                    original_lines[original_index]
                    if original_index < i2
                    else "[Line removed]"
                )

                current_line = (
                    current_lines[current_index]
                    if current_index < j2
                    else "[Line removed]"
                )

                changes.append({
                    "line": current_index + 1,
                    "original": original_line,
                    "current": current_line
                })

        # Deleted lines
        elif tag == "delete":

            for index in range(i1, i2):

                changes.append({
                    "line": j1 + 1,
                    "original": original_lines[index],
                    "current": "[Line deleted]"
                })

        # Added lines
        elif tag == "insert":

            for index in range(j1, j2):

                changes.append({
                    "line": index + 1,
                    "original": "[New line]",
                    "current": current_lines[index]
                })

    return changes


# =========================================================
# HASH BIT DIFFERENCE
# =========================================================

def calculate_hash_difference(hash1, hash2):

    if not hash1 or not hash2:
        return 0, 0

    binary1 = bin(
        int(hash1, 16)
    )[2:].zfill(256)

    binary2 = bin(
        int(hash2, 16)
    )[2:].zfill(256)

    different_bits = sum(
        a != b
        for a, b in zip(binary1, binary2)
    )

    percentage = (
        different_bits / 256
    ) * 100

    return different_bits, percentage


# =========================================================
# CREATE DATABASE
# =========================================================

create_database()


# =========================================================
# STREAMLIT CONFIG
# =========================================================

st.set_page_config(
    page_title="Secure File Integrity Verifier",
    page_icon="🔐",
    layout="wide"
)


# =========================================================
# TITLE
# =========================================================

st.title(
    "🔐 Secure File Integrity Verifier"
)

st.write(
    "SHA-256 based system for detecting file modification, "
    "verifying file integrity and visualizing the internal "
    "SHA-256 process."
)

st.divider()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("📌 Navigation")

page = st.sidebar.radio(
    "Select Module",
    [
        "🏠 Dashboard",
        "📂 Register File",
        "🔍 Verify File",
        "📊 File Database",
        "🧪 SHA-256 Demo",
        "⚡ Avalanche Effect",
        "⚙️ SHA-256 Internal Process"
    ]
)


# =========================================================
# DASHBOARD
# =========================================================

if page == "🏠 Dashboard":

    st.header("🏠 Integrity Dashboard")

    data = read_database()

    if len(data) > 1:

        headers = data[0]
        rows = data[1:]

        dataframe = pd.DataFrame(
            rows,
            columns=headers
        )

        total_files = len(dataframe)

        authentic = len(
            dataframe[
                dataframe["Status"] == "Authentic"
            ]
        )

        modified = len(
            dataframe[
                dataframe["Status"] == "Modified"
            ]
        )

        registered = len(
            dataframe[
                dataframe["Status"] == "Registered"
            ]
        )

    else:

        total_files = 0
        authentic = 0
        modified = 0
        registered = 0

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "📁 Total Files",
            total_files
        )

    with col2:
        st.metric(
            "✅ Authentic",
            authentic
        )

    with col3:
        st.metric(
            "❌ Modified",
            modified
        )

    with col4:
        st.metric(
            "📝 Not Verified",
            registered
        )

    st.divider()

    st.subheader("🔄 System Workflow")

    st.code(
        """
Original File
      ↓
Generate SHA-256
      ↓
Store Hash + File
      ↓
Excel Database
      ↓
Upload File for Verification
      ↓
Generate Current SHA-256
      ↓
Compare Hashes
      ↓
 ┌───────────────┐
 │ Hashes Same?  │
 └───────────────┘
      ↓       ↓
     YES      NO
      ↓       ↓
 AUTHENTIC  MODIFIED
              ↓
       Compare Lines
              ↓
      Show Exact Changes
        """
    )

    st.info(
        "SHA-256 detects whether the file content has changed. "
        "For supported text files, the application also identifies "
        "the exact modified lines."
    )


# =========================================================
# REGISTER FILE
# =========================================================

elif page == "📂 Register File":

    st.header("📂 Register Original File")

    st.write(
        "Upload the original file. Its SHA-256 hash and a copy "
        "of the original file will be stored for future verification."
    )

    uploaded_file = st.file_uploader(
        "Choose Original File",
        type=None,
        key="register_file"
    )

    if uploaded_file:

        file_data = uploaded_file.getvalue()

        file_hash = calculate_hash(file_data)

        st.success(
            f"Selected: {uploaded_file.name}"
        )

        st.subheader("🔑 SHA-256 Hash")

        st.code(file_hash)

        col1, col2 = st.columns(2)

        with col1:

            st.metric(
                "File Size",
                f"{round(len(file_data) / 1024, 2)} KB"
            )

        with col2:

            st.metric(
                "Hash Length",
                "256 bits"
            )

        st.divider()

        if st.button(
            "🔒 Register File",
            use_container_width=True
        ):

            result = register_file(
                uploaded_file.name,
                len(file_data),
                file_hash,
                file_data
            )

            if result:

                st.success(
                    "✅ File successfully registered!"
                )

                st.info(
                    "The SHA-256 hash and original file "
                    "have been stored."
                )

            else:

                st.warning(
                    "⚠️ A file with this name is already registered."
                )


# =========================================================
# VERIFY FILE
# =========================================================

elif page == "🔍 Verify File":

    st.header("🔍 Verify File Integrity")

    st.write(
        "Upload a previously registered file to check "
        "whether it has been modified."
    )

    uploaded_file = st.file_uploader(
        "Choose File to Verify",
        type=None,
        key="verify_file"
    )

    if uploaded_file:

        file_data = uploaded_file.getvalue()

        current_hash = calculate_hash(file_data)

        st.subheader("🔑 Current SHA-256 Hash")

        st.code(current_hash)

        if st.button(
            "🔍 Verify File",
            use_container_width=True
        ):

            result, original_hash, original_path = verify_file(
                uploaded_file.name,
                current_hash
            )

            if result is None:

                st.warning(
                    "⚠️ File not found in the database."
                )

                st.info(
                    "Register the original file first."
                )

            elif result:

                st.success(
                    "✅ FILE IS AUTHENTIC"
                )

                st.write(
                    "The SHA-256 hash matches the original hash. "
                    "The file has not been modified."
                )

                different_bits, percentage = (
                    calculate_hash_difference(
                        original_hash,
                        current_hash
                    )
                )

                st.metric(
                    "Different Hash Bits",
                    f"{different_bits} / 256"
                )

            else:

                st.error(
                    "❌ FILE HAS BEEN MODIFIED"
                )

                st.write(
                    "The current SHA-256 hash does not match "
                    "the original hash."
                )

                # -----------------------------------------
                # HASH COMPARISON
                # -----------------------------------------

                st.subheader(
                    "📊 Hash Comparison"
                )

                col1, col2 = st.columns(2)

                with col1:

                    st.write("Original Hash")

                    st.code(original_hash)

                with col2:

                    st.write("Current Hash")

                    st.code(current_hash)

                different_bits, percentage = (
                    calculate_hash_difference(
                        original_hash,
                        current_hash
                    )
                )

                st.subheader(
                    "📈 Hash Difference Analysis"
                )

                col1, col2 = st.columns(2)

                with col1:

                    st.metric(
                        "Different Bits",
                        f"{different_bits} / 256"
                    )

                with col2:

                    st.metric(
                        "Hash Difference",
                        f"{percentage:.2f}%"
                    )

                # -----------------------------------------
                # EXACT LINE COMPARISON
                # -----------------------------------------

                if (
                    original_path
                    and os.path.exists(original_path)
                    and is_text_file(uploaded_file.name)
                ):

                    with open(
                        original_path,
                        "rb"
                    ) as f:

                        original_data = f.read()

                    changes = compare_text_files(
                        original_data,
                        file_data
                    )

                    st.divider()

                    st.subheader(
                        "📍 Exact Modified Lines"
                    )

                    if changes:

                        st.error(
                            f"🔴 {len(changes)} line-level "
                            f"change(s) detected."
                        )

                        for index, change in enumerate(
                            changes,
                            start=1
                        ):

                            with st.container(
                                border=True
                            ):

                                st.write(
                                    f"### Change {index} — "
                                    f"Line {change['line']}"
                                )

                                col1, col2 = st.columns(2)

                                with col1:

                                    st.write(
                                        "🔴 Original"
                                    )

                                    st.code(
                                        change["original"]
                                    )

                                with col2:

                                    st.write(
                                        "🟢 Current"
                                    )

                                    st.code(
                                        change["current"]
                                    )

                    else:

                        st.info(
                            "The file changed, but a line-level "
                            "difference could not be determined."
                        )

                elif not is_text_file(
                    uploaded_file.name
                ):

                    st.info(
                        "📄 Exact line comparison is available "
                        "for text-based files such as TXT, CSV, "
                        "PY, JAVA, HTML, CSS, JS and JSON."
                    )


# =========================================================
# FILE DATABASE
# =========================================================

elif page == "📊 File Database":

    st.header("📊 File Database")

    st.write(
        "Registered files and their SHA-256 integrity information."
    )

    data = read_database()

    if len(data) > 1:

        headers = data[0]
        rows = data[1:]

        dataframe = pd.DataFrame(
            rows,
            columns=headers
        )

        # Hide internal path from main display
        display_columns = [
            "File ID",
            "File Name",
            "File Size (KB)",
            "SHA-256 Hash",
            "Registered Date",
            "Last Verified",
            "Status",
            "Verification Count"
        ]

        st.dataframe(
            dataframe[display_columns],
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        with open(
            EXCEL_FILE,
            "rb"
        ) as file:

            excel_data = file.read()

        st.download_button(
            label="⬇️ Download Excel Database",
            data=excel_data,
            file_name="file_database.xlsx",
            mime=(
                "application/vnd.openxmlformats-"
                "officedocument.spreadsheetml.sheet"
            ),
            use_container_width=True
        )

    else:

        st.info(
            "No files have been registered yet."
        )


# =========================================================
# BASIC SHA-256 DEMO
# =========================================================

elif page == "🧪 SHA-256 Demo":

    st.header("🧪 Live SHA-256 Demonstration")

    st.write(
        "Change even one character and observe how "
        "the SHA-256 hash changes."
    )

    text = st.text_area(
        "Enter text",
        "Hello World"
    )

    if text:

        hash_value = hashlib.sha256(
            text.encode()
        ).hexdigest()

        st.subheader("Input")

        st.code(text)

        st.subheader("SHA-256 Output")

        st.code(hash_value)

        st.info(
            "💡 Try changing one character. "
            "The hash will change significantly."
        )


# =========================================================
# AVALANCHE EFFECT
# =========================================================

elif page == "⚡ Avalanche Effect":

    st.header("⚡ SHA-256 Avalanche Effect")

    st.write(
        "The avalanche effect demonstrates how a small change "
        "in the input can produce a substantially different hash."
    )

    col1, col2 = st.columns(2)

    with col1:

        text1 = st.text_area(
            "Original Input",
            "Hello World"
        )

    with col2:

        text2 = st.text_area(
            "Modified Input",
            "Hello world"
        )

    if text1 and text2:

        hash1 = hashlib.sha256(
            text1.encode()
        ).hexdigest()

        hash2 = hashlib.sha256(
            text2.encode()
        ).hexdigest()

        st.subheader("🔑 Hash Comparison")

        col1, col2 = st.columns(2)

        with col1:

            st.write("Original Hash")

            st.code(hash1)

        with col2:

            st.write("Modified Hash")

            st.code(hash2)

        different_bits, percentage = (
            calculate_hash_difference(
                hash1,
                hash2
            )
        )

        st.divider()

        col1, col2 = st.columns(2)

        with col1:

            st.metric(
                "Different Bits",
                f"{different_bits} / 256"
            )

        with col2:

            st.metric(
                "Hash Difference",
                f"{percentage:.2f}%"
            )

        st.info(
            "A small input change causes a large change "
            "in the SHA-256 output."
        )


# =========================================================
# SHA-256 INTERNAL PROCESS
# =========================================================

elif page == "⚙️ SHA-256 Internal Process":

    st.header(
        "⚙️ SHA-256 Internal Process Visualization"
    )

    st.write(
        "This module demonstrates the internal stages "
        "of the SHA-256 algorithm."
    )

    st.warning(
        "Educational visualization: the internal SHA-256 "
        "implementation is used to expose the processing "
        "steps and 64 rounds."
    )

    st.divider()

    uploaded_file = st.file_uploader(
        "📂 Choose a file to analyze",
        type=None,
        key="internal_file"
    )

    if uploaded_file:

        data = uploaded_file.getvalue()

        st.success(
            f"File selected: {uploaded_file.name}"
        )

        # ---------------------------------------------
        # FILE INFORMATION
        # ---------------------------------------------

        padded = sha256_padding(data)

        block_count = len(padded) // 64

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(
                "File Size",
                f"{len(data)} bytes"
            )

        with col2:

            st.metric(
                "Original Bits",
                len(data) * 8
            )

        with col3:

            st.metric(
                "512-bit Blocks",
                block_count
            )

        # ---------------------------------------------
        # STEP 1
        # ---------------------------------------------

        st.divider()

        st.subheader(
            "1️⃣ Input → Bytes"
        )

        st.code(
            " ".join(
                f"{b:02x}"
                for b in data[:32]
            )
        )

        if len(data) > 32:

            st.caption(
                f"Showing first 32 bytes of "
                f"{len(data)} total bytes."
            )

        # ---------------------------------------------
        # STEP 2
        # ---------------------------------------------

        st.subheader(
            "2️⃣ SHA-256 Padding"
        )

        st.write(
            f"Original size: **{len(data) * 8} bits**"
        )

        st.write(
            f"Padded size: **{len(padded) * 8} bits**"
        )

        st.code(
            " ".join(
                f"{b:02x}"
                for b in padded[:64]
            )
        )

        # ---------------------------------------------
        # STEP 3
        # ---------------------------------------------

        st.subheader(
            "3️⃣ 512-bit Message Block"
        )

        st.code(
            " ".join(
                f"{b:02x}"
                for b in padded[:64]
            )
        )

        st.caption(
            "64 bytes × 8 = 512 bits"
        )

        # ---------------------------------------------
        # CALCULATE EDUCATIONAL SHA
        # ---------------------------------------------

        final_hash, padded_data, all_blocks = (
            educational_sha256(data)
        )

        # ---------------------------------------------
        # STEP 4
        # ---------------------------------------------

        st.subheader(
            "4️⃣ Message Schedule W[0] → W[63]"
        )

        first_schedule = all_blocks[0]["W"]

        schedule_data = []

        for i, value in enumerate(
            first_schedule
        ):

            schedule_data.append({
                "Word": f"W[{i}]",
                "32-bit Value": f"{value:08x}"
            })

        schedule_df = pd.DataFrame(
            schedule_data
        )

        st.dataframe(
            schedule_df,
            use_container_width=True,
            hide_index=True
        )

        # ---------------------------------------------
        # STEP 5
        # ---------------------------------------------

        st.subheader(
            "5️⃣ 64 SHA-256 Rounds"
        )

        st.write(
            """
            Each 512-bit block is processed through
            64 rounds. The eight working variables
            are:
            """
        )

        st.code(
            "a   b   c   d   e   f   g   h"
        )

        speed = st.slider(
            "⏱️ Round visualization speed",
            min_value=0.01,
            max_value=0.5,
            value=0.05,
            step=0.01
        )

        start = st.button(
            "▶ Start 64-Round SHA-256 Process",
            use_container_width=True
        )

        if start:

            progress = st.progress(0)

            round_placeholder = st.empty()

            state_placeholder = st.empty()

            calculation_placeholder = st.empty()

            rounds = all_blocks[0]["rounds"]

            for round_data in rounds:

                round_number = round_data["round"]

                progress.progress(
                    round_number / 64
                )

                round_placeholder.subheader(
                    f"🔄 Round {round_number} / 64"
                )

                state_df = pd.DataFrame({
                    "Variable": [
                        "a",
                        "b",
                        "c",
                        "d",
                        "e",
                        "f",
                        "g",
                        "h"
                    ],

                    "32-bit Value": [
                        f"{round_data['a']:08x}",
                        f"{round_data['b']:08x}",
                        f"{round_data['c']:08x}",
                        f"{round_data['d']:08x}",
                        f"{round_data['e']:08x}",
                        f"{round_data['f']:08x}",
                        f"{round_data['g']:08x}",
                        f"{round_data['h']:08x}"
                    ]
                })

                state_placeholder.dataframe(
                    state_df,
                    use_container_width=True,
                    hide_index=True
                )

                calculation_placeholder.code(
                    f"""
W[{round_number - 1}] =
{round_data['W']:08x}

K[{round_number - 1}] =
{round_data['K']:08x}

T1 =
{round_data['T1']:08x}

T2 =
{round_data['T2']:08x}
"""
                )

                time.sleep(speed)

            progress.progress(1.0)

            round_placeholder.success(
                "✅ All 64 SHA-256 rounds completed!"
            )

            # -----------------------------------------
            # FINAL HASH
            # -----------------------------------------

            st.divider()

            st.subheader(
                "6️⃣ Final 256-bit SHA-256 Hash"
            )

            st.code(
                final_hash
            )

            st.metric(
                "Hash Length",
                "256 bits / 32 bytes / 64 hexadecimal characters"
            )

            # -----------------------------------------
            # VALIDATION
            # -----------------------------------------

            standard_hash = hashlib.sha256(
                data
            ).hexdigest()

            if final_hash == standard_hash:

                st.success(
                    "✅ Educational SHA-256 result matches "
                    "Python's standard SHA-256 result."
                )

            else:

                st.error(
                    "❌ SHA-256 implementation mismatch."
                )

            # -----------------------------------------
            # EXPLANATION
            # -----------------------------------------

            st.divider()

            st.subheader(
                "🧠 What Happened?"
            )

            st.write(
                """
                1. The file was converted into bytes.

                2. SHA-256 padding was added.

                3. The data was divided into 512-bit blocks.

                4. Each block was expanded into 64 message words.

                5. Each block was processed through 64 rounds.

                6. The internal hash state was updated.

                7. The final result was a 256-bit SHA-256 hash.
                """
            )

            st.info(
                "🔐 SHA-256 is a one-way cryptographic hash. "
                "It does not encrypt or decrypt the original file."
            )