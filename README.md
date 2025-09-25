# 🔒 Ethical Port Scanner

This project is an ethical-by-default port scanner designed for educational purposes and responsible network testing. It is built with a strong focus on preventing unauthorized scanning and demonstrating a commitment to ethical hacking principles.

The project was developed as part of a university project/internship to showcase a practical understanding of network programming and cybersecurity fundamentals.

## ✨ Key Features

- **Ethical-by-Default:** The scanner is hardcoded to only scan loopback (`127.0.0.1`) and private IP addresses by default.
- **Explicit Target Whitelisting:** To scan any public IP or domain, the user must explicitly add that target to the `allowed_targets.txt` file, providing a clear audit trail and preventing accidental misuse.
- **Clear User Warnings:** The program provides a clear warning and detailed instructions before any scan, reinforcing ethical use.
- **Simple & Fast:** Uses Python's `socket` library and `ThreadPoolExecutor` for efficient, multithreaded port scanning.

## 🚀 How to Use

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/your-username/ethical-port-scanner.git](https://github.com/your-username/ethical-port-scanner.git)
    cd ethical-port-scanner
    ```

2.  **Install Dependencies:**
    This project uses standard Python libraries. No extra installation is required.

3.  **Run the Scanner:**
    ```bash
    python port_scanner_safe.py
    ```

4.  **Provide a Target:**
    Follow the prompts to enter a target domain or IP. If the target is not a private IP, you will be prompted to add it to the `allowed_targets.txt` file.

## 📄 File Structure

- `port_scanner_safe.py`: The main Python script containing the port scanning logic.
- `allowed_targets.txt`: A plain text file for whitelisting public targets.
- `README.md`: This file, providing an overview of the project.

## 🤝 Contribution

This project is open for improvement and collaboration. Feel free to fork the repository and submit pull requests.

---

**Disclaimer:** This tool is for educational purposes only. Use it responsibly and only on networks and devices you own or have explicit permission to test.
