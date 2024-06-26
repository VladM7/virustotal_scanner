# VirusTotal Scanner

Simple application to scan files with VirusTotal API, accessible via CLI.

## Description

This script is used for interfacing with the VirusTotal API to submit files for scanning and retrieving the analysis results in a convenient way, via a command-line interface (CLI). It's designed to be both efficient in its operation and user-friendly, offering clear feedback and guidance on the results of scans.

## Getting started

### Dependencies

- Python 3.12
- `pyinstaller` module

### Installing

To store the API key you will need to create the `.env` file in the root directory of the project with the following content:

```env
API_KEY=<your_api_key>
```

Then, you can directly run the Python file:

```shell
python -u "scanner.py"
```

Or build the project using `pyinstaller`:

- Compile the Python file

```shell
pyinstaller --onefile scanner.py
```

- Run the resulting `.exe` file, which will be stored in the `dist/` directory.

```shell
cd ./dist
scanner.exe
```

### Help

For information about the usage of the script, including the command-line arguments that can be used, run:

```shell
scanner -h
```

## Author

@VladM7

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

This project was built using the [VirusTotal API v3](https://docs.virustotal.com/reference/overview).
