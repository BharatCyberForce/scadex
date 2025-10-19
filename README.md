# SCADEX 

![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Language](https://img.shields.io/badge/language-C-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Author](https://img.shields.io/badge/author-Indian%20Cyber%20Force-red.svg)

---

Industrial Control System Protocol Scanner!

scadex is a **multi threaded Industrial Control System network scanner** designed to identify ICS protocols running on IP hosts.
---

## Features

- 🔍 Detects multiple **ICS protocols**:
  - **Modbus/TCP (502)**
  - **Siemens S7 (102)**
  - **BACnet/IP (47808)**
  - **DNP3 (20000)**
- **Multi-threaded scanning** for high performance  
- Supports **IP lists, CIDR notations**, and **IP ranges**  
- Optional **CSV output** for logging discovered hosts
- High Accuracy
---

## Build Instructions

### Requirements

- GCC or Clang (C compiler)
- POSIX environment (Linux, BSD, macOS)

### Compilation

```bash
gcc -o scadex scadex.c -lpthread
````

### 🧪 Run Example

```bash
./scadex -i targets.txt -t 50 -o results.csv -v -p modbus,s7,bacnet,dnp3
```

---

## Command Options

| Option           | Description                                                                  |
| :--------------- | :--------------------------------------------------------------------------- |
| `-i <file>`      | Input file containing IPs, ranges, or CIDR blocks *(required)*               |
| `-t <threads>`   | Number of concurrent threads *(default: 20, max: 100)*                       |
| `-o <file>`      | Output CSV file for detected services                                        |
| `-v`             | Verbose mode (shows all scanned IPs, even those without detections  )        |
| `-p <protocols>` | Comma-separated list of protocols to scan (`modbus`, `s7`, `bacnet`, `dnp3`) |
| `-h`             | Display usage information                                                    |

---

## Future

* Add more ICS/SCADA protocols
* Add banner grabbing / version detection

---

### Example Usage

| Command                                | Description                       |
| -------------------------------------- | --------------------------------- |
| `./scadex -i iplist.txt`               | Scan all default ICS protocols    |
| `./scadex -i ips.txt -p modbus`        | Scan only Modbus devices          |
| `./scadex -i network.txt -t 100 -v`    | Run verbose scan with 100 threads |
| `./scadex -i targets.txt -o found.csv` | Save detected hosts to CSV        |



⚠️ Disclaimer Indian Cyber Force is not responsible for any illegal or unauthorized activity
