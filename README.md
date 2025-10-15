# scadex
SCADEX: ICS/SCADA Protocol ScannerSCADEX is a high-speed, multi-threaded C program designed for identifying Industrial Control Systems (ICS) and Supervisory Control and Data Acquisition (SCADA) devices by fingerprinting common industrial network protocols.The tool supports scanning IP ranges, CIDR blocks, and single IP addresses from an input file.⚠️ Disclaimer Indian Cyber Force is not responsible for any illegal or unauthorized activity conducted with this tool. This software is intended for educational, research, and legitimate penetration testing purposes only, conducted with explicit, written permission from the asset owner.✨ FeaturesMulti-Protocol Scan: Checks for four core ICS protocols in a single pass.High Performance: Uses POSIX multi-threading (pthreads) for rapid, concurrent scanning.Flexible Input: Accepts IPs, IP ranges (192.168.1.1-254), and CIDR notation (192.168.1.0/24).Protocol Selection: Allows users to specify which protocols to check.TXT Output: Saves detected SCADA/PLC systems to an output file.🛠️ Protocols SupportedProtocolPortDescriptionModbus/TCP502Used for querying Modbus holding registers.S7102Siemens S7 Communication, often for PLC discovery.BACnet47808 (UDP)Building Automation and Control Networks (BACnet).DNP320000Distributed Network Protocol (DNP3).🏗️ Building and CompilationSince SCADEX is written in C and utilizes POSIX threads, it requires a standard C compiler (like GCC or Clang) and the pthread library.PrerequisitesA POSIX-compliant operating system (Linux, macOS, etc.).GCC (GNU Compiler Collection) or Clang.CompilationCompile the source file using the -lpthread flag to link the threading library:# Compile the source file (assuming the filename is scanner.c)
gcc -o scadex scanner.c -lpthread

# Make the binary executable
chmod +x scadex
🚀 UsageThe tool requires an input file (-i) containing the list of targets.ArgumentsFlagArgumentDescriptionDefault-i<file>REQUIRED. Input file containing IPs, CIDRs, or ranges.N/A-t<number>Number of threads to use for scanning (max 100).20-o<file>Output file to save detected SCADA targets (IP,Protocol).N/A-vN/AVerbose mode. Prints all IPs, even if no SCADA service is found.Disabled-p<list>Comma-separated list of protocols to scan (modbus,s7,bacnet,dnp3).All-hN/ADisplay help message.N/AExample ScanCreate an input file (targets.txt):192.168.1.1-192.168.1.100
10.0.0.0/24
172.16.1.5
Run the scanner with 50 threads, checking only Modbus and S7, and saving the output:./scadex -i targets.txt -t 50 -p modbus,s7 -o scan_results.txt
Example Output (Console):============================
 SCADEX 
        bY Indian Cyber Force
============================
[Modbus] 192.168.1.5
[S7]     192.168.1.10
...
Scan Completed. Total 350 IP Processed
