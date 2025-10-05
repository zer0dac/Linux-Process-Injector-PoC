
# Disclaimer:
This tool is intended for educational and ethical hacking purposes only. Always obtain permission before testing any system or application. The developers are not responsible for any misuse or damage caused by this tool.

# Usage

Environment Setup:

<img width="715" height="61" alt="image" src="https://github.com/user-attachments/assets/a7ad4d9e-0c4e-4a03-aceb-a20c30f4e244" />

Creating Payload:

<img width="733" height="299" alt="image" src="https://github.com/user-attachments/assets/9e4a78ed-a230-410b-84e6-dc211e1215f3" />

We applied -e x64/xor encoding to obfuscate the payload. This makes it harder for signature-based security tools (like antivirus or intrusion detection systems) to detect the
shellcode. Simple XOR encoding also ensures low overhead compared to more complex encoders.


Executing victim process:
The vulnerable_process is running as expected and remains in an active state, providing the necessary output:

<img width="775" height="98" alt="image" src="https://github.com/user-attachments/assets/bfeacd04-e413-4b59-82d9-f3e80cc8a073" />

If we don’t have these values, we could still locate the process using:
* ps aux | grep vulnerable_process – To find the process ID and verify its status.
* cat /proc/<PID>/maps – To check memory mappings and identify a writable and executable memory region.

On the attacker machine a Metasploit listener was set up:

<img width="776" height="109" alt="image" src="https://github.com/user-attachments/assets/cb2329a6-a84a-470a-850f-c8a992a45dc3" />
<img width="780" height="37" alt="image" src="https://github.com/user-attachments/assets/49ac9ee0-d6a2-42a3-a2b8-db550e0113b8" />

Executing Exploit:

<img width="776" height="130" alt="image" src="https://github.com/user-attachments/assets/a16d00ec-0883-4794-822a-ed199c1f1a85" />
<img width="594" height="350" alt="image" src="https://github.com/user-attachments/assets/bb760933-6015-487a-8bd9-faa1e1525983" />
