# bftp
Data diode written in Python for sending files over a one-way fibre optic connection to an airgapped computer.

Loosely based on BlindFTP from https://adullact.net/projects/blindftp/ but with a fair amount of rewriting and enhancements.

##  Hardware requirements:

- Two computers with fibre network cards
- rx of low side connected to something that always transmits e.g. a copper to fibre media converter (most fibre cards will not transmit unless they see light on the receive side)
- tx of low side connected to rx of high side with a single fibre strand
- tx of high side left unconnected
- You may require specific network cards and/or driver versions as some cards aren't happy unless both fibres are connected in the normal way

## How to run:

- Start bftp server on the high side computer:
  - `python3 bftp_receive.py -a <IP address to listen on> <path to write received files to>`
- Start bftp client on the low side computer:
  - Add an ARP entry so the low side knows the MAC address of the high side
    - e.g. on Windows: `arp -s <high side IP> <high side MAC> <low side IP>`
  - `python3 bftp_send.py -t <directory to scan for new files> -a <high side IP> -b`
- Client will now run in a loop scanning the input directory and sending files as they appear. Directory structures are also preserved, so an entire directory tree can be dropped into the input directory and will then be recreated accurately on the high side.
- Note that when using the -b switch (loop continually) files are removed from the input directory after they have been sent. Alternatively use either -s or -t without also adding -b to run as a one-shot operation without deleting and then terminate.
