# cloudflare-ping-application-systems

- It a small Ping CLI application for MacOS or Linux. The CLI app accepts a hostname or an IP address as its argument, then send ICMP "echo requests" in a loop to the target while receiving "echo reply" messages. It reports loss and RTT times for each sent message.

- The Ping Code is written in 'C' language

- It add support for both IPv4 and IPv6
- It allow to set TTL as an argument and report the corresponding "time exceeded” ICMP messages
