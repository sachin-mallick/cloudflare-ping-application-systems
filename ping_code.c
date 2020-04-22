#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>

#define DEFAULT_PACKET_SIZE 56
#define RECV_TIMEOUT 1
#define TTL 'T'

int ping_flag = 1;
int ipv4_flag = 0;
int ipv6_flag = 0;
int ttl_flag = 0;
int default_ttl = 54;


void interrupt_handler(int x) {
    ping_flag = 0;
}

unsigned short checksum(void *b, int len) 
{   unsigned short *buf = b; 
    unsigned int sum=0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 

void ping(int sock_fd, struct sockaddr *sa_dest, char* ip_addr) 
{
    int ttl = default_ttl;
    int seq = 0;
    int packets_recieved = 0;

    struct icmp icmp_hdr;
    struct icmp6_hdr icmp_hdr_6;

    struct sockaddr_in sa_from;
    struct timespec start_time, end_time;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;
    long double rtt = 0;

    if (ttl <= 0) {
        printf("Time Exceeded. TTL less than or equal to 0\n");
        return;
    }
    // Setting the TTL value for the system
    if (setsockopt(sock_fd, SOL_SOCKET, IP_TTL,
                    &ttl, sizeof(ttl)) != 0)
    {
        printf("Error with setsockopt\n");
    }

    // Setting timeout of the system
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO,
                    (const char*)&tv_out, sizeof(tv_out)))
    {
        printf("Error with setsockopt setting timeout\n");
    }  
    
    while (ping_flag) {
        memset(&icmp_hdr, 0, sizeof(icmp_hdr));
        memset(&icmp_hdr_6, 0, sizeof(icmp_hdr_6));
        
        if (ipv4_flag == 0 && ipv6_flag == 1) {
            icmp_hdr_6.icmp6_type = ICMP6_ECHO_REQUEST;
            icmp_hdr_6.icmp6_code = 0;
            icmp_hdr_6.icmp6_cksum = 0;
            icmp_hdr_6.icmp6_id = getpid();
            icmp_hdr_6.icmp6_seq = seq;

            usleep(1000000);

            clock_gettime(CLOCK_MONOTONIC, &start_time);
            if (sendto(sock_fd, &icmp_hdr_6, sizeof(icmp_hdr_6), 0, sa_dest, sizeof(struct sockaddr_in6)) <= 0) 
            {
                printf("Error with sendto()\n");
                printf("%s\n",strerror(errno));
                return;
            }

            socklen_t addr_len = sizeof(sa_from);

            if (recvfrom(sock_fd, &icmp_hdr_6, sizeof(icmp_hdr_6), 0, (struct sockaddr*)&sa_from, &addr_len) <= 0)
            {
                printf("Error with recvfrom\n");
                return;
            }
        }
        else {
            icmp_hdr.icmp_type = ICMP_ECHO;
            icmp_hdr.icmp_hun.ih_idseq.icd_id = getpid();
            icmp_hdr.icmp_hun.ih_idseq.icd_seq = seq;
            icmp_hdr.icmp_cksum = checksum(&icmp_hdr, sizeof(icmp_hdr));

            usleep(1000000);

            clock_gettime(CLOCK_MONOTONIC, &start_time);
            if (sendto(sock_fd, &icmp_hdr, sizeof(icmp_hdr), 0, sa_dest, sizeof(sa_dest)) <= 0) 
            {
                printf("Error with sendto()\n");
                printf("%s\n",strerror(errno));
                return;
            }

            socklen_t addr_len = sizeof(sa_from);

            if (recvfrom(sock_fd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr*)&sa_from, &addr_len) <= 0)
            {
                printf("Error with recvfrom\n");
                return;
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &end_time);
        double timeElapsed = ((double)(end_time.tv_nsec -  start_time.tv_nsec))/1000000.0;
        rtt = (end_time.tv_sec-start_time.tv_sec) * 1000.0 + timeElapsed;
        printf("%d %s %s:", 64, "bytes from", ip_addr); // Report bytes and IP address
        printf("%s=%d", " icmp_seq", seq);                // Report icmp_seq
        printf("%s=%d", " ttl", default_ttl);             // Report TTL
        printf("%s %.3Lf %s\n", " rtt =", rtt, "ms"); // Report RTT
        packets_recieved++;     //Increment packet recieved
        seq ++;
    }

    /* End of ping report statistics */
    printf("--- ping statistics ---\n");
    double packet_loss = 100.0 * ((seq - packets_recieved)/(seq));
    printf("%d packets transmitted, %d packets recieved, %.1f",
            seq, packets_recieved, packet_loss);
    printf("%% packet loss\n"); 
    

} 

int main(int argc, char ** argv) 
{
    /* TTL option */
    struct option long_options[] = {
        {"ttl", required_argument, NULL, TTL},
        {0, 0, 0, 0}
    };


    /* Using getopt to handle TTL argument as input */
    int opt;
    while ((opt = getopt_long(argc, argv, "t", long_options, NULL)) != -1) {
        switch (opt) {
            case TTL:
                if (optarg) {
                    default_ttl = atoi(optarg);
                    ttl_flag = 1;
                }
                break;
            default:
                break;
        }
    }
    /* Our ping app should only accept 1 argument */
    if (argc > 3 || argc < 2) {
        printf("Usage: sudo ./ping --ttl=<input> <hostname/address> or ./ping <hostname/address>\n");
        return 1;
    }

    int status;
    struct addrinfo hints;
    struct addrinfo *res;
    

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char* host = argv[1];
    if (ttl_flag) {
        host = argv[2];
    }

    /* Create linked list of addrinfo using getaddrinfo and store in res*/
    if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0) {
        printf("%s\n", host);
        printf("Error with getaddrinfo\n");
        return 1;
    }

    struct addrinfo *i;
    struct sockaddr_in sockaddr_dest_ipv4;
    struct sockaddr_in6 sockaddr_dest_ipv6;
    
   /* Loop through linked list res and obtain sockaddr_in destinations for IPv4 and IPv6 */
    for (i= res;i != NULL; i= i->ai_next) {

        if (i->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)i->ai_addr;
            sockaddr_dest_ipv4 = *ipv4;
            ipv4_flag = 1;
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)i->ai_addr;
            sockaddr_dest_ipv6 = *ipv6;
            ipv6_flag = 1;
        }
    }

    /* ------------------ Setting up socket ------------------------- */

    int sockfd;
    if (ipv4_flag == 0 && ipv6_flag == 1) {
        sockfd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6); // Note, since we are using SOCK_RAW, need root privilege 
    }
    else {
        sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    }

    if (sockfd < 0) {
        printf("Error with socket\n");
        printf("Please ensure you are running with sudo command since we are using SOCK_RAW\n");
        return 1;
    }


    /* Printing IP_address */
    char ip_addr[INET6_ADDRSTRLEN];
    void *sa_sinaddr;

    if (ipv4_flag == 0 && ipv6_flag == 1) {
        sa_sinaddr = &(sockaddr_dest_ipv6.sin6_addr);
        inet_ntop(PF_INET6, sa_sinaddr, ip_addr, sizeof ip_addr);
    }
    else {
        sa_sinaddr = &(sockaddr_dest_ipv4.sin_addr);
        inet_ntop(PF_INET, sa_sinaddr, ip_addr, sizeof ip_addr);
    }
    
    printf("%s %s (%s): %d %s", "PING", host, ip_addr, DEFAULT_PACKET_SIZE, "data bytes\n");

    /* Handle Interrupts to end pinging */
    signal(SIGINT, interrupt_handler);

    /* Call ping with approriate sockaddr destination via IPv6 or IPv4 */
    if (ipv4_flag == 0 && ipv6_flag == 1) {
        ping(sockfd, (struct sockaddr*)&sockaddr_dest_ipv6, ip_addr);
    }
    else {
        ping(sockfd, (struct sockaddr*)&sockaddr_dest_ipv4, ip_addr);
    }

    freeaddrinfo(res);
    return 0;
}   
