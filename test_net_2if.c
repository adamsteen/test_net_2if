/*
 * Copyright (c) 2019 Adam Steen <adam@adamsteen.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TWO_INTERFACES
#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806
#define HLEN_ETHER  6
#define PLEN_IPV4  4

/*
 * Exit the application, returning (status) to the host if possible.
 *
 * Status values of 255 and above are reserved for use by Solo5.
 */
#define SOLO5_EXIT_SUCCESS	0
#define SOLO5_EXIT_FAILURE	1
#define SOLO5_EXIT_ABORT	255

static int waitsetfd = -1;
static int npollfds;

typedef enum {
    /*
     * The operation completed successfully.
     */
    SOLO5_R_OK = 0,
    /*
     * The operation cannot be completed at this time. Retrying an identical
     * operation at a later time may succeed.
     */
    SOLO5_R_AGAIN,
    /*
     * Invalid argument.
     */
    SOLO5_R_EINVAL,
    /*
     * The operation failed due to an unspecified error.
     */
    SOLO5_R_EUNSPEC
} solo5_result_t;

struct ether {
    uint8_t target[HLEN_ETHER];
    uint8_t source[HLEN_ETHER];
    uint16_t type;
};

struct arp {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    uint8_t sha[HLEN_ETHER];
    uint8_t spa[PLEN_IPV4];
    uint8_t tha[HLEN_ETHER];
    uint8_t tpa[PLEN_IPV4];
};

struct ip {
    uint8_t version_ihl;
    uint8_t type;
    uint16_t length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint8_t src_ip[PLEN_IPV4];
    uint8_t dst_ip[PLEN_IPV4];
};

struct ping {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seqnum;
    uint8_t data[0];
};

struct arppkt {
    struct ether ether;
    struct arp arp;
};

struct pingpkt {
    struct ether ether;
    struct ip ip;
    struct ping ping;
};

/*
 * Type for sets of up to 64 I/O handles.
 */
typedef uint64_t solo5_handle_set_t;

/*
 * Network I/O.
 */
/*
 * Ethernet address length in bytes.
 */
#define SOLO5_NET_ALEN          6
/*
 * Ethernet frame header (target, source, type) length in bytes.
 */
#define SOLO5_NET_HLEN          14

struct solo5_net_info {
    uint8_t mac_address[SOLO5_NET_ALEN];
    size_t mtu;                 /* Not including Ethernet header */
};

/*
 * Solo5 type for time values, with nanosecond precision.
 */
typedef uint64_t solo5_time_t;

static const solo5_time_t NSEC_PER_SEC = 1000000000ULL;

int tap_attach(const char *ifname)
{
    int fd;

    /*
     * Syntax @<number> indicates a pre-existing open fd, so just pass it
     * through if the supplied <number> is in range and O_NONBLOCK can be set.
     */
    if (ifname[0] == '@') {
        char *endp;
        long int maybe_fd = strtol(&ifname[1], &endp, 10);
        if (*endp != 0 /* Invalid character at (*endp)? */
            || endp == &ifname[1] /* Empty string? */)
            errno = EINVAL;
        else if (maybe_fd < 0 || maybe_fd > INT_MAX)
            errno = ERANGE;
        if (errno)
            return -1;

        fd = (int)maybe_fd;
        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
            return -1;

        return fd;
    }
    else if (strlen(ifname) >= IFNAMSIZ) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /*
     * Verify that the interface exists and is up and running. If we don't do
     * this then we get "create on open" behaviour on most systems which is not
     * what we want.
     */
    struct ifaddrs *ifa, *ifp;
    int found = 0;
    int up = 0;

    if (getifaddrs(&ifa) == -1)
        return -1;
    ifp = ifa;
    while (ifp) {
        if (strncmp(ifp->ifa_name, ifname, IFNAMSIZ) == 0) {
            found = 1;
            up = ifp->ifa_flags & (IFF_UP | IFF_RUNNING);
            break;
        }
        ifp = ifp->ifa_next;
    }
    freeifaddrs(ifa);
    if (!found) {
        errno = ENOENT;
        return -1;
    }

    if (!up) {
        errno = ENETDOWN;
        return -1;
    }

    char devname[strlen(ifname) + 6];

    snprintf(devname, sizeof devname, "/dev/%s", ifname);
    fd = open(devname, O_RDWR | O_NONBLOCK);
    if (fd == -1)
        return -1;

    return fd;
}

void tap_attach_genmac(uint8_t *mac)
{
    int rfd = open("/dev/urandom", O_RDONLY);

    if (rfd == -1)
        err(1, "Could not open /dev/urandom");

    int ret;

    ret = read(rfd, mac, 6);
    assert(ret == 6);
    close(rfd);
    mac[0] &= 0xfe;
    mac[0] |= 0x02;
}

solo5_result_t solo5_net_write(int fd, const uint8_t *buf,
        size_t size)
{
    int ret;

    ret = write(fd, buf, size);
    assert(size == ret);
    return SOLO5_R_OK;
}

solo5_result_t solo5_net_read(int fd, uint8_t *buf, size_t size,
        size_t *read_size)
{
    ssize_t ret;

    ret = read(fd, buf, size);
    if ((ret == 0) ||
        (ret == -1 && errno == EAGAIN)) {
        return SOLO5_R_AGAIN;
    }
    assert(ret > 0);
    *read_size = ret;
    return SOLO5_R_OK;
}

solo5_result_t solo5_net_acquire(const char *name, int *fd,
        struct solo5_net_info *info)
{
    *fd = tap_attach(name);
    if (fd < 0) {
        warnx("Could not attach interface: %s", name);
        return -1;
    }

    tap_attach_genmac(info->mac_address);
    info->mtu = 1500;
    return SOLO5_R_OK;
}

uint64_t solo5_clock_monotonic(void)
{
    struct timespec ts;

    int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    assert(rc == 0);
    return (ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;
}

bool solo5_yield(solo5_time_t deadline, solo5_handle_set_t *ready_set)
{
    uint64_t now, timeout_nsecs;

    now = solo5_clock_monotonic();
    if (deadline <= now)
        timeout_nsecs = 0;
    else
        timeout_nsecs = deadline - now;
    /*
     * At least one event must be requested in kevent(), otherwise the call
     * will just return or error.
     */
    int nevents = npollfds ? npollfds : 1;
    int nrevents;
    struct kevent revents[nevents];
    struct timespec ts;

    ts.tv_sec = timeout_nsecs / 1000000000ULL;
    ts.tv_nsec = timeout_nsecs % 1000000000ULL;

    nrevents = kevent(waitsetfd, NULL, 0, revents, nevents, &ts);
    /*
     * Unlike the epoll() implementation, we can't easily restart the kqueue()
     * call on EINTR, due to not having a straightforward way to recalculate
     * the timeout.  While we could use EVFILT_TIMER similarly to the Linux
     * timerfd, this has system-wide limits on the number of active timers.
     *
     * However: We don't handle any signals, other than by terminating the
     * tender.  Therefore, we should never see EINTR in practice here. If this
     * turns out not to be the case, prominently warn the user about it and
     * pretend we woke up early with no events, which is better than just
     * asserting/aborting.
     */
    if (nrevents == -1 && errno == EINTR) {
        warnx("hypercall_poll(): kqueue() returned EINTR");
        warnx("hypercall_poll(): This should not happen, please report a bug");
        nrevents = 0;
    }
    assert(nrevents >= 0);
    if (nrevents > 0) {
        for (int i = 0; i < nrevents; i++)
            *ready_set |= (1ULL << (uintptr_t)revents[i].udata);
    }
    return nrevents;
}

void register_pollfd(int fd, uintptr_t waitset_data)
{
    if (waitsetfd == -1) {
        waitsetfd = kqueue();
        if (waitsetfd == -1)
            err(1, "Could not create wait set");
    }

    struct kevent ev;
    /*
     * waitset_data is a solo5_handle_t, and will be returned by kevent() as
     * part of any received event.
     */
    EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, (void *)waitset_data);
    if (kevent(waitsetfd, &ev, 1, NULL, 0, NULL) == -1)
        err(1, "kevent(EV_ADD) failed");

    npollfds++;
}

static void xputs(int ifindex, const char *s)
{
    char which[] = "[serviceX] ";

    which[8] = '0' + ifindex;
    printf("%s%s", which, s);
}

/* Copied from https://tools.ietf.org/html/rfc1071 */
static uint16_t checksum(uint16_t *addr, size_t count)
{
    /* Compute Internet Checksum for "count" bytes
     * beginning at location "addr".*/
    register long sum = 0;

    while (count > 1)  {
        /*  This is the inner loop */
        sum += * (unsigned short *) addr++;
        count -= 2;
    }

    /* Add left-over byte, if any */
    if (count > 0)
        sum += * (unsigned char *) addr;

    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

static void tohexs(char *dst, uint8_t *src, size_t size)
{
    while (size--) {
        uint8_t n = *src >> 4;
        *dst++ = (n < 10) ? (n + '0') : (n - 10 + 'a');
        n = *src & 0xf;
        *dst++ = (n < 10) ? (n + '0') : (n - 10 + 'a');
        src++;
    }
    *dst = '\0';
}

struct netif {
    uint8_t ipaddr[4];
    uint8_t ipaddr_brdnet[4];
    int fd;
    struct solo5_net_info info;
};

struct netif ni[] = {
    {
        .ipaddr = { 0x0a, 0x00, 0x00, 0x02 }, /* 10.0.0.2 */
        .ipaddr_brdnet = { 0x0a, 0x00, 0x00, 0xff } /* 10.0.0.255 */
    },
#ifdef TWO_INTERFACES
    {
        .ipaddr = { 0x0a, 0x01, 0x00, 0x02 }, /* 10.1.0.2 */
        .ipaddr_brdnet = { 0x0a, 0x01, 0x00, 0xff } /* 10.1.0.255 */
    }
#endif
};

uint8_t ipaddr_brdall[4] = { 0xff, 0xff, 0xff, 0xff }; /* 255.255.255.255 */
uint8_t macaddr_brd[HLEN_ETHER] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static unsigned long n_pings_received = 0;
static bool opt_verbose = false;
static bool opt_limit = false;

static bool handle_arp(int ifindex, uint8_t *buf)
{
    struct arppkt *p = (struct arppkt *)buf;

    if (p->arp.htype != htons(1))
        return false;

    if (p->arp.ptype != htons(ETHERTYPE_IP))
        return false;

    if (p->arp.hlen != HLEN_ETHER || p->arp.plen != PLEN_IPV4)
        return false;

    if (p->arp.op != htons(1))
        return false;

    if (memcmp(p->arp.tpa, ni[ifindex].ipaddr, PLEN_IPV4))
        return false;

    /* reorder ether net header addresses */
    memcpy(p->ether.target, p->ether.source, HLEN_ETHER);
    memcpy(p->ether.source, ni[ifindex].info.mac_address, HLEN_ETHER);
    memcpy(p->arp.tha, p->arp.sha, HLEN_ETHER);
    memcpy(p->arp.sha, ni[ifindex].info.mac_address, HLEN_ETHER);

    /* request -> reply */
    p->arp.op = htons(2);

    /* spa -> tpa */
    memcpy(p->arp.tpa, p->arp.spa, PLEN_IPV4);

    /* our ip -> spa */
    memcpy(p->arp.spa, ni[ifindex].ipaddr, PLEN_IPV4);

    return true;
}

static bool handle_ip(int ifindex, uint8_t *buf)
{
    struct pingpkt *p = (struct pingpkt *)buf;

    if (p->ip.version_ihl != 0x45)
        return false; /* we don't support IPv6, yet :-) */

    if (p->ip.type != 0x00)
        return false;

    if (p->ip.proto != 0x01)
        return false; /* not ICMP */

    if (memcmp(p->ip.dst_ip, ni[ifindex].ipaddr, PLEN_IPV4) &&
        memcmp(p->ip.dst_ip, ni[ifindex].ipaddr_brdnet, PLEN_IPV4) &&
        memcmp(p->ip.dst_ip, ipaddr_brdall, PLEN_IPV4))
        return false; /* not ip addressed to us */

    if (p->ping.type != 0x08)
        return false; /* not an echo request */

    if (p->ping.code != 0x00)
        return false;

    /* reorder ether net header addresses */
    memcpy(p->ether.target, p->ether.source, HLEN_ETHER);
    memcpy(p->ether.source, ni[ifindex].info.mac_address, HLEN_ETHER);

    p->ip.id = 0;
    p->ip.flags_offset = 0;

    /* reorder ip net header addresses */
    memcpy(p->ip.dst_ip, p->ip.src_ip, PLEN_IPV4);
    memcpy(p->ip.src_ip, ni[ifindex].ipaddr, PLEN_IPV4);

    /* recalculate ip checksum for return pkt */
    p->ip.checksum = 0;
    p->ip.checksum = checksum((uint16_t *) &p->ip, sizeof(struct ip));

    p->ping.type = 0x0; /* change into reply */

    /* recalculate ICMP checksum */
    p->ping.checksum = 0;
    p->ping.checksum = checksum((uint16_t *) &p->ping,
            htons(p->ip.length) - sizeof(struct ip));

    n_pings_received++;
    return true;
}

static void send_garp(int ifindex)
{
    struct arppkt p;
    uint8_t zero[HLEN_ETHER] = { 0 };

    /*
     * Send a gratuitous ARP packet announcing our MAC address.
     */
    memcpy(p.ether.source, ni[ifindex].info.mac_address, HLEN_ETHER);
    memcpy(p.ether.target, macaddr_brd, HLEN_ETHER);
    p.ether.type = htons(ETHERTYPE_ARP);
    p.arp.htype = htons(1);
    p.arp.ptype = htons(ETHERTYPE_IP);
    p.arp.hlen = HLEN_ETHER;
    p.arp.plen = PLEN_IPV4;
    p.arp.op = htons(1);
    memcpy(p.arp.sha, ni[ifindex].info.mac_address, HLEN_ETHER);
    memcpy(p.arp.tha, zero, HLEN_ETHER);
    memcpy(p.arp.spa, ni[ifindex].ipaddr, PLEN_IPV4);
    memcpy(p.arp.tpa, ni[ifindex].ipaddr, PLEN_IPV4);

    if (solo5_net_write(ni[ifindex].fd, (uint8_t *)&p, sizeof p) != SOLO5_R_OK)
        xputs(ifindex, "Could not send GARP packet\n");
}


static bool handle_packet(int ifindex)
{
    uint8_t buf[ni[ifindex].info.mtu + SOLO5_NET_HLEN];
    solo5_result_t result;
    size_t len;
    struct ether *p = (struct ether *)&buf;
    bool handled = false;

    result = solo5_net_read(ni[ifindex].fd, buf, sizeof buf, &len);
    if (result != SOLO5_R_OK) {
        xputs(ifindex, "Read error\n");
        return false;
    }

    if (memcmp(p->target, ni[ifindex].info.mac_address, HLEN_ETHER) &&
        memcmp(p->target, macaddr_brd, HLEN_ETHER))
        return true; /* not ether addressed to us */

    switch (htons(p->type)) {
        case ETHERTYPE_ARP:
            if (handle_arp(ifindex, buf)) {
                handled = true;
                if (opt_verbose)
                    xputs(ifindex, "Received arp request, sending reply\n");
            }
            break;
        case ETHERTYPE_IP:
            if (handle_ip(ifindex, buf)) {
                if (opt_verbose)
                    xputs(ifindex, "Received ping, sending reply\n");
                handled = true;
            }
            break;
        default:
            break;
    }

    if (handled) {
        if (solo5_net_write(ni[ifindex].fd, buf, len) != SOLO5_R_OK) {
            xputs(ifindex, "Write error\n");
            return false;
        }
    }
    else {
        xputs(ifindex, "Unknown or unsupported packet, dropped\n");
    }

    return true;
}

static bool ping_serve(void)
{
    uintptr_t i = 0;;
    if (solo5_net_acquire("tap100", &ni[0].fd, &ni[0].info) != SOLO5_R_OK) {
        printf("Could not acquire 'service0' network\n");
        return false;
    }
    register_pollfd(ni[0].fd, i);
#ifdef TWO_INTERFACES
    i++;
    if (solo5_net_acquire("tap101", &ni[1].fd, &ni[1].info) != SOLO5_R_OK) {
        printf("Could not acquire 'service1' network\n");
        return false;
    }
    register_pollfd(ni[1].fd, i);
#endif

    char macaddr_s[(HLEN_ETHER * 2) + 1];
    tohexs(macaddr_s, ni[0].info.mac_address, HLEN_ETHER);
    xputs(0, "Serving ping on 10.0.0.2, with MAC: ");
    printf("%s", macaddr_s);
    printf("\n");

    send_garp(0);

#ifdef TWO_INTERFACES
    tohexs(macaddr_s, ni[1].info.mac_address, HLEN_ETHER);
    xputs(1, "Serving ping on 10.1.0.2, with MAC: ");
    printf("%s", macaddr_s);
    printf("\n");

    send_garp(1);
#endif

    for (;;) {
        bool io_ready = false;
        solo5_handle_set_t ready_set = 0;

        io_ready = solo5_yield(solo5_clock_monotonic() + NSEC_PER_SEC,
                &ready_set);
        if (io_ready && (ready_set & 1U << 0)) {
            if (!handle_packet(0))
                return false;
        }
#ifdef TWO_INTERFACES
        if (io_ready && (ready_set & 1U << 1))
            if (!handle_packet(1))
                return false;
#endif
        if (!io_ready && ready_set != 0) {
            printf("error: Yield returned false, but handles in set!\n");
            return false;
        }
        if (opt_limit && n_pings_received >= 100000) {
            printf("Limit reached, exiting\n");
            break;
        }
    }

    return true;
}

int
main(int argc, char *argv[])
{
    if (ping_serve()) {
        printf("SUCCESS\n");
        return SOLO5_EXIT_SUCCESS;
    }
    else {
        printf("FAILURE\n");
        return SOLO5_EXIT_FAILURE;
    }
}

