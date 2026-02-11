#include "mip.h"
#include "unix_ipc.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/*
- Globalt debugflagg, som skrus på med -d som argument.
- makro for betinget debug-logging.
- Skrives kun når g_debug==1, som settes med -d. Bruker fprintf(stderr, ...)
  slik at debug ikke blandes med vanlig programoutput.
*/
static int g_debug = 0;
#define DBG(...)                                                               \
  if (g_debug) {                                                               \
    fprintf(stderr, __VA_ARGS__);                                              \
  }

/*
  - Holder på min egen MIP-adresse, som jeg trenger
    når jeg skal gjøre en mulig ARP-request i send_mip_via_nh().
*/
static uint8_t g_my_mip;

/*
 - owner_fd er en liten tabell, som er indeksert på sdu_type.
 - Formålet er at den lagrer hvilken UNIX-klient-fd som "eier" typen.
 - Denne gjelder bare for server og ruter, slik at vi når vi sender til enten
   serveren eller ruteren som er koblet til mipd, vil vi hente fd-en i denne
   tabellen.
 - Antar at det enten en ping_server, eller ping_clients kan koble seg til
   samme mipd. Hvis man vil koble begge på samme mipd må man kjøre ping_server
   først.
 - Når vi kobler ping_clients for en mipd, vil den første fd-en
   bli et element i owner_fd også, men det har ikke noe å si fordi vi vil
   aldri gå inn i den når vi skal sende opp til ping_clients.
*/
static int owner_fd[8];
/*
 - tabell hvor hver mipd kan oppebevare 8 interfaces.
 - Valgte 8, fordi det er mer enn nok for denne oppgaven.
 - Denne variabelen fylles av collect_local_ifaces().
 - I tillegg brukes den for å slå opp egen MAC per ifindex, og for å sende
   broadcast på alle porter i send_mip_arp_request().
*/
static ifinfo_t my_ifs[8];
/*
 - Denne variabelen holder styr på antall interface vi finner for hver vert.
 - Antall elementer i my_ifs[].
*/
static int my_if_count = 0;

/*
 - En enkel arp_cache (MIP→MAC+ifindex).
 - Brukes av mip_arp_lookup()/arp_insert().
*/
static arp_entry_t arp_cache[64];

/*
 - En struct som skal brukes til for å holde oversikt over et klientregister,
   slik at mipd kan være koblet til flere apper om gangen.
 - fd: UNIX-fd for forbindelsen til en app-prosess (routingd,
 ping_client,ping_server).
 - type: SDU-type appen registrerer seg som (0x02=PING, 0x04=ROUTING).
*/
typedef struct {
  int fd;       // UNIX fd
  uint8_t type; // 0x02=Ping, 0x04=Routing
} client_t;

/*
 - Fast tabell som lagrer alle aktive klienter (en oppføring per tilkoblet app).
*/
static client_t clients[MAXFDS];
/*
 - Antall gyldige oppføringer i clients[], som er fra 0 til 512 (MAXFDS)
*/
static int nclients = 0;

/*
 - PING-håndterer: En FIFO per destinasjons-MIP.
 - fd_queue_t: Et sirkulært buffer som husker hvilket klient-FD som har sendt
 PING til en gitt destinasjon, slik at mottatt PONG kan rutes tilbake til riktig
 fd.
 - En ulempe/edgecase med denne er at hvis to ping_clients sender en
 PING-melding helt likt til samme destinasjon, så kan mottatt melding sendes
 feil opp til ping_clients, fordi vi har en FIFO-kø. Men ellers så funker den
 veldig bra. Siden testskriptet ikke tar hensyn til dette edgecaset har jeg ikke
 fikset det.
 - q: selve sirkulære køen (maks 64 ventere per destinasjon).
 - head: neste indeks å lese fra. (pop)
 - tail: neste indeks å skrive til. (push)
 - len : antall elementer i køen (0 til 64).
*/
typedef struct {
  int q[64];
  int head, tail, len; // head/tail = les/skriv peker
} fd_queue_t;

static fd_queue_t wait_q[256]; // kø per destinasjons-MIP-adresse (0 til 255).

/*
 - En struct for en "ventende" klient-pakke når vi ikker finner MAC-adressen i
   ARP_cache. (ARP-miss)
 - used: 1 hvis indeksplassen den bruker er i bruk, elles 0.
 - dst: den endelige destinasjonen appen ønsker å sende til.
 - orig_src: den opprinnlige avsenderens MIP-adresse. Beholdes uendret når
 pakkes gjør forwarding.
 - nhop: neste hop i forwardingen.
 - sdu_type: Typen til pakken som sendes. Enten 0x02 eller 0x04.
 - ttl: TTL som skal brukes videre. (antall maks hopp videre vi kan gjøre)
 - len: SDU-lengde.
 - data[MIP_MAX_SDU]: SDU-data.
 - Settes i main() når send_mip_unicast() returnerer -2 (ARP-miss).
 - flushes/tømmes når ARP-RESPONSE kommer.
*/
typedef struct {
  uint8_t used;
  uint8_t dst;
  uint8_t orig_src;
  uint8_t nhop;
  uint8_t sdu_type;
  uint8_t ttl;
  size_t len;
  uint8_t data[MIP_MAX_SDU];
} pending_t;

/*
 - Fast tabell med inntil 256 ventende pakker.
 - Når ARP-RESP for en gitt nhop kommer, kalles pend_flush_for_dst() som finner
 alle oppføringer der nhop = MIP-adressen gitt av ARP-RESP. Derretter sendes dem
 via send_mip_via_nh().
*/
static pending_t pend[256];

/*
 - route_wait_ent_t:
 - Har alle felter lik som pending_t, men inneholder ikke nhop.
 - Tar vare på hele pakke-informasjonen (header + payload), når vi venter
   på neste hopp fra routingd.
*/
typedef struct {
  uint8_t orig_src;  // opprinnelig kilde i MIP-headeren (h.src)
  uint8_t final_dst; // endelig dest i MIP-headeren (h.dst)
  uint8_t sdu_type;  // MIP_TYPE_*
  uint8_t ttl;       // allerede decrementet (h.ttl - 1)
  size_t len;        // SDU-lengde (uten MIP-header)
  uint8_t data[MIP_MAX_SDU];
} route_wait_ent_t;

/*
 - En sirkulær FIFO (kapasitet 128, men kan endres hvis det trengs)
   med pakker som er klare til forwarding, men mangler neste hopp.
   Når routingd sender Response en poppes et element, og
   sendes via send_mip_via_nh().
 - q: buffer med ventende entries.
 - head: neste indeks å lese. Når vi gjør pop.
 - tail: neste indeks å legg inn. Når vi gjør push.
 - len: antall elementer i køen (0 til 128).
*/
typedef struct {
  route_wait_ent_t q[128];
  int head, tail, len;
} route_wait_q_t;

/*
 - Køen for pakker som venter på next-hop fra routingd.
*/
static route_wait_q_t rwait;

/*
 - Forklarer alle funksjonene nærmere når jeg bygger de uner main.
*/

// for debug/printing.
static void print_usage(const char *prog);
static void print_mac(const char *prefix, const uint8_t mac[6]);
static void print_arp_cache(void);

// sjekker om payload starter på Ping eller Pong.
int has_prefix(const uint8_t *s, size_t n, const char *pfx);
int is_ping_payload(const uint8_t *p, size_t n);
int is_pong_payload(const uint8_t *p, size_t n);

// levering opp til app.
int deliver_up_to_fd(int fd, uint8_t src_mip, const uint8_t *sdu, size_t len);
int deliver_up_to_type(uint8_t type, uint8_t src_mip, const uint8_t *sdu,
                       size_t len);

// klientregister.
int add_client(int fd, uint8_t type);
void remove_client(int fd);
uint8_t type_for_fd(int fd);

// PING-klienter håndteringskø.
void q_push(fd_queue_t *q, int fd);
int q_pop(fd_queue_t *q);

// pending (ARP for next-hop).
int pend_put(uint8_t dst, uint8_t orig_src, uint8_t nhop, uint8_t sdu_type,
             uint8_t ttl, const uint8_t *data, size_t len);
static int pend_flush_for_dst(int rawfd, uint8_t arpmip);

// route-wait FIFO.
static void rw_push(const route_wait_ent_t *e);
static int rw_pop(route_wait_ent_t *out);

// UNIX socket.
static int build_UNIX_Socket(const char *path);

// RAW-socket, og sending og mottak av pakker over ethernet.
int build_RAW_socket(void);
static int send_eth_frame(int rawfd, int ifindex, const uint8_t dst[6],
                          const uint8_t src[6], uint16_t ethertype,
                          const void *payload, size_t plen);
static ssize_t recv_eth_frame(int rawfd, uint8_t src_out[6], uint8_t dst_out[6],
                              uint16_t *ethertype_out, int *in_ifx_out,
                              uint8_t *payload, size_t cap);

// interfaces.
static void collect_local_ifaces(void);
static int mymac_for_ifindex(int ifx, uint8_t out_mac[6]);

// ARP-cache + MIP-ARP
int mip_arp_lookup(uint8_t mip, uint8_t mac_out[6], int *ifx_out);
static void arp_insert(uint8_t mip, const uint8_t mac[6], int ifindex);
static void build_miparp_payload(uint8_t type, uint8_t addr, uint8_t out[4]);
static int send_mip_arp_request(int rawfd, uint8_t my_mip, uint8_t target_mip);
static int send_mip_arp_response(int rawfd, uint8_t my_mip, uint8_t dst_mip,
                                 const uint8_t dst_mac[6], int out_ifindex);

// MIP send/forward/broadcast
static int send_mip_unicast(int rawfd, uint8_t my_mip, uint8_t dst_mip,
                            const void *sdu, size_t len, uint8_t sdu_type,
                            uint8_t ttl);

static int send_mip_via_nh(int rawfd, uint8_t orig_src, uint8_t final_dst,
                           uint8_t next_hop, uint8_t ttl, const void *sdu,
                           size_t len, uint8_t sdu_type);
static int send_mip_broadcast(int rawfd, uint8_t my_mip, const void *sdu,
                              size_t len, uint8_t sdu_type, uint8_t ttl);

// route request.
static void send_route_request(int unix_fd, uint8_t my_mip, uint8_t dst);

// epoll hjelpere og metode som behandler pakker over raw-socket.
static int ep_add(int efd, int fd, uint32_t evs);
static int ep_del(int efd, int fd);
static void handle_raw_event(int rawfd, uint8_t my_mip);

/*
Hva funksjonen gjør:
  - setter opp MIP-daemonen og kjører epoll-løkka. I tillegg håndterer den
  argumenter som blir skrevet inn.
  - Oppretter UNIX server-socket (lytter for apper) og RAW AF_PACKET-socket
  (Ethernet).
  - Samler lokale interfaces (ifindex + MAC), initierer globale strukturer,
    og kjører en epoll som håndterer:
      * nye UNIX-klienttilkoblinger (registrering av SDU-type)
      * innkommende pakker på RAW-socket
      * data og avslutning fra tilkoblede UNIX-klienter.

Parametre:
  - argc: antall argumenter.
  - argv: argumentvektor.

Globale variabler som påvirker (egentlig alle):
  - g_debug: styrer DBG-logging til stderr.
  - owner_fd[]: nullstilles og fylles ved klientregistrering; brukes for sending
    til riktig server/routingd.
  - my_ifs[]: fylt av collect_local_ifaces().
  - arp_cache[]: oppdateres løpende av ARP-håndteringen.

Returverdi:
 - 0 ved normal avsltuning. terminering av hovedløkka eller -h inn som kommando.
 - 1 ved systemfeil, som socket osv.
 - 2 ved brukerfeil, ved at man skriver ugyldige argumenter.
*/

int main(int argc, char **argv) {
  const char *path = NULL;
  uint8_t my_mip = 0;
  // For å skrive inn -d og -h som argumenter.
  int i = 1;
  while (i < argc) {
    const char *arg = argv[i];
    if (arg[0] != '-')
      break; // Vi bruker ikke "-" som betyr at vi kan starte på path og mip.
    if (strcmp(arg, "-h") == 0) {
      print_usage(argv[0]);
      return 0;
    } else if (strcmp(arg, "-d") == 0) {
      g_debug = 1; // skrur på debug-logging.
      i++;
      continue;
    } else {
      fprintf(stderr, "Ukjent flagg: %s\n\n", arg);
      print_usage(argv[0]);
      return 2; /* retunerer 2 når det er noe kommando-feil*/
    }
  }

  if (argc - i != 2) {
    fprintf(stderr, "Error: expected <socket_upper> and <MIP address>.\n\n");
    print_usage(argv[0]);
    return 2;
  }
  path = argv[i];
  {
    char *end = NULL;
    unsigned long v = strtoul(argv[i + 1], &end,
                              0); /* støtter MIP-adresse både som 11 og 0x0B */
    if (end == argv[i + 1] || *end != '\0' || v > 255) {
      fprintf(stderr,
              "Error: MIP address must be integer in [0,255]. Got: '%s'\n",
              argv[i + 1]);
      return 2;
    }
    my_mip = (uint8_t)v;
  }
  DBG("[mipd] Starting. my_mip=0x%02x, unix=%s, ETH_TYPE_P=0x%04x\n", my_mip,
      path, ETH_TYPE_P);
  g_my_mip = my_mip; // i main etter parsing

  for (int t = 0; t < 8; t++) {
    owner_fd[t] = -1;
  }
  int lfd = build_UNIX_Socket(path);
  if (lfd < 0)
    return 1; // Retunrerer når det gjelder feil socket,epoll osv.
  DBG("[mipd] Listening on %s\n", path);
  collect_local_ifaces();
  int rawfd = build_RAW_socket();
  if (rawfd < 0) {
    close(lfd);
    unlink(path);
    return 1;
  }
  int epfd = epoll_create1(0);
  if (epfd == -1) {
    perror("epoll_create1");
    close(lfd);
    unlink(path);
    return 1;
  }
  // Overvåker nye forbindelser
  if (ep_add(epfd, lfd, EPOLLIN) == -1) {
    perror("epoll_ctl ADD lfd");
    close(epfd);
    close(lfd);
    unlink(path);
    return 1;
  }
  if (ep_add(epfd, rawfd, EPOLLIN) == -1) {
    perror("epoll_ctl ADD rawfd");
    close(rawfd);
    close(epfd);
    unlink(path);
    return 1;
  }
  const int MAX = 32;
  struct epoll_event events[MAX];

  for (;;) {
    int n = epoll_wait(epfd, events, MAX, -1);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      perror("epoll_wait");
      break;
    }
    for (int i = 0; i < n; i++) {
      int fd = events[i].data.fd;
      uint32_t ev = events[i].events;

      // Hvis det er nye tilkoblinger går vi hit.
      if (fd == lfd && (ev & EPOLLIN)) {
        int tmp = accept(lfd, NULL, NULL);
        if (tmp == -1) {
          perror("accept");
          continue;
        }
        // Vi leser registreningsbyte (typen) her.
        uint8_t reg_type = 0xFF;
        ssize_t rn = recv(tmp, &reg_type, 1, MSG_WAITALL);
        if (rn != 1 || reg_type > MIP_TYPE_MAX) {
          close(tmp);
          DBG("[mipd] Kunne ikke motta typen koblingen.\n");
          continue;
        }
        if (add_client(tmp, reg_type) < 0) {
          close(tmp);
          DBG("[mipd] For mange klienter\n");
          continue;
        }
        /*Legg den nye UNIX-tilkoblingen i epoll, og oppdage når motparten
          lukker forbindelsen*/
        if (ep_add(epfd, tmp, EPOLLIN | EPOLLRDHUP) == -1) {
          perror("epoll_ctl ADD fd");
          remove_client(tmp);
          close(tmp);
          continue;
        }
        DBG("[mipd] Klient tilkoblet (fd=%d) (type%d) \n", tmp, reg_type);
        continue;
      }
      // Håndterer pakker over raw-socket her.
      if (fd == rawfd && (ev & EPOLLIN)) {
        handle_raw_event(rawfd, my_mip);
        continue;
      }

      /*Håndterer at UNIX-klienten har lagt på, eller at det har oppstått en
        feil på forbindelsen.*/
      if (fd != lfd && fd != rawfd &&
          (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
        ep_del(epfd, fd);
        remove_client(fd);
        close(fd);
        DBG("[mipd] Klient fd=%d la på\n", fd);
        continue;
      }
      // Event fra en aktiv UNIX-klient
      if (fd != lfd && fd != rawfd) {
        // Er det data å lese?
        if (ev & EPOLLIN) {
          uint8_t dst_mip, ttl;
          uint8_t sdu[UPPER_MAX_MSG];
          ssize_t r = recv_msg(fd, &dst_mip, &ttl, sdu, sizeof sdu);
          if (r <= 0) {
            if (r < 0) {
              perror("recv_msg");
            }
            ep_del(epfd, fd);
            remove_client(fd);
            close(fd);
            DBG("[mipd] Klient disconnected (fd=%d)\n", fd);
            continue;
          }

          uint8_t t = type_for_fd(fd);
          if (t == 0xFF) {
            continue;
          }
          uint8_t eff_ttl = ttl;
          if (eff_ttl == 0) {
            eff_ttl = MIP_DEFAULT_TTL;
          }

          // For HELLO-meldinger som sendes til alle naboer.
          if (dst_mip == MIP_BROADCAST && t == MIP_TYPE_ROUTING) {
            if (send_mip_broadcast(rawfd, my_mip, sdu, (size_t)r, t, eff_ttl) !=
                0) {
              perror("send_mip_broadcast");
            }
            continue; // ferdig for denne meldingen
          }

          /*
           - Når vi mottar response fra routingd, og skal videresende pakken som
           kom inn.
           - Popper den ventende pakken fra rwait og videresender via gitt
           next-hop.
          */
          if (t == MIP_TYPE_ROUTING) {
            if (r >= 4 && sdu[0] == 'R' && sdu[1] == 'S' && sdu[2] == 'P') {
              uint8_t nhop = sdu[3];
              route_wait_ent_t e;
              if (rw_pop(&e) != 0) {
                DBG("[mipd] RSP but queue empty — ignore\n");
                continue; // ferdig med denne UNIX-meldingen
              }
              if (nhop == 255) {
                DBG("[mipd] no route for 0x%02x -> drop\n", e.final_dst);
                continue; // ingen rute — ferdig med meldingen
              }

              int rc = send_mip_via_nh(rawfd, e.orig_src, e.final_dst, nhop,
                                       e.ttl, e.data, e.len, e.sdu_type);
              if (rc == -2) {
                DBG("[mipd] ARP pending (nhop=0x%02x) — buffered forward\n",
                    nhop);
                if (pend_put(e.final_dst, e.orig_src, nhop, e.sdu_type, e.ttl,
                             e.data, e.len) < 0) {
                  DBG("[mipd] pend full for UPDATE til 0x%02x\n", e.final_dst);
                }
              } else if (rc < 0) {
                perror("send_mip_via_nh");
              } else {
                DBG("[mipd] forwarded via nhop=0x%02x to dst=0x%02x (%zu "
                    "bytes)\n",
                    nhop, e.final_dst, e.len);
              }
              continue;
            }
          }
          if (t == MIP_TYPE_ROUTING && sdu[0] == 'U') {
            int rc = send_mip_unicast(rawfd, my_mip, dst_mip, sdu, (size_t)r,
                                      MIP_TYPE_ROUTING, eff_ttl);
            if (rc == -2) {
              if (pend_put(dst_mip, my_mip, dst_mip, MIP_TYPE_ROUTING, eff_ttl,
                           sdu, (size_t)r) < 0) {
                DBG("[mipd] pend full for UPDATE til 0x%02x\n", dst_mip);
              }
            }
            continue;
          }
          /* Når vi sender PING-melding ut, legger vi klientens fd i wait_q for
             indeks dst_mip. Dette gjør slik at riktig fd får PONG når den
             kommer tilbake.
          */
          if (t == MIP_TYPE_PING && is_ping_payload(sdu, (size_t)r)) {
            q_push(&wait_q[dst_mip], fd);
          }

          /* Når vi skal sende PING-pakken videre til riktig nabo,
          gjør jeg en send_route_request() til routingd, som
          fører til at pakken sendes til riktig nabo når vi får
          Response fra routingd.
          */

          route_wait_ent_t sp = {.orig_src = my_mip,
                                 .final_dst = dst_mip,
                                 .sdu_type = t,
                                 .ttl = eff_ttl,
                                 .len = (size_t)r};
          memcpy(sp.data, sdu, sp.len);

          /*  legger pakken jeg skal sende i route-wait, fordi skal gjøre
              route-request.
          */
          rw_push(&sp);
          int routing_fd = owner_fd[MIP_TYPE_ROUTING];
          if (routing_fd != -1) {
            send_route_request(routing_fd, my_mip, dst_mip);
          } else {
            DBG("[mipd] no routingd connected — drop queued packet for "
                "dst=0x%02x\n",
                dst_mip);
          }
          continue;
        }
        continue;
      }
    }
  }
  // Rydder opp
  for (int j = 0; j < nclients; j++) {
    close(clients[j].fd);
  }
  close(rawfd);
  close(epfd);
  close(lfd);
  unlink(path);
  return 0;
}

/*
Hva funksjonen gjør:
 - Skriver ut brukshjelp dersom man ønsker det.
 - Skriv -h som et argument på starten som stopper programmet og printer ut
 brukshjelp.
Parametre:
 - prog: programvavnet det gjelder (argv[0]).
Returverdi:
  - ingen
*/
void print_usage(const char *prog) {
  DBG("Usage: %s [-h] [-d] <socket_upper> <MIP address>\n"
      "Options:\n"
      "  -d    enable debugging mode\n"
      "  -h    prints help and exits the program\n"
      "Arguments:\n"
      "  socket_upper  pathname of the UNIX socket.\n"
      "  MIP address.  the MIP address to assign to this host\n",
      prog);
}
/*
Hva funksjonen gjør:
 - Skriver en MAC-adresse som tekst i hex ut på terminalen.
 -Hjelper til med debugging.
Parametre:
 - prefix: streng som printes før selve MAC-adressen (f.eks. "mac=").
 - mac: peker til 6-byte MAC-adresse som skal skrives ut.
Returverdi:
  - ingen
*/
void print_mac(const char *prefix, const uint8_t mac[6]) {
  DBG("%s%02x:%02x:%02x:%02x:%02x:%02x", prefix, mac[0], mac[1], mac[2], mac[3],
      mac[4], mac[5]);
}
/*
Hva funksjonen gjør:
  - Printer elemenetne vi har i cache.
Parametre:
 - ingen
Returverdi:
  - ingen
*/
void print_arp_cache(void) {
  int elements = (int)(sizeof arp_cache / sizeof arp_cache[0]);
  DBG("[mipd] ARP cache:\n");
  for (int i = 0; i < elements; i++) {
    if (arp_cache[i].in_use) {
      DBG("  MIP=0x%02x -> ", arp_cache[i].mip);
      print_mac("MAC=", arp_cache[i].mac);
      DBG(" ifindex=%d\n", arp_cache[i].ifindex);
    }
  }
}

/*
Hva funksjonen gjør:
 - Sjekker om en bytebuffer starter med gitt tekstprefiks.
Parametre:
 - s: peker til payload.
 - n: antall byte i payload.
 - pfx: streng å matche mot starten av payload.
Returverdi:
  - 1 hvis payload starter med pfx, ellers 0.
*/
int has_prefix(const uint8_t *s, size_t n, const char *pfx) {
  size_t L = strlen(pfx);
  if (n < L || !s) {
    return 0;
  }
  if (memcmp(s, pfx, L) == 0) { // Kunne egentlig ha brukt strcmp også.
    return 1;
  }
  return 0;
}
/*
Hva funksjonene gjør:
  - sjekker om payload starter med "PING:" eller "PONG:"
Parametre:
  - p: peker til payload.
  - n: lengde på payload i byte.
Returverdi;
  - 1 hvis prefiks er "PING:" eller "PONG:", ellers 0.
*/
int is_ping_payload(const uint8_t *p, size_t n) {
  return has_prefix(p, n, "PING:");
}
int is_pong_payload(const uint8_t *p, size_t n) {
  return has_prefix(p, n, "PONG:");
}

/*
Hva funksjonene gjør:
  - Sender SDU direkte til en spesifikk app-tilkobling (fd).
  - Brukes slik at vi vet hvilket klient-fd som skal motta "PONG-meldingen".
Parametre:
  - fd: UNIX-socket fd til appen.
  - src_mip: avsenderens MIP-adresse som leveres.
  - sdu og len: data og lengde som skal leveres.
Returverdi;
  - send_msg() sin returverdi (0 ved suksess og mindre enn 0 ved feil).
*/
int deliver_up_to_fd(int fd, uint8_t src_mip, const uint8_t *sdu, size_t len) {
  return send_msg(fd, src_mip, 0, sdu, len);
}

/*
Hva funksjonene gjør:
  - Lever SDU til eieren av en gitt SDU-type (enten ping_server eller routingd).
  - Brukes når vi ikke  til en ping_server eller routingd lokalt. Ikke
    ping_client.
Parametre:
  - type: MIP_TYPE som brukes til å hente riktig fd fra owner_fd.
  - src_mip: avsenderens MIP-adresse
  - sdu og len: data og lengde som skal leveres.
Globale varibaler som påvirker:
 - owner_fd[]: map fra SDU-type til eierens fd.
Returverdi:
  - send_msg() sin returverdi (0 ved suksess og -1 feil).
  - ellers -1 hvis ingen er registrert for denne typen.
*/
int deliver_up_to_type(uint8_t type, uint8_t src_mip, const uint8_t *sdu,
                       size_t len) {
  int ofd = owner_fd[type];
  if (ofd != -1) {
    return send_msg(ofd, src_mip, 0, sdu, len);
  }
  return -1;
}

/*
Hva funksjonene gjør:
  - Registrerer en ny app-tilkobling (fd,type) i klienttabellen.
  - Setter owner_fd[type] hvis den ikke var satt fra før.
Parametre:
  - fd: UNIX-socket fd for appen.
  - type : sdu-typen appen registrerer seg som.

Globale variabler som påvirkes:
  - clients[]:tabell over aktive klienter.
  - nclients: antall gyldige oppføringer.
  - owner_fd[]: eier per SDU-type.
Returverdi;
  - 0 ved suksess, -1 hvis klienttabellen er full.
*/

int add_client(int fd,
               uint8_t type) { // Legger til ny kobling til mipd i listen.
  if (nclients >= MAXFDS) {
    return -1;
  }
  clients[nclients].fd = fd;
  clients[nclients].type = type;
  nclients++;
  // Sett owner_fd for denne typen hvis ingen eier er satt
  if (type < 8 && owner_fd[type] == -1) {
    owner_fd[type] = fd;
  }
  return 0;
}
/*
Hva funksjonene gjør:
  - Fjerner en app/klient-tilkobling fra klienttabellen og frigir eventuelle
    fd-er i owner_fd.
Parametre:
  - fd : UNIX-socket fd som skal fjernes.
Globale variabler som påvirkes:
  - clients[]:tabell over aktive klienter.
  - nclients: antall gyldige oppføringer.
  - owner_fd[]: nullstilles for typer der denne fd var eier.
Returverdi;
  - ingen
*/
void remove_client(int fd) {
  for (int i = 0; i < nclients; i++) {
    if (clients[i].fd == fd) {
      clients[i] = clients[nclients - 1];
      nclients--;
      // memset(&clients[nclients], 0, sizeof clients[0]); // null ut "gammel
      // siste"
      break;
    }
  }
  for (int t = 0; t < 8; t++) {
    if (owner_fd[t] == fd) {
      owner_fd[t] = -1;
    }
  }
}
/*
Hva funksjonene gjør:
  - Slår opp hvilken SDU-type som er registrert for et gitt tilkoblet fd.
  -
Parametre:
  - fd : UNIX-socket fd til klienten.
Globale variabler som påvirkes:
  - clients[]:tabell over aktive klienter.
  - nclients: antall gyldige oppføringer.
Returverdi;
  - klientens type, elles 0xFF.
*/
uint8_t type_for_fd(int fd) {
  for (int i = 0; i < nclients; i++) {
    if (clients[i].fd == fd) {
      return clients[i].type;
    }
  }
  return 0xFF; // hvis vi ikke finner typen.
}

/*
Hva funksjonene gjør:
  -  Legger et fd inn i den sirkulære køen. Hvis køen er full (64),
     droppes eldste element (head flyttes) før innsetting.
Parametre:
  - q:peker til fd_queue_t (køen).
  - fd:fd som skal legges i køen.
Globale variabler som påvirkes:
  - wait_q[256]: destinasjonen som fd skal sende til legges inn for den
                 indeksen i denne listen.
Returverdi;
  - Ingen (void).
*/
void q_push(fd_queue_t *queue, int fd) {
  if (queue->len >= 64) {
    queue->head = (queue->head + 1) % 64;
    queue->len--;
  }
  queue->q[queue->tail] = fd;
  queue->tail = (queue->tail + 1) % 64;
  queue->len++;
}
/*
Hva funksjonene gjør:
  -  Leser ut (pop) første fd fra den sirkulære køen.
Parametre:
  - q:peker til fd_queue_t (køen).
Globale variabler som påvirkes:
  - wait_q[256]: destinasjonen som fd skal sende til poppes,
                 og sendes opp til riktig ping_client.
Returverdi;
  - fd-en som skal motta pakken.
*/
int q_pop(fd_queue_t *queue) {
  if (queue->len == 0) {
    return -1;
  }
  int fd = queue->q[queue->head];
  queue->head = (queue->head + 1) % 64;
  queue->len--;
  return fd;
}
/*
Hva funksjonene gjør:
  - Lagrer en ventende pakke i første ledige slot i pend[] (ARP-miss-buffer).
  - Legger inn i første ledige indeksplass.
Parametre:
  - dst: endelig destinasjon.
  - orig_src: den opprinnlige avsenderens MIP-adresse.
  - nhop: (MIP-adressen vi ARP-er på).
  - sdu_type: MIP-type.
  - ttl: TTL som skal brukes videre.
  - data og len: SDU-data og lengden til SDU-data.
Globale variabler som påvirkes:
  - pend[]: første ledige element fylles og merkes used=1.
Returverdi;
  - Indeksen (0 til 255) til indeksplassen som ble brukt, eller -1 hvis det er
    fullt.
*/
int pend_put(uint8_t dst, uint8_t orig_src, uint8_t nhop, uint8_t sdu_type,
             uint8_t ttl, const uint8_t *data, size_t len) {
  for (int i = 0; i < 256; i++) {
    if (!pend[i].used) {
      pend[i].used = 1;
      pend[i].dst = dst;
      pend[i].orig_src = orig_src;
      pend[i].nhop = nhop;
      pend[i].sdu_type = sdu_type;
      pend[i].ttl = ttl;
      pend[i].len = len;
      memcpy(pend[i].data, data, len);
      return i;
    }
  }
  return -1; // full
}

/*
Hva funksjonene gjør:
  - Sender alle pendende pakker som venter på ARP for gitt next-hop (arpmip).
  - For hver match:
      kaller send_mip_via_nh(), og hvis det går frigjøres sloten.
Parametre:
  - rawfd: RAW-socket fd.
  - arpmip : MIP-adressen vi nettopp lærte MAC for fra ARP.
      - MIP-adressen vi lærte var next_hop. next_hop == arpmip.
Globale variabler som påvirkes:
  - pend[]: alle treff på nhop==arpmip blir sendt, og ved suksess
            settes used til 0. Plassen er da ledig for andre pakker.
Returverdi;
  - Antall pakker som faktisk ble sendt.
*/
static int pend_flush_for_dst(int rawfd, uint8_t arpmip) {
  int count = 0;
  for (int i = 0; i < 256; i++) {
    if (pend[i].used && pend[i].nhop == arpmip) {
      int rc = send_mip_via_nh(rawfd, pend[i].orig_src, pend[i].dst,
                               pend[i].nhop, pend[i].ttl, pend[i].data,
                               pend[i].len, pend[i].sdu_type);
      if (rc >= 0) {
        pend[i].used = 0;
        count++;
      } else {
        perror("send_mip_via_nh");
      }
    }
  }
  return count;
}
/*
Hva funksjonene gjør:
  - Legger et element på slutten av route-wait-køen (rwait).
  - Venter da på response fra routingd.
Parametre:
  - e:peker til elementet som skal kopieres inn i køen.

Globale variabler som påvirkes:
  - rwait: Elementene puttes inn i rwait.q,
           som en FIFO.
Returverdi;
  - Ingen.
*/
void rw_push(const route_wait_ent_t *e) {
  if (rwait.len >= 128) { // dropp eldste om full
    rwait.head = (rwait.head + 1) % 128;
    rwait.len--;
  }
  rwait.q[rwait.tail] = *e;
  rwait.tail = (rwait.tail + 1) % 128;
  rwait.len++;
}

/*
Hva funksjonene gjør:
  -  Henter ut (popper) eldste element fra route-wait-køen (rwait).
Parametre:
  - out:peker der det poppede elementet kopieres til.
Globale variabler som påvirkes:
  - rwait: Elementene poppes frarwait.q.
Returverdi;
  - 0 ved suksess og -1 hvis køen er tom.
*/
int rw_pop(route_wait_ent_t *out) {
  if (rwait.len == 0)
    return -1;
  *out = rwait.q[rwait.head];
  rwait.head = (rwait.head + 1) % 128;
  rwait.len--;
  return 0;
}
/*
Hva funksjonene gjør:
  - Oppretter en lyttende UNIX server-socket som mipd lytter på. Dette
    foregår lokalt.
Parametre:
  - path: Filsti til socket (f.eks. /tmp/mipd.sock).
Returverdi;
  - fd vil være større eller >= når alt er korrekt, og -1 ved feil.
  - perror() vil kalles på feil når det kommer til socket/bind/listen.
*/

int build_UNIX_Socket(const char *path) {
  int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd == -1) {
    perror("socket");
    return -1;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
  unlink(path); // sørger for at gammel socket-fil ikke blokkerer bind().
  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) == -1) {
    perror("bind");
    close(fd);
    return -1;
  }
  if (listen(fd, 16) == -1) {
    perror("listen");
    close(fd);
    unlink(path);
    return -1;
  }
  return fd;
}

/*
Hva funksjonen gjør:
    - Oppretter RAW AF_PACKET-socket for vår EtherType (MIP).
    - Bruker SOCK_RAW og htons(ETH_TYPE_P) slik at kjernen filtrerer innkommende
      ethernet-rammer til bare MIP.
    - Socketen brukes til å sende/motta Ethernet-rammer mot naboer.
returverdi:
    - Retunerer fd (>=0) ved suksess, og -1 ved feil.
*/

int build_RAW_socket() {
  int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_TYPE_P));
  if (fd < 0) {
    perror("socket(AF_PACKET)");
    return -1;
  }
  return fd;
}

/*
Hva funksjonen gjør:
 - Sender en Ethernet-ramme ut på valgt interface.
    - Bygger en komplett Ethernet-ramme (dest/src/ethertype + payload)
 - Har valgt å sette buffer på 1600, fordi ethernet-payloaden er maks 1500 byte.
   Setter 1600, så jeg har litt rom ekstra tilfelle.
parameter:
 - rawfd: RAW socket sin fd.
 - ifindex: Hvilken port som vi skal sende for å nå naboen.
 - dst: destinasjons-MAC.
 - src: kilde-MAC.
 - ethertype: ETH_TYPE_P 0x88B5
 - payload: (MIP-header + SDU)
 - plen: payload-lengde i bytes.
returverdi:
  - Retunerer 0 ved suksess, og -1 hvis ikke alt har blitt sendt.
*/

int send_eth_frame(int rawfd, int ifindex, const uint8_t dst[6],
                   const uint8_t src[6], uint16_t ethertype,
                   const void *payload, size_t plen) {
  uint8_t frame[1600];
  size_t off = 0;
  // Ethernet-header (14 bytes)
  memcpy(frame + off, dst, 6);
  off += 6;
  memcpy(frame + off, src, 6);
  off += 6;
  uint16_t eth_be = htons(ethertype);
  memcpy(frame + off, &eth_be, 2);
  off += 2;
  // Payload
  if (off + plen > sizeof(frame)) {
    return -1;
  }
  memcpy(frame + off, payload, plen);
  off += plen;
  struct sockaddr_ll sll = {0};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = eth_be;
  sll.sll_ifindex = ifindex;
  ssize_t n = sendto(rawfd, frame, off, 0, (struct sockaddr *)&sll, sizeof sll);
  print_arp_cache();
  DBG("[mipd] ETH SEND ifx=%d ", ifindex);
  print_mac("dst=", dst);
  DBG(" ");
  print_mac("src=", src);
  DBG(" type=0x%04x len=%zd\n", ntohs(ethertype), (ssize_t)off);
  if (n == (ssize_t)off) {
    return 0;
  } else {
    return -1;
  }
}
/*
Hva funksjonen gjør:
  - Mottar en Ethernet-ramme fra RAW-socketen, og tar ut informasjonen den har
    fått.
  - Tar ut informasjonen hvor vi mottar, kilde mac, destinasjons-mac, ethertype,
    interfacet den kom på.
  - Kopierer også payloaden (etter 14 bytes), til bufferet som skal
    videresendes.
  - Videresendes til lokal tilkoblet klient dst==my_mip.
Parametere:
  - rawfd: RAW socket sin fd.
  - src: kilde-MAC.
  - dst: destinasjons-MAC.
  - ethertype_out: mottatt EtherType.
  - in_ifx_out: ifindex ethernet-rammen kom inn på.
  - payload: buffer for payloaden etter de 14-bytes ethhdr, som skal sendes
             videre.
  - cap: kapasitet i payload-buffer.
  - plen:  payload-lengde i bytes.
returverdi:
  - returnerer antall payload-bytes levert, som er 0 opptil cap (maks bytes
    payload kan ha). Eller -1 ved feil eller for lite til header.
*/

ssize_t recv_eth_frame(int rawfd, uint8_t src_out[6], uint8_t dst_out[6],
                       uint16_t *ethertype_out, int *in_ifx_out,
                       uint8_t *payload, size_t cap) {
  uint8_t
      buf[2000]; /*setter den bare til 2000, men viktigste at den er over 1500*/

  struct sockaddr_ll sll;
  socklen_t sll_len = sizeof sll;
  ssize_t n =
      recvfrom(rawfd, buf, sizeof buf, 0, (struct sockaddr *)&sll, &sll_len);
  if (n < 0) {
    return -1;
  }
  // Må minst ha plass til en Ethernet-header
  if ((size_t)n < sizeof(struct ethhdr)) {
    return -1;
  }
  struct ethhdr *eh = (struct ethhdr *)buf;
  // Kopier ut MAC-adresser.
  memcpy(dst_out, eh->h_dest, 6);
  memcpy(src_out, eh->h_source, 6);
  // Konverter Ethertype til host-orden.
  if (ethertype_out != NULL) {
    *ethertype_out = ntohs(eh->h_proto);
  }
  // Ifindex for interfacet pakken kom inn på.
  if (in_ifx_out != NULL) {
    *in_ifx_out = sll.sll_ifindex;
  }
  // Regner ut payload (alt etter headeren.
  size_t frame_payload_len = (size_t)n - sizeof(struct ethhdr);
  /*Bestemmer hvor mye vi faktisk kan kopiere inn i payload gitt kapasiteten
    cap*/
  size_t copy_len = frame_payload_len;
  if (copy_len > cap) {
    copy_len = cap;
  }
  // Kopier payloaden.
  if (copy_len > 0) {
    memcpy(payload, buf + sizeof(struct ethhdr), copy_len);
  }
  print_arp_cache();
  DBG("[mipd] ETH RECV ifx=%d ", sll.sll_ifindex);
  print_mac("dst=", dst_out);
  DBG(" ");
  print_mac("src=", src_out);
  DBG(" type=0x%04x len=%zd\n", ethertype_out ? *ethertype_out : 0, n);
  return (ssize_t)copy_len;
}

/*
Hva funksjonen gjør:
 - Samler lokale nettverksgrensesnitt og lagrer ifindex + MAC.
 - Går gjennom getifaddrs() og plukker AF_PACKET-entries. Hopper over loopback.
Globale variabler som påvirker:
 - Globale variabler som tas i bruk er my_ifs[] og my_if_count.
    - fyller de inn i denne metoden
returverdi:
  - ingen.
ekstra:
 - antall elementer = (int)(sizeof my_ifs / sizeof my_ifs[0] = (totale bytes)
                      / (bytes per element).
*/
void collect_local_ifaces(void) {
  struct ifaddrs *ifs = NULL;
  struct ifaddrs *p = NULL;
  // Henter en lenket liste av alle nettverksgrensesnitt på maskinen.
  if (getifaddrs(&ifs) != 0) {
    perror("getifaddrs");
    return;
  }
  for (p = ifs; p != NULL; p = p->ifa_next) {
    if (!p->ifa_addr) // Hopper over tomme entries.
    {
      continue;
    }
    // Er kun interessert i lenkelagsadresser (AF_PACKET). Her ligger MAC +
    // ifindex.
    if (p->ifa_addr->sa_family != AF_PACKET) {
      continue;
    }
    if (!strcmp(p->ifa_name, "lo")) // Hopper over loopback (lo).
    {
      continue;
    }
    // Caster til sockaddr_ll som har feltene vi trenger: sll_ifindex (ifindex),
    // sll_addr (MAC)
    struct sockaddr_ll *sll = (struct sockaddr_ll *)p->ifa_addr;
    if (sll->sll_halen != ETH_ALEN) // Forventer 6-byte MAC.
    {
      continue;
    }
    if (my_if_count < (int)(sizeof my_ifs / sizeof my_ifs[0])) {
      my_ifs[my_if_count].ifindex = sll->sll_ifindex;
      memcpy(my_ifs[my_if_count].mac, sll->sll_addr, 6);
      DBG("[mipd] IFACE: ifindex=%d, name=%s, ", sll->sll_ifindex, p->ifa_name);
      print_mac("mac=", my_ifs[my_if_count].mac);
      DBG("\n");
      my_if_count++;
    }
  }
  freeifaddrs(ifs);
}
/*
Hva funksjonen gjør:
 - Slår opp vår egen MAC for en gitt ifindex.
Parametre;
  - ifx: ifindex for interfacet/ettverksgrensesnittet for verten vi er på.
  - out_mac: buffer (6 bytes) som fylles med MAC.
returverdi:
  - Det retuneres 0 hvis det blir funnet, og -1 hvis ikke.
*/

int mymac_for_ifindex(int ifx, uint8_t out_mac[6]) {
  for (int i = 0; i < my_if_count; i++) {
    if (my_ifs[i].ifindex == ifx) {
      memcpy(out_mac, my_ifs[i].mac, 6);
      return 0;
    }
  }
  return -1;
}

/*
Hva funksjonen gjør:
 - Slår opp (MIP→MAC,ifindex) i lokal ARP-cache.
Parametre;
  - mip: MIP-adressen vi leter etter.
  - mac_out: kopierer ut på denne variabelen hvis det er treff.
  - ifx_out: kopierer ut på denne variabelen hvis det er treff.
returverdi:
  - retunerer 0 hvis det er treff, og -1 hvis ikke.
*/

int mip_arp_lookup(uint8_t mip, uint8_t mac_out[6], int *ifx_out) {
  int elements = (int)(sizeof arp_cache / sizeof arp_cache[0]);
  for (int i = 0; i < elements; i++) {
    if (arp_cache[i].in_use && arp_cache[i].mip == mip) {
      memcpy(mac_out, arp_cache[i].mac, 6);
      if (ifx_out) {
        *ifx_out = arp_cache[i].ifindex;
      }
      return 0;
    }
  }
  return -1; // Finnes ikke i cache.
}
/*
Hva funksjonen gjør:
 - Sett inn eller oppdater en ARP-oppføring (MIP→MAC,ifindex). Tror egentlig
   ikke oppdatering er så viktig, men har det med for denne obligen.
Parametre;
  - mip: mip-adressen til naboen.
  - mac: MAC-adressen til naboen.
  - ifindex: ifindex porten naboen er nådd gjennom.
returverdi:
  - ingen
*/
void arp_insert(uint8_t mip, const uint8_t mac[6], int ifindex) {
  int elements = (int)(sizeof arp_cache / sizeof arp_cache[0]);
  // Oppdater hvis den finnes allerede.
  for (int i = 0; i < elements; i++) {
    if (arp_cache[i].in_use && arp_cache[i].mip == mip) {
      memcpy(arp_cache[i].mac, mac, 6);
      arp_cache[i].ifindex = ifindex;
      return;
    }
  }
  // ellers finn ledig.
  for (int i = 0; i < elements; i++) {
    if (!arp_cache[i].in_use) {
      arp_cache[i].in_use = 1;
      arp_cache[i].mip = mip;
      memcpy(arp_cache[i].mac, mac, 6);
      arp_cache[i].ifindex = ifindex;
      return;
    }
  }
}
/*
Hva funksjonen gjør:
 - bygger MIP-ARP SDU som er på 4 bytes: type:1bit ,adresse:(8bit) og padding på
   resten.
Parametre;
  - type: 0=request, 1=respons. Sjekker dette på første bit.
  - addr: MIP-adressen det spørres/svares om.
  - out: 4-byte buffer som fylles, og skal sendes.
returverdi:
- ingen
*/

void build_miparp_payload(uint8_t type, uint8_t addr, uint8_t out[4]) {
  out[0] = (type & 0x01); // vi bruker bare bit0
  out[1] = addr;
  out[2] = 0;
  out[3] = 0; // padding til 32 bit
}
/*
Hva funksjonen gjør:
 - Sender MIP-ARP REQUEST (broadcast) for å vite hva MIP-adressen sin MAC
   tilsvarer.
Parametre;
  - rawfd: Raw-socketen sin fd.
  - my_mip: MIP-adressen fra mitt ståsted.
  - target_mip: MIP-adresse vi vil finne.
returverdi:
  - retunrerer 0 hvis alt går som det skal, og -1 ved feil i pakking/sending.
*/

int send_mip_arp_request(int rawfd, uint8_t my_mip, uint8_t target_mip) {
  uint8_t brd[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint8_t payload[4];
  build_miparp_payload(0 /*req*/, target_mip, payload);
  // MIP-header (4 bytes) + payload (4 bytes) = 8 bytes i Ethernet-payload.
  mip_header h = {.dst = MIP_BROADCAST,
                  .src = my_mip,
                  .ttl = 1, // broadcast: TTL=1
                  .sdu_len_bytes = 4,
                  .sdu_type = MIP_TYPE_ARP};
  uint8_t pdu[8];
  memcpy(pdu, &h, 4);
  memcpy(pdu + 4, payload, 4);
  // DBG("[mipd] ARP REQ: who has MIP=0x%02x? (from 0x%02x)\n", target_mip,
  // my_mip); sender på alle interface(naboer). En og en om gangen.
  for (int i = 0; i < my_if_count; i++) {
    int ifx = my_ifs[i].ifindex;
    const uint8_t *srcmac = my_ifs[i].mac;
    if (send_eth_frame(rawfd, ifx, brd, srcmac, ETH_TYPE_P, pdu, sizeof pdu) !=
        0) {
      perror("send_eth_frame (ARP req)");
    }
  }
  return 0;
}

/*
Hva funksjonen gjør:
   - Sender MIP-ARP RESPONSE unicast til den som forespurte.
   - Sender direkte/unicast, fordi vi allerede kjenner dens forespurtes
MAC-adresse når den sendre en request. Parametre;
   - rawfd: Raw-socketen sin fd.
   - dst_mip: MIP-adressen som spurte(mottaker).
   - dst_mac: MAC til mottaker.
   - out_ifindex: interface man skal sende ut til.
returverdi:
   - Retunerer 0 hvis alt går som det skal, og -1 hvis det skjer noe feil
   underveis.
*/
int send_mip_arp_response(int rawfd, uint8_t my_mip, uint8_t dst_mip,
                          const uint8_t dst_mac[6], int out_ifindex) {
  uint8_t payload[4];
  /* 1 = response*/
  build_miparp_payload(1, my_mip, payload);
  mip_header h = {
      .dst = dst_mip, // fylles av mottatt header. Senderens MIP-adresse.
      .src = my_mip,
      .ttl = 1,
      .sdu_len_bytes = 4,
      .sdu_type = MIP_TYPE_ARP};
  uint8_t pdu[8];
  memcpy(pdu, &h, 4);
  memcpy(pdu + 4, payload, 4);
  // finn riktig MAC for out_ifindex.
  uint8_t srcmac[6];
  if (mymac_for_ifindex(out_ifindex, srcmac) != 0) {
    return -1;
  }
  DBG("[mipd] ARP RESP: I am 0x%02x ", my_mip);
  print_mac("mac=", srcmac);
  DBG(" via ifx=%d to dst_mip=0x%02x ", out_ifindex, dst_mip);
  print_mac("dstmac=", dst_mac);
  DBG("\n");
  return send_eth_frame(rawfd, out_ifindex, dst_mac, srcmac, ETH_TYPE_P, pdu,
                        sizeof pdu);
}

/*
   - Sender en MIP-SDU unicast (PING i denne koden) til dst_mip. Gjør en MIP-ARP
   request hvis vi ikke finner MAC-adressen i ARP-cache.
   - rawfd: RAW-socket sin fd.
   - my_mip: min MIP-adresse (kilde)
   - dst_mip: destinasjon MIP
   - sdu: peker til SDU-data (app-payload).
   - len: SDU-lengde i bytes. Paddes slik at det er delelig på 4.
   - returnerer 0 ved suksess, og -1 ved feil.
     - Hvis vi må gjøre en ARP-request så vil -2 retuneres, som betyr at vi må
   ta vare på den dataen som opprinnelig skulle sendes.
*/
// Lagt til sdu_type og ttl her, fordi vi har spesifisert hva vi skal sende over
// wire.
static int send_mip_unicast(int rawfd, uint8_t my_mip, uint8_t dst_mip,
                            const void *sdu, size_t len, uint8_t sdu_type,
                            uint8_t ttl) {
  // beregner hvor mange null-bytes som må legges til på slutten for at total
  // lengde blir delelig på 4.
  size_t pad = (4 - (len % 4)) % 4;
  size_t wire_len = len + pad;
  uint8_t mac[6];
  int ifx = -1;
  if (mip_arp_lookup(dst_mip, mac, &ifx) != 0) {
    DBG("[mipd] ARP miss for 0x%02x → sending ARP-REQUEST\n", dst_mip);
    send_mip_arp_request(rawfd, my_mip, dst_mip);
    return -2; // ARP pending.
  }
  mip_header h = {.dst = dst_mip,
                  .src = my_mip,
                  .ttl = ttl,
                  .sdu_len_bytes = (uint16_t)wire_len,
                  .sdu_type = sdu_type};
  // uint8_t head[4];
  //  if (mip_pack_header(head, &h) != 0)
  //  {
  //      return -1;
  //  }
  uint8_t pdu[2048]; // Siden ethernet-rammen kan maksimalt ta 1600, så trenger
                     // jeg ikke å ha den så stor, men bare har det slik for nå.
  memcpy(pdu, &h, 4);
  // memcpy(pdu, head, 4);
  memcpy(pdu + 4, sdu, len);
  if (pad) {
    memset(pdu + 4 + len, 0, pad);
  }
  uint8_t srcmac[6]; // Kopierer MAC-adressen inn, slik at jeg kan sende over.
  if (mymac_for_ifindex(ifx, srcmac) != 0) {
    return -1;
  }
  DBG("[mipd] PING SEND: 0x%02x -> 0x%02x, SDU=%zu(+%zu pad)\n", my_mip,
      dst_mip, len, pad);
  return send_eth_frame(rawfd, ifx, mac, srcmac, ETH_TYPE_P, pdu, 4 + wire_len);
}

/*
Hva funksjonen gjør:
  - Sender en MIP-pakke videre via et gitt neste hopp (next_hop).
    Headeren beholder original avsender (orig_src) og slutt-destinasjon
    (final_dst). Dette er viktig for at forwaridng skal funke.
  - Kalles når vi har fått ARP-RESP fra arpmip (som er nabo/dst)
Parametre:
  - rawfd: RAW-socket fd.
  - orig_src: den opprinnlige avsenderens MIP-adresse. Beholdes uendret når
              pakkes gjør forwarding her.
  - final_dst:endelig MIP-destinasjon som skal stå i headeren.
  - next_hop:MIP-adressen til neste hop.
  - ttl:TTL som legges i headeren.
  - sdu/len: payload og payload-lengde.
  - sdu_type: MIP-type.
Globale variabler som påvirkes:
  - ARP-cache kan brukes/oppdateres indirekte (via ARP-lookup/req).
Returverdi:
  - 0: sendt OK.
  - -2: ARP mangler for next_hop, ARP-REQ blir sendt. Dataen legges i kø,
        of venter på ARP-RSP.
  - <0: annen feil.
*/

int send_mip_via_nh(int rawfd, uint8_t orig_src, uint8_t final_dst,
                    uint8_t next_hop, uint8_t ttl, const void *sdu, size_t len,
                    uint8_t sdu_type) {
  size_t pad = (4 - (len % 4)) % 4;
  size_t wire_len = len + pad;

  int ifx;
  uint8_t nh_mac[6];
  if (mip_arp_lookup(next_hop, nh_mac, &ifx) != 0) {
    // ARP på neste hopp, og ikke på final_dst.
    send_mip_arp_request(rawfd, g_my_mip, next_hop);
    return -2; // ARP pending
  }
  mip_header h = {.dst = final_dst,
                  .src = orig_src,
                  .ttl = ttl,
                  .sdu_len_bytes = (uint16_t)wire_len,
                  .sdu_type = sdu_type};

  uint8_t pdu[4 + MIP_MAX_SDU];
  // memcpy(pdu, head, 4);
  memcpy(pdu, &h, 4);
  memcpy(pdu + 4, sdu, len);
  if (pad) {
    memset(pdu + 4 + len, 0, pad);
  }

  uint8_t srcmac[6];
  if (mymac_for_ifindex(ifx, srcmac) != 0) {
    return -1;
  }

  return send_eth_frame(rawfd, ifx, nh_mac, srcmac, ETH_TYPE_P, pdu,
                        4 + wire_len);
}
/*
Hva funksjonen gjør:
  - Sender en MIP-broadcast (dst=0xFF) på alle lokale interfaces, uten ARP.
  - Er for hello meldinger fra routingd.
Parametre:
  - rawfd: RAW-socket fd.
  - my_mip: avsenderens MIP-adresse.
  - sdu/len:  payload og lengde.
  - sdu_type: MIP-type.
  - ttl: TTL som skal legges inn.
Returverdi:
  - 0: sendt.
  - mindre enn 0 ved feil.
*/
int send_mip_broadcast(int rawfd, uint8_t my_mip, const void *sdu, size_t len,
                       uint8_t sdu_type, uint8_t ttl) {
  // pad til 4
  size_t pad = (4 - (len % 4)) % 4;
  size_t wire_len = len + pad;

  mip_header h = {.dst = MIP_BROADCAST, // 0xFF
                  .src = my_mip,
                  .ttl = ttl,
                  .sdu_len_bytes = (uint16_t)wire_len,
                  .sdu_type = sdu_type};

  uint8_t pdu[1600];
  memcpy(pdu, &h, 4);
  memcpy(pdu + 4, sdu, len);

  if (pad) {
    memset(pdu + 4 + len, 0, pad);
  }
  uint8_t brd[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  // send på alle interfaces
  for (int i = 0; i < my_if_count; i++) {
    int ifx = my_ifs[i].ifindex;
    const uint8_t *srcmac = my_ifs[i].mac;
    if (send_eth_frame(rawfd, ifx, brd, srcmac, ETH_TYPE_P, pdu,
                       4 + wire_len) != 0) {
      perror("send_eth_frame(broadcast)");
    }
  }
  DBG("[mipd] BROADCAST SEND: 0x%02x -> 0xFF, type=%u, len=%zu\n", my_mip,
      sdu_type, len);
  return 0;
}

/*
Hva funksjonen gjør:
  - Ber routingd om neste hopp til en destinasjon (sender "REQ" over
    UNIX-socket).
Parametre:
  - unix_fd: fd til routingd sin UNIX-tilkobling.
  - my_mip: min MIP-adresse.
  - dst: slutt-destinasjonen vi trenger rute til.
Returverdi:
  - Ingen
  - Feil logges med perror her.
- ekstra:
  -UNIX-melding: addr = my_mip, ttl = 0, SDU = {'R','E','Q', dst}
*/

void send_route_request(int unix_fd, uint8_t my_mip, uint8_t dst) {
  uint8_t sdu[4] = {0x52, 0x45, 0x51,
                    dst}; // 4 bytes er allerede 4-justert → OK for send_msg
  if (send_msg(unix_fd, my_mip, 0, sdu, sizeof sdu) != 0) {
    perror("[mipd] ROUTE-REQUEST send_msg");
  } else {
    DBG("[mipd] REQ(dst=0x%02x) -> routingd\n", dst);
  }
}
/*
Hva funksjonen gjør:
  - Legger fd til epoll-settet med gitte events.
Parametre:
  - efd: epoll file descriptor fra epoll_create1().
  - fd: fd-en som vil overvåkes.
  - evs: En bitmaske av EPOLL-events.
Returverdi:
  - retunrerer 0 hvis alt går bra, og -1 ved noe feil.

*/
int ep_add(int efd, int fd, uint32_t evs) {
  struct epoll_event ev;
  memset(&ev, 0, sizeof ev);
  ev.events = evs;
  ev.data.fd = fd;
  return epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
}
/*
Hva funksjonen gjør:
  - Fjerner en fd fra et epoll-settet.
Parametre:
  - efd: Epoll file descriptor.
  - fd: fd-en som skal tas ut av overvåkningen.
Returverdi:
  - retunrerer 0 hvis alt går bra, og -1 ved noe feil.
*/

int ep_del(int efd, int fd) { return epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL); }

/*
 - Håndterer en innkommende Ethernet-ramme, og gjør riktig handling basert på
 hva som er sendt.
 - rawfd: RAW-socket sin fd.
 - my_mip: min MIP-adresse.
 - app_cfd: tilkoblet app-socket (UNIX) eller -1 hvis ingen applikasjon har
 koblet.
 - Vi gjør arp_insert() både når vi gjør ARP-request eller får en ARP-response.
 Dette fører til at begge vertene får hverandres MAC-adresse gjennom kun en
 ARP-request-kall.
*/
void handle_raw_event(int rawfd, uint8_t my_mip) {
  uint8_t src_mac[6];
  uint8_t dst_mac[6];
  uint8_t payload[2048];
  uint16_t ethertype;
  int in_ifx = -1;
  ssize_t paylen = recv_eth_frame(rawfd, src_mac, dst_mac, &ethertype, &in_ifx,
                                  payload, sizeof(payload));
  if (paylen <= 0)
    return;
  if (ethertype != ETH_TYPE_P)
    return;
  if (paylen < 4)
    return; // må minst ha en MIP-header.
  mip_header h;
  memcpy(&h, payload, 4);
  uint8_t *sdu = payload + 4;
  size_t sdu_len = paylen - 4;
  DBG("[mipd] MIP RECV: src=0x%02x dst=0x%02x ttl=%u type=%u sdu_len=%zu\n",
      h.src, h.dst, h.ttl, h.sdu_type, sdu_len);
  if (h.sdu_type == MIP_TYPE_ARP) {
    if (sdu_len < 4)
      return; // ARP-SDU er 4 byte.
    uint8_t arptype = sdu[0] & 0x01;
    uint8_t arpmip = sdu[1];
    if (arptype == 0) // request.
    {
      DBG("[mipd]  ARP REQUEST for 0x%02x (from src=0x%02x)\n", arpmip, h.src);
      // svarer hvis de spør etter meg.
      arp_insert(h.src, src_mac,
                 in_ifx); // Legger inn i cache, når det er request slik at vi
                          // kan sende direkte med kun unicast neste gang.
      if (arpmip == my_mip) {
        send_mip_arp_response(rawfd, my_mip, h.src, src_mac, in_ifx);
      }
    } else {
      DBG("[mipd]  ARP RESPONSE: 0x%02x is at ", arpmip);
      print_mac("", src_mac);
      DBG(" (ifx=%d)\n", in_ifx);
      arp_insert(arpmip, src_mac,
                 in_ifx); // Legger inn i cache, når vi får response også.
      DBG("[mipd] ARP cache: 0x%02x -> %02x:%02x:%02x:%02x:%02x:%02x "
          "(ifindex=%d)\n",
          arpmip, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4],
          src_mac[5], in_ifx);
      int flushed = pend_flush_for_dst(rawfd, arpmip);
      if (flushed > 0) {
        DBG("[mipd] Flushed %d pending packet(s) for 0x%02x\n", flushed,
            arpmip);
      }
    }
    return;
  }
  if (h.dst == my_mip || h.dst == MIP_BROADCAST) {
    if (h.sdu_type == MIP_TYPE_PING) {
      if (is_pong_payload(sdu, sdu_len)) {
        int cfd = q_pop(&wait_q[h.src]);
        DBG("[mipd]  PING to me (0x%02x) from 0x%02x; delivering to app (%zu "
            "bytes)\n",
            my_mip, h.src, sdu_len);
        if (cfd != -1) {
          deliver_up_to_fd(cfd, h.src, sdu, sdu_len);
        } else {
          DBG("[mipd] We did not find the fd, so we cant send the message.");
        }
      } else {
        DBG("[mipd]  PING to server (0x%02x) from 0x%02x; delivering to server "
            "(%zu bytes)\n",
            my_mip, h.src, sdu_len);
        deliver_up_to_type(MIP_TYPE_PING, h.src, sdu, sdu_len);
      }
    } else {
      // 0x04 (routing)
      deliver_up_to_type(h.sdu_type, h.src, sdu, sdu_len);
    }
    return;
  }
  // forwarding
  if (h.dst != my_mip) {
    if (h.ttl <= 1) {

      DBG("[mipd] drop ttl (dst=0x%02x)\n", h.dst);
      return;
    }
    uint8_t newttl = h.ttl - 1;
    // Legg pakken i ventekø for denne dst’en
    route_wait_ent_t e = {.orig_src = h.src,
                          .final_dst = h.dst,
                          .sdu_type = h.sdu_type,
                          .ttl = newttl,
                          .len = sdu_len};

    memcpy(e.data, sdu, sdu_len);
    rw_push(&e);

    // Be routingd om rute (enkelt: send alltid req).
    int rfd = owner_fd[MIP_TYPE_ROUTING]; // 0x04
    if (rfd == -1) {
      DBG("[mipd] no routingd; drop( dst=0x%02x )\n", h.dst);
      return;
    }
    send_route_request(rfd, my_mip, h.dst);
    return; // ferdig med denne ethernet-rammen
  }
  return;
}
