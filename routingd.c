
#include "mip.h"
#include "unix_ipc.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
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
// sender hello-meldinger hvert sekund til alle naboer.
#define HELLO_MS 1000
// timeout nabo etter tre sekunder uten hello-melding.
#define NEIGH_TIMEOUT 3000
// sender update-meldinger hvert andre sekund til alle naboer.
#define UPDATE_MS 2000
// uendelig kost i DVR (ikke nåbar rute).
// Brukes i poisoned reverse og for å invaliderer/markere at en rute er brutt.
#define INF_COST 0xFFFF
/*
 - Structet viser en oppføring i rutetabellen (DVR), som holder oversikt over
    alle ende-destinasjoner i nettverket, og hvilken nabo det er best å gå til
    for å komme til dest.
 - valid: 1 hvis oppføringen i rtable er en gyldig rute, ellers 0.
 - dest: MIP-adressen til destinasjonen denne ruta gjelder.
 - next_hop: Hvilken nabo-mip det er best å gå til for å komme kjappest til
             dest.
 - cost: akkumulert kost (hopp) til dest.
 - last_updated_ms: Når oppføringen sist ble oppdatert.
*/
typedef struct {
  uint8_t valid;
  uint8_t dest;
  uint8_t next_hop;
  uint16_t cost;
  double last_updated_ms; // vet ikke om jeg trenger denne enda.
} route_t;
/*
 - Structet viser info om en direkte nabo vi har sett nylig via HELLO.
 - present: 1 hvis naboen er aktiv/sist sett innen timeout, ellers 0.
 - mip: naboens MIP-adresse.
 - last_hello_ms: antall ms for sist mottatte HELLO fra denne naboen.
*/
typedef struct {
  uint8_t present;
  uint8_t mip;
  double last_hello_ms;
} neighbor_t;
/*
 - Tabell over direkte naboer, som er indeksert på MIP-adresse (0 til 255).
 - Oppdateres av handle_hello() og invalideres ved timeout i hovedløkken.
*/
static neighbor_t neighbors[256];
static route_t rtable[256];
// for debug/printing
static void print_usage(const char *prog);
/*
 - Bruker de ikke i koden nå.
 - Brukte de for debug for å sjekke om tabellene så riktig ut.
 - Kan kommenteres ut hvis det er ønskelig å bruke de.
*/
// static void dump_neighbors(void);
// static void dump_rtable(void);

// Gir meg nåtid i millisekunder.
static double now_ms(void);
// UNIX tilkobling.
static int connect_unix(const char *path);
// håndterer hello-protokollen.
static int send_hello(int unix_fd);
static void handle_hello(uint8_t src_mip);
// Håndterer update-protokollen.
static int send_update_to_neighbor(int ufd, uint8_t neighbor_mip);
static int send_updates(int ufd);
// Håndterer REQ/RSP mot mipd og UPDATE-mottak
static void handle_update(uint8_t src_mip, const uint8_t *buf, ssize_t n);
static void handle_req(int unix_fd, uint8_t src_mip, const uint8_t *buf,
                       ssize_t n);
static uint8_t next_hop_for(uint8_t dst);
static void poison_routes_via(uint8_t dead_neighbor);
// epoll hjelper.
static int ep_add(int efd, int fd, uint32_t evs);
/*
Hva funksjonen gjør:
  - Starter routingd, og kobler til mipd over UNIX-socket, registrerer SDU-type
    til mipd, og kjører epoll-løkka. I tillegg håndterer den argumenter som blir
    skrevet inn.
  - Håndterer innkommende meldinger fra mipd (HELLO/UPDATE/REQ) og sender
    periodiske HELLO og UPDATE-meldinger til naboer.
  - Utfører timeouts for naboer og invaliderer rutene
    ved timeout.
Parametre:
  - argc: antall argumenter.
  - argv: argumentvektor.
Globale variabler som påvirker (egentlig alle):
  - g_debug: styrer DBG-logging.
  - neighbors[256]: initieres og oppdateres ved HELLO og ved timeout.
  - my_ifs[]: fylt av collect_local_ifaces().
  - rtable[256]: initieres og oppdateres av handle_hello()/handle_update()
                 og invalideres ved neighbor-timeout.
Returverdi:
 - 0 ved normal avsltuning. terminering av hovedløkka eller -h inn som kommando.
 - 1 ved systemfeil, som socket osv.
 - 2 ved brukerfeil, ved at man skriver ugyldige argumenter.
*/
int main(int argc, char **argv) {
  const char *path = NULL;
  // For å skrive inn -d og -h som argumenter.
  int i = 1;
  while (i < argc) {
    const char *arg = argv[i];
    if (arg[0] != '-')
      break; // Vi bruker ikke - som betyr at vi kan starte på path.
    if (strcmp(arg, "-h") == 0) {
      print_usage(argv[0]);
      return 0;
    } else if (strcmp(arg, "-d") == 0) {
      g_debug = 1;
      i++;
      continue;
    } else {
      fprintf(stderr, "Ukjent flagg: %s\n\n", arg);
      print_usage(argv[0]);
      return 2; /* retunerer 2 når det er noe kommando-feil*/
    }
  }
  if (argc - i != 1) {
    fprintf(stderr, "Error: expected <socket_upper>. \n");
    print_usage(argv[0]);
    return 2;
  }
  path = argv[i];
  int fd = connect_unix(path);
  if (fd < 0) {
    return 1;
  }
  // registrer SDU-type 0x04 til mipd. (routing)
  if (send_registration(fd, 0x04) != 0) {
    perror("send_registration");
    close(fd);
    return 1;
  }
  DBG("[routingd] connected to %s and registered type 0x04\n", path);
  int epfd = epoll_create1(0);
  if (epfd == -1) {
    perror("epoll_create1");
    close(fd);
    return 1;
  }
  // Overvåker nye forbindelser
  if (ep_add(epfd, fd, EPOLLIN) == -1) {
    perror("epoll_ctl ADD lfd");
    close(epfd);
    close(fd);
    return 1;
  }
  memset(neighbors, 0, sizeof neighbors);
  memset(rtable, 0, sizeof rtable);
  // Planlegger første HELLO
  double next_hello_ms = now_ms() + HELLO_MS;
  // planlegger første UPDATE
  double next_update_ms = now_ms() + UPDATE_MS;
  const int MAX = 32;
  struct epoll_event events[MAX];
  for (;;) {
    int n = epoll_wait(epfd, events, MAX, 1000);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("epoll_wait");
      break;
    }
    // håndter innkommende HELLO, UPDATE og REQUEST-pakker.
    for (int k = 0; k < n; k++) {
      if ((events[k].events & EPOLLIN) && events[k].data.fd == fd) {
        uint8_t src_mip, ttl;
        uint8_t buf[UPPER_MAX_MSG];
        ssize_t r = recv_msg(fd, &src_mip, &ttl, buf, sizeof buf);
        if (r < 0) {
          perror("recv_msg");
          continue;
        }
        if (r == 0) {
          DBG("[routingd] mipd closed — exit\n");
          close(epfd);
          close(fd);
          return 0;
        }
        // Mottar "Hello-pakke":
        if (r >= 1 && buf[0] == 'H') {
          handle_hello(src_mip);
          continue;
        }
        // Mottar "Update-pakke":
        if (r >= 2 && buf[0] == 'U') {
          handle_update(src_mip, buf, r);
          continue;
        }
        // Mottar "Request-pakke":
        if (r >= 4 && buf[0] == 'R' && buf[1] == 'E' && buf[2] == 'Q') {
          handle_req(fd, src_mip, buf, r);
          continue;
        }
      }
    }
    // periodisk HELLO, som sendes hvert sekund.
    double now = now_ms();
    if (now >= next_hello_ms) {
      if (send_hello(fd) < 0) { // dst=0xFF, ttl=1
        DBG("Sending av hello feilet!\n");
      }
      next_hello_ms = now + HELLO_MS; // planlegger neste.
    }
    if (now >= next_update_ms) {
      send_updates(fd);
      next_update_ms = now + UPDATE_MS;
    }
    // nabo timeouts.
    for (int m = 0; m < 256; m++) {
      if (neighbors[m].present &&
          now - neighbors[m].last_hello_ms > NEIGH_TIMEOUT) {
        neighbors[m].present = 0;
        // poison alt via m.
        poison_routes_via((uint8_t)m);
        // kjører med en gang. Venter ikke på neste auto UPDATE.
        send_updates(fd);
        DBG("[routingd] neighbor 0x%02x timed out — direct route invalidated\n",
            m);
      }
    }
  }
  close(epfd);
  close(fd);
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
static void print_usage(const char *prog) {
  printf("Usage: %s [-h] [-d] <socket_upper>\n"
         "Options:\n"
         "  -d    enable debugging mode\n"
         "  -h    prints help and exits the program\n"
         "Arguments:\n"
         "  socket_upper  pathname of the UNIX socket.\n",
         prog);
}
// To print ut funksjoner for å se aktive naboer, og rutetabellen.
/*
Hva funksjonen gjør:
 - Skriver ut alle kjente naboer med hvor lenge siden sist HELLO.
Returverdi:
 - ingen.
*/
// static void dump_neighbors(void) {
//   double now = now_ms();
//   DBG("[routingd] Neighbors:\n");
//   for (int m = 0; m < 256; m++) {
//     if (neighbors[m].present) {
//       double age = now - neighbors[m].last_hello_ms;
//       DBG("  mip=0x%02x  last_hello=%.0fms ago\n", m, age);
//     }
//   }
// }
/*
Hva funksjonen gjør:
 - Skriver ut rutetabellen (dest, neste hopp, kost og siste den ble oppdatert).
Returverdi:
 - ingen.
*/
// static void dump_rtable(void) {
//   double now = now_ms();
//   DBG("[routingd] Routing table:\n");
//   for (int d = 0; d < 256; d++) {
//     if (rtable[d].valid) {
//       double age = now - rtable[d].last_updated_ms;
//       DBG("  dest=0x%02x  next_hop=0x%02x  cost=%u  age=%.0fms\n",
//           rtable[d].dest, rtable[d].next_hop, (unsigned)rtable[d].cost, age);
//     }
//   }
// }
/*
Hva funksjonen gjør:
 - Gir nåværende tid i millisekunder.
 - Leser tid fra gettimeofday.
Returverdi:
  - nåværende millisekund.
*/
static double now_ms(void) {
  struct timeval time;
  gettimeofday(&time, NULL);
  return (double)time.tv_sec * 1000.0 + (double)time.tv_usec / 1000;
}
/*
Hva funksjonen gjør:
  - Oppretter en lyttende UNIX server-socket som mipd lytter på. Dette
    foregår lokalt.
Parametre:
  - path: Filsti til socket (f.eks. /tmp/mipd.sock).
Returverdi;
  - fd vil være større eller >= når alt er korrekt, og -1 ved feil.
  - perror() vil kalles på feil når det kommer til socket/bind/listen.
*/
static int connect_unix(const char *path) {
  int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd == -1) {
    perror("socket");
    return -1;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
  if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == -1) {
    perror("connect");
    close(fd);
    return -1;
  }
  return fd;
}
/*
Hva funksjonen gjør:
  - Sender en HELLO-SDU ('H') som broadcast (dst=0xFF, ttl=1).
Parametre:
  - unix_fd: tilkoblingen til mipd.
Returverdi:
  - 0 ved suksess, -1 ved feilm hvor jeg logger med DBG.
*/
static int send_hello(int unix_fd) {
  uint8_t hello[4] = {'H', 0, 0, 0}; // Slik at det er 4-byte justert.
  ssize_t rc = send_msg(unix_fd, MIP_BROADCAST, 1, hello, sizeof hello);
  if (rc < 0) {
    DBG("[routingd] send_hello: rc=%zd error\n", rc);
    return -1;
  }
  DBG("[routingd] HELLO sent (dst=0xFF, ttl=1)\n");
  return 0;
}
/*
Hva funksjonen gjør:
  - Oppdaterer nabotabellen ved mottatt HELLO og legger inn direkte rute
    (kost=1).
Parametre:
  - src_mip: MIP-adressen til naboen som sendte HELLO.
Globale variabler som påvirkes:
  - neighbors[src_mip] settes/oppdateres.
  - rtable[src_mip] settes som gyldig direkte rute.
Returverdi:
  - Ingen.
*/
static void handle_hello(uint8_t src_mip) {
  double t = now_ms();
  neighbors[src_mip].present = 1;
  neighbors[src_mip].mip = src_mip;
  neighbors[src_mip].last_hello_ms = t;
  rtable[src_mip].valid = 1; // direkte rute
  rtable[src_mip].dest = src_mip;
  rtable[src_mip].next_hop = src_mip; // ett hopp:naboen selv
  rtable[src_mip].cost = 1;
  rtable[src_mip].last_updated_ms = t;
  DBG("[routingd] HELLO from 0x%02x -> neighbor + direct route cost=1\n",
      src_mip);
  // dump_neighbors();
  // dump_rtable();
}
/*
Hva funksjonen gjør:
  - Bygger og sender UPDATE-melding som skal sendes til en nabo.
  - Bruker poisoned reverse: ruter som går via naboen annonseres som INF_COST.
Parametre:
  - ufd: UNIX-socket fd til mipd.
  - neighbor_mip: MIP-adresse til naboen vi sender til.
Globale variabler som påvirkes:
  - Leser rtable[] når oppføringer pakkes.
Returverdi:
  - 0 ved suksess, -1 ved feil.
Ekstra:
 - Update-pakken: ["U",count,oppføring1,oppføring2...]: U, sier at det er en
   update pakke, count
 - count: Antall oppføringer vi skal lese.
 - Oppføring: (dest,cost)
*/
static int send_update_to_neighbor(int ufd, uint8_t neighbor_mip) {
  uint8_t buf[UPPER_MAX_MSG];
  size_t off = 0; // peker på hvor vi skal skrive inn i bufferet.
  buf[off] = 'U';
  off += 1;
  size_t npos =
      off;      // plassen i buf vi skal legge antall N (antall oppføringer)
  buf[off] = 0; // midlertidig 0. fylles når vi vet N.
  off += 1;
  uint8_t count = 0; // teller antall N vi faktisk skriver inn.
  for (int d = 0; d < 256; d++) {
    if (!rtable[d].valid) {
      continue;
    }
    uint16_t adv = rtable[d].cost;
    if (rtable[d].next_hop == neighbor_mip) {
      adv = INF_COST; // Poisoned Reverse.
    }
    if (off + 3 > sizeof(buf)) {
      break;
    }
    // Skriv dest inn (en byte)
    buf[off] = (uint8_t)d;
    off += 1;
    // Skriver kost i nettverksrekkefølge.
    uint16_t be = htons(adv);
    memcpy(buf + off, &be, 2);
    off += 2;
    count += 1; // en ny oppføring lagt inn.
  }
  buf[npos] = count;
  size_t send_len = pad4(off);
  if (send_len > off) {
    memset(buf + off, 0, send_len - off);
  }
  // Skal sendes til riktig nabo nå (neighbor_mip)
  if (send_msg(ufd, neighbor_mip, 1, buf, send_len) < 0) {
    perror("[routingd] send_update send_msg");
    return -1;
  }
  DBG("[routingd] UPDATE -> 0x%02x (N=%u)\n", neighbor_mip, count);
  return 0;
}
// sender til alle naboer. Kan ta noen feilsjekker her etter hvert.
/*
Hva funksjonen gjør:
  - Sender UPDATE til alle kjente naboer (de med present=1).
Parametre:
  - ufd: fd-en til mipd.
Returverdi:
  - 0 (best-effort); enkeltkall kan feile, men funksjonen fortsetter.
*/
static int send_updates(int ufd) {
  for (int i = 0; i < 256; i++) {
    if (neighbors[i].present) {
      send_update_to_neighbor(ufd, (uint8_t)i);
    }
  }
  DBG("[routingd] UPDATE sent to alle naboer\n");
  return 0;
}
/*
Hva funksjonen gjør:
  - Behandler mottatt UPDATE ('U') fra nabo og oppdaterer rutetabellen.
  - Kost via nabo = annonsert kost + 1.
  - INF_COST fra nabo invaliderer ruter via nabo.
Parametre:
  - src_mip:MIP-adressen til naboen som sendte UPDATE.
  - buf: peker til mottatt SDU-innhold.
  - n: lengde på SDU (bytes).
Globale variabler som påvirkes:
  - rtable[]: oppføringer legges til/oppdateres/invalideres.
Returverdi:
  - Ingen.
*/
static void handle_update(uint8_t src_mip, const uint8_t *buf, ssize_t n) {
  if (n < 2 || buf[0] != 'U') {
    return;
    DBG("Can not handle the given update pack from 0x%02x", src_mip);
  }
  uint8_t N = buf[1];
  const uint8_t *p = buf + 2;
  const uint8_t *end = buf + n;
  double t = now_ms();
  for (uint8_t i = 0; i < N; i++) {
    if (p + 3 > end) {
      break;
    }
    uint8_t dest = p[0];
    uint16_t be;
    memcpy(&be, p + 1, 2);
    p += 3;
    uint16_t adv_cost = ntohs(be);
    if (adv_cost == INF_COST) {
      if (rtable[dest].valid && rtable[dest].next_hop == src_mip) {
        rtable[dest].valid = 0;
        DBG("[routingd] PR from 0x%02x: invalidate dest=0x%02x\n", src_mip,
            dest);
      }
      continue;
    }
    uint32_t via_cost = (uint32_t)adv_cost + 1;
    if (via_cost > 0xFFFF) {
      via_cost = 0xFFFF;
    }
    if (!rtable[dest].valid || via_cost < rtable[dest].cost ||
        rtable[dest].next_hop == src_mip) {
      rtable[dest].valid = 1;
      rtable[dest].dest = dest;
      rtable[dest].next_hop = src_mip;
      rtable[dest].cost = (uint16_t)via_cost;
      rtable[dest].last_updated_ms = t;
      DBG("[routingd] UPDATE via 0x%02x: dest=0x%02x cost=%u\n", src_mip, dest,
          (unsigned)via_cost);
    }
  }
  DBG("[routingd] handled UPDATE from 0x%02x\n", src_mip);
  // dump_neighbors();
  // dump_rtable();
}

/*
Hva funksjonen gjør:
  - Behandler en ruteforespørsel (REQ) fra mipd og svarer med RSP(nhop).
Parametre:
  - unix_fd: UNIX-socket fd til mipd.
  - src_mip: MIP-adressen til verten som spurte (brukt i send_msg).
  - buf: peker til mottatt SDU (forventer 'R','E','Q',dst).
  - n: lengde på SDU (bytes).
Globale variabler som påvirkes:
  - Leser rtable[] via next_hop_for().
Returverdi:
  - Ingen (sender svar til mipd).
- Ekstra:
  - MIPD -> routingd: REQ-SDU = {'R','E','Q', dst}
  - routingd -> MIPD:  RSP-SDU = {'R','S','P', nhop}
*/
static void handle_req(int unix_fd, uint8_t src_mip, const uint8_t *buf,
                       ssize_t n) {
  if (n < 4)
    return; // for kort
  if (buf[0] != 'R' || buf[1] != 'E' || buf[2] != 'Q') {
    return;
  }
  uint8_t dst = buf[3];
  uint8_t nhop = next_hop_for(dst);
  uint8_t rsp[4] = {'R', 'S', 'P', nhop};
  // svarer til MIP-daemonen på samme socket, med addr=src_mip, ttl=0
  if (send_msg(unix_fd, src_mip, 0, rsp, sizeof rsp) != 0) {
    perror("[routingd] send RESPONSE");
  } else {
    DBG("[routingd] REQ(dst=0x%02x) -> RSP(nhop=0x%02x)\n", dst, nhop);
  }
}

/*
Hva funksjonen gjør:
  - Går gjennom hele rutetabellen og setter kost=INF_COST for ALLE destinasjoner
    der next_hop == dead_neighbor (altså ruter som gikk via denne naboen).
  - Beholder valid=1 og next_hop=dead_neighbor på de,
    slik at de annonseres som "uendelig" i neste UPDATE.
Parametre:
  - dead_neighbor: MIP-adressen til naboen som er tapt (timeout).
Globale variabler som påvirkes:
  - rtable[256]
Returverdi:
  - Ingen
*/
static void poison_routes_via(uint8_t dead_neighbor) {
  double t = now_ms();

  // Poison direkte rute til naboen selv
  rtable[dead_neighbor].valid = 1;
  rtable[dead_neighbor].dest = dead_neighbor;
  rtable[dead_neighbor].next_hop = dead_neighbor;
  rtable[dead_neighbor].cost = INF_COST;
  rtable[dead_neighbor].last_updated_ms = t;

  // Poison alle ruter som gikk via naboen
  for (int d = 0; d < 256; d++) {
    if (rtable[d].valid && rtable[d].next_hop == dead_neighbor) {
      rtable[d].cost = INF_COST;
      rtable[d].last_updated_ms = t;
    }
  }
}
/*
Hva funksjonen gjør:
  - Slår opp neste hopp for en destinasjon i rtable.
Parametre:
  - dst: destinasjonens MIP-adresse.
Returverdi:
  - Neste hopp (MIP) hvis rute finnes. Ellers 255 (ingen rute).
*/
static uint8_t next_hop_for(uint8_t dst) {
  if (rtable[dst].valid && rtable[dst].cost != INF_COST) {
    return rtable[dst].next_hop;
  }
  return 255; // spesifikasjonen: 255 == fant ikke rute.
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
static int ep_add(int efd, int fd, uint32_t evs) {
  struct epoll_event ev;
  memset(&ev, 0, sizeof ev);
  ev.events = evs;
  ev.data.fd = fd;
  return epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
}