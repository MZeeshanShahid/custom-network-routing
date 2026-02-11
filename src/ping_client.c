#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "mip.h"
#include "unix_ipc.h" // pad4, send_msg, recv_msg ligger i denne, som jeg bruker her.

static void client_print_usage(const char *prog);
static int connect_unix(const char *path);
static int set_recv_timeout(int fd, int sec, int usec);
static double now_ms(void);

/*
Hva funksjonen gjør:
 - Her leser vi argumentene korrekt.
 - Vi bygger SDU, og padder riktig, slik at det er en multiplum av 4.
 - Koblet mot mipd (UNIX SOCK_SEQPACKET), og setter SO_RCVTIMEO=1s.
 - Vi sender SDU (send_msg), og venter på PONG (recv_msg), samtidig som vi måler
   RTT.
Parametre:
  - argc: antall argumenter.
  - argv: argumentvektor.
Returverdi:
 - Retunerer 0 hvis alt går bra, eller hvis vi får en timeout uten spesielle
 feil.
 - Retunerer 1 ved argumentfeil, valideringsfeil eller feil når vi sender/mottar
   data.
*/
int main(int argc, char **argv) {

  if (argc >= 2 && strcmp(argv[1], "-h") == 0) {
    client_print_usage(argv[0]);
    return 0;
  }

  if (argc < 5) {
    client_print_usage(argv[0]);
    return 1;
  }

  const char *sock_path = argv[1];
  const char *user_msg = argv[2];
  uint8_t dst_mip = (uint8_t)strtoul(
      argv[3], NULL, 0); // Gjør at argumentet støtter 11 eller 0x0B f.eks.
  uint8_t ttl = (uint8_t)strtoul(argv[4], NULL, 0);

  if (ttl > 15) {
    fprintf(stderr, "Error: ttl must be in [0,15]\n");
    return 1;
  }

  // Bygger teksten her slik: "PING:<msg>"
  char text[MIP_MAX_SDU];
  int wn = snprintf(text, sizeof text, "PING: %s", user_msg);
  if (wn < 0 || wn > (int)MIP_MAX_SDU) {
    fprintf(stderr, "[klient] melding for lang\n");
    return 1;
  }

  size_t wire = pad4((size_t)wn); // Runder opp til nærmeste multiplum av 4.
  if (wire > MIP_MAX_SDU) {
    fprintf(stderr, "[klient] SDU for stor\n");
    return 1;
  }

  // SDU-buffer som er paddet slik at det er et multiplum av 4.
  uint8_t sdu[MIP_MAX_SDU];
  memcpy(sdu, text, (size_t)wn);
  if (wire > (size_t)wn)
    memset(sdu + wn, 0, wire - (size_t)wn);

  int fd = connect_unix(sock_path);
  if (fd < 0)
    return 1;

  // registrer SDU-type 0x02 (Ping) en byte etter connect().

  if (send_registration(fd, 0x02) != 0) {
    perror("send_registration");
    close(fd);
    return 1;
  }

  if (set_recv_timeout(fd, 1, 0) != 0) {
    close(fd);
    return 1;
  }

  printf("[klient] Sending to dst_mip=0x%02x, SDU_len=%zu (pad=%zu): \"%s\"\n",
         dst_mip, wire, wire - (size_t)wn, text);

  double t0 = now_ms();

  if (send_msg(fd, dst_mip, ttl, sdu, wire) != 0) {
    fprintf(stderr, "[klient] send_msg feilet\n");
    close(fd);
    return 1;
  }

  // Venter på PONG fra mipd over UNIX-socketen.
  uint8_t src_mip = 0;
  uint8_t ttl_in = 0;
  uint8_t buf[MIP_MAX_SDU];
  ssize_t n = recv_msg(fd, &src_mip, &ttl_in, buf, sizeof buf);

  if (n < 0) {
    printf("timeout\n");
    close(fd);
    return 0;
  }

  if (n <= 0) {
    fprintf(stderr, "[klient] recv_msg feilet (%zd)\n", n);
    close(fd);
    return 1;
  }

  double t1 = now_ms();
  double rtt_ms = t1 - t0;

  // Fjerner null-padding på slutten før vi skriver ut som tekst.
  size_t used = (size_t)n;
  while (used > 0 && buf[used - 1] == 0)
    used--;

  char printable[MIP_MAX_SDU];
  size_t cap = sizeof printable - 1;
  size_t copy = used;
  if (copy > cap) {
    copy = cap;
  }
  memcpy(printable, buf, copy);
  printable[copy] = '\0';

  printf("[klient] Answer from src_mip=0x%02x, len=%zd, RTT=%.2f ms, text: "
         "\"%s\"\n",
         src_mip, n, rtt_ms, printable);

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
*/
static void client_print_usage(const char *prog) {
  printf("Usage: %s [-h] <socket_lower> <message> <destination_host>\n"
         "Options:\n"
         "  -h    prints help and exits the program\n"
         "Arguments:\n"
         "  socket_lower      pathname of the socket that the MIP daemon uses "
         "to communicate with upper layers.\n"
         "  message           the message that needs to be sent\n"
         "  destination_host  MIP address of the destination host\n",
         prog);
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
  - Setter en mottakstimeout (SO_RCVTIMEO) på en socket.
  - Funksjonen kaller setsockopt(SOL_SOCKET, SO_RCVTIMEO) med gitt (sec,usec).
parametre:
  - fd: åpen socket-fd.
  - (sec,usec) = grensen for hvor lenge socketen kan vente før det skjer en
    timeout (1 sekund).
  - sec/usec: timeout-variabler på sekunder og mikrosekunder.
Retuverdi;
  - Retunerer 0 dersom alt går som det skal, og -1 hvis det skjer feil med
  setsockopt() kallet.
*/

static int set_recv_timeout(int fd, int sec, int usec) {
  struct timeval tv = {.tv_sec = sec, .tv_usec = usec};
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0) {
    perror("setsockopt(SO_RCVTIMEO)");
    return -1;
  }
  return 0;
}
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
