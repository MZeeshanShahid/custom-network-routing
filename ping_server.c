
#include "unix_ipc.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void server_print_usage(const char *prog);
static int connect_unix(const char *path);
/*
Hva funksjonen gjør:
 - Kobler til mipd via UNIX SOCK_SEQPACKET. Vdere lytter serveren på meldinger
   fra mipd hele tiden.
 - Dersom serveren mottar data, vil den svare tilbake med "PONG: <samme tekst>"
   med send_msg til mipd som vidre sender daten videre.
Parametre:
  - argc: antall argumenter.
  - argv: argumentvektor.
Returverdi:
 - Retunerer 0 ved normal avslutning, og -1 ved argumentfeil eller

*/
int main(int argc, char **argv) {

  if (argc >= 2 && strcmp(argv[1], "-h") == 0) {
    server_print_usage(argv[0]);
    return 0;
  }

  if (argc < 2)

  {
    fprintf(stderr, "bruk: %s <unix_path>\n", argv[0]);
    return 1;
  }

  const char *path = argv[1];
  int fd = connect_unix(path);

  if (send_registration(fd, 0x02) != 0) {
    perror("send_registration");
    close(fd);
    return 1;
  }

  printf("[server] Tilkoblet mipd på %s - venter på PING\n", path);

  for (;;) {
    uint8_t src_mip;
    uint8_t ttl_in;
    uint8_t sduIN[MIP_MAX_SDU];

    // Her mottar vi PING, og setter verdiene inn i src_mip og sduIN.
    ssize_t n = recv_msg(fd, &src_mip, &ttl_in, sduIN, sizeof sduIN);

    if (n <= 0) {
      if (n < 0) {
        perror("[server] recv_msg");
      } else {
        fprintf(stderr, "[server] peer closed\n");
      }

      break;
    }
    // “klipper bort” null-bytes (0x00) på slutten av den mottatte SDU-en før vi
    // skriver den som tekst.
    size_t used = (size_t)n;
    while (used > 0 && sduIN[used - 1] == 0) {
      used--;
    }
    // Skriv mottatt tekst
    char txt[2048];
    size_t p = used;

    if (p > sizeof(txt) - 1) {
      p = sizeof(txt) - 1; // holder av 1 byte til '\0'.
    }
    memcpy(txt, sduIN, p);
    txt[p] = '\0';

    printf("[server] PING fra 0x%02x, len=%zd: \"%s\"\n", src_mip, n, txt);

    const char *msg = txt;
    if (strncmp(txt, "PING:", 5) == 0) {
      msg += 5; // hopper over "PING:" som vi mottok.
    }

    // Bygger teksten slik: PONG:<tekst>
    char out_text[2048];
    int wn = snprintf(out_text, sizeof out_text, "PONG: %s", msg);

    if (wn < 0 || wn > (int)MIP_MAX_SDU) {
      fprintf(stderr, "[server] svar for langt\n");
      continue;
    }

    size_t wire = pad4((size_t)wn);
    uint8_t sdu[MIP_MAX_SDU];

    memcpy(sdu, out_text, (size_t)wn);
    if (wire > (size_t)wn) {
      memset(sdu + wn, 0, wire - (size_t)wn);
    }

    // Sender PONG-meldingen tilbake til mipd lokalt.
    if (send_msg(fd, src_mip, 0, sdu, wire) !=
        0) //(la mipd velge default for TTL)
    {
      perror("[server] send_msg");
      break;
    }
    printf("[server] sendte PONG til 0x%02x, len=%zu\n", src_mip, wire);
  }
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
static void server_print_usage(const char *prog) {
  printf("Usage: %s [-h] <socket_lower>\n"
         "Options:\n"
         "  -h    prints help and exits the program\n"
         "Arguments:\n"
         "  socket_lower  pathname of the socket that the MIP daemon uses to "
         "communicate with upper layers.\n",
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