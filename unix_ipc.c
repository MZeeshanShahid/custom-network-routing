#include "unix_ipc.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int send_registration(int fd, uint8_t sdu_type) {
  ssize_t n = send(fd, &sdu_type, 1, 0);
  if (n == 1) {
    return 0;
  } else {
    return -1;
  }
}

/*
  Felles send og recive message, som man bruker over når sender med
  UNIX-socket.
*/

/*
Hva funksjonen gjør:
 - Sender en MIP-appmelding over en UNIX-socket.
 - Vi bygger et meldingsbuffer med 1 byte adresse + ttl + SDU-data.
Paramtere:
 - fd: tilkoblet UNIX socket mot mipd.
 - addr: MIP-destinasjonsadresse (1 byte) som legges i første byte på når vi
         skal sende dataen.
 - ttl: ttl som skal sendes med.
 - sdu: peker til SDU-data som skal sendes.
 - len: antall bytes i SDU.
Returverdi:
    - 0  hvis hele meldingen er sendt.
    - 1 ved feil, fordi input-vali­dering feiler, eller send() feiler.
*/

int send_msg(int fd, uint8_t addr, uint8_t ttl, const void *sdu, size_t len) {
  // 1) Valider input i med hensyn til MIP-spesifikasjonen.
  if (len > MIP_MAX_SDU || (len % 4) != 0) {
    return -1;
  }

  if (sdu == NULL) {
    return -1;
  }

  /*Pakkermeldingen i ett sammenhengende buffer: Første byte = adresse,
    andre byte = TTL, derretter SDU-data. */
  uint8_t msg[UPPER_MAX_MSG];
  msg[0] = addr;
  msg[1] = ttl; // hvis det er 0 brukes default TTL i mipd (ned) / ignorer (opp)
  memcpy(msg + 2, sdu, len);

  // Sender hele blokken i ETT kall. Med SOCK_SEQPACKET leveres dette som en
  // automatisk melding.
  size_t total = 2 + len;
  ssize_t n = send(fd, msg, total, 0);
  if (n < 0) {
    return -1;
  }
  if ((size_t)n != total) {
    return -1;
  }

  return 0;
}

/*
Hva funksjonen gjør:
   - Mottar en MIP-appmelding fra en UNIX-socket.
   - Leser en hel melding fra socketen inn i et midlertidig buffer.
   - Tolker første og andre byte som avsenderens MIP-adresse og TTL + resten som
    SDU.
Parametere:
   - fd: tilkoblet UNIX socket mot mipd.
   - src_out: peker som mottar avsenderens MIP-adresse (1 byte).
   - ttl_out: peker som mottar acsenderes TTL.
   - sdu_out: et buffer der SDU-data kopieres inn.
   - cap: kapasiteteten i sdu_out i bytes.
Returverdi
   - Retunrerer antall SDU-bytes kopiert til sdu_out.
   - Retunerer 0, hvis motparten lukker forbindelsen, og -1 hvis der noe feil
     med validering osv.
*/

ssize_t recv_msg(int fd, uint8_t *src_out, uint8_t *ttl_out, void *sdu_out,
                 size_t cap) {
  // Validerer pekere/kapasitet.
  if (src_out == NULL || (cap > 0 && sdu_out == NULL)) {
    return -1;
  }
  // Leser hele meldingen inn i et midlertidig buffer.
  uint8_t msg[UPPER_MAX_MSG];
  ssize_t n = recv(fd, msg, sizeof msg, 0);
  if (n <= 0) {
    // n == 0 betyr ay peer lukket.
    // n < 0 betyr feil.
    if (n < 0) {
      printf("Feil ved mottak\n");
      return -1;
    }
    return n;
  }
  // Minst en byte må være til stede (adressefeltet).
  if (n < 2) {
    return -1;
  }
  // Pakker ut adresse-byten + TTL og beregner SDU-lengde.
  *src_out = msg[0];
  *ttl_out = msg[1];
  size_t sdu_len = (size_t)n - 2;

  if (sdu_len > cap) {
    return -1;
  }

  memcpy(sdu_out, msg + 2, sdu_len);

  // Returner hvor mange SDU-bytes vi faktisk la i sdu_out.
  return (ssize_t)sdu_len;
}
