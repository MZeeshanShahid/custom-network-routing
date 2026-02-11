
#ifndef MIP_H
#define MIP_H

#include <stddef.h>
#include <stdint.h>

/* Egen ethertype for MIP-rammer, slik at RAW-socket kan filterere
   MIP-trafikk.*/
#define ETH_TYPE_P 0x88B5

/*
   Dette er en spesiell MIP-addresse, som brukes når jeg skal gjøre en MIP-ARP
   request. Dette fører til at jeg får vite MAC-adressen til MIP-adressen jeg
   skal sende til. Når jeg gjør broadcast, sender jeg til alle naboer på samme
   lenke, hvor den riktige naboen svarer og gir en response.
*/
#define MIP_BROADCAST 0xFF

/*
  Det er to SDU-typer vi skal ta hensyn til:
    - MIP_TYPE_ARP: MIP-ARP SDU (request/response skilles i første byte i
      SDU). Se metoden build_miparp_payload(uint8_t type, uint8_t addr,
      uint8_t out[4]).
    - MIP_TYPE_PING: PING/PONG (tekst vi skriver selv og sender over)
*/
#define MIP_TYPE_ARP 0x01
#define MIP_TYPE_PING 0x02
#define MIP_TYPE_ROUTING 0x04

/*
    Feltgrenser for MIP-header-delen. Maksimal plass vi kan bruke.
      - MIP_TTL_MAX: Kan maks bruke 4 bits.
      - MIP_SDU_WORDS_MAX: Maks antall 32-bit ord som SDU-Len feltet kan
   repesentere er 9 bits.
        - Kan altså ha representere opptil 511 ord, noe som betyr at maksimalt
   antall bytes den kan inneholde er 2044 bytes.
            - 511 * 4 = 2044 bytes.
      - MIP_TYPE_MAX: Når vi skriver inn hvilken type MIP-SDU er, kan den
   maksimalt være 3 bit stor.
        - Vi sender inn bare 0x01 eller 0x02 i praksis for sdy_type i header.
*/
#define MIP_TTL_MAX 0x0F         /*4 bits*/
#define MIP_SDU_WORDS_MAX 0x01FF /* 9 bits*/
#define MIP_TYPE_MAX 0x07        /* 3 bits */

// MAXFDS: Bare en tilfeldig grense jeg har valgt.
#define MAXFDS 512
#define MIP_DEFAULT_TTL 8

/*
  - Samler inn info om nettverksgrensesnitt (ifindex + MAC).
  - Har en static ifinfo_t my_ifs[8] på toppen av mipd.c, som gir hver MIP
  daemon en liste med interface-ID og MAC-addressen til interfacet.
*/
typedef struct {
  int ifindex;    // interface-ID som kjernen gir (f.eks. h2-eth1 kan ha ifindex
                  // 5). Unik lokalt for alle.
  uint8_t mac[6]; // MAC-adressen (48-bit) til interfacet.

} ifinfo_t;

/*
  - Elementene i ARP-cache som hver mipd har.
    - mip: MIP-adressen (0–255) til naboen.
    - mac[6]: Ethernet MAC-adressen (48 bit) til samme nabo
    - Linux interface index, altså hvilken port som gjelder for interfacet.
    - 0/1: om denne tabellplassen er i bruk, slik at det er mulig å oppdatere
  den.
*/
typedef struct {
  uint8_t mip;
  uint8_t mac[6];
  int ifindex;
  int in_use;
} arp_entry_t;

/*
 - Dette er formatet på hvordan MIP-headeren skal se ut.
 - Med feltgrensene jeg har laget over kan jeg pakke og pakke ut headeren
 riktig.
    - dst: Desitnasjon for MIP-adressen. 1 byte.
    - src: MIP-adresse fra senderen. 1 byte.
    - ttl: (Time To Live). Hvor mange ganger en vert kan videresende (hoppe)
 datapakken.
    - sdu_len_bytes: SDU-lengden i bytes. Må være delelig med 4.
    - sdu_type: Hvilken type SDU-en er. Enten ARP eller PING.

*/
typedef struct {
  uint8_t dst;
  uint8_t src;
  uint8_t ttl : 4;
  uint16_t sdu_len_bytes : 9;
  uint8_t sdu_type : 3;
} __attribute__((packed)) mip_header;
#endif