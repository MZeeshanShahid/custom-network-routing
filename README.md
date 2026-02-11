I denne oppgaven har jeg implementert ruting og videresending i et egendefinert nettverkslag. nettverkslagsprosessen (MIP-daemonen)  er utvidet med en forwarding-mekanisme som håndterer TTL, utfører ruteoppslag og videresender pakker 
til neste hopp basert på informasjon fra en rutingtabell. Dette fører til at noder (datamaskiner) kan kommunisere med hverandre over flere hopp i nettverket.

Det er utviklet en egen rutingdaemon som kjører en dynamisk Distance Vector Routing-protokoll med Poisoned Reverse for å hindre uendlige rutingsløkker mellom vertene. 
Rutingdaemonen oppdager naboer, utveksler rutinginformasjon og har en rutingtabell som oppdateres kontinuerlig. I tillegg håndterer den interne ruteoppslag mellom prosesser. 
Resultatet er en fungerende nettverkslagsimplementasjon med dynamisk ruting, som sikrer at alle verter i systemet kan kommunisere med hverandre.

Se design-dokumentet for mer informasjon.
