# Automated Web Scanner

**Systeemvereisten**
- Linux-distributie (getest op Ubuntu en Kali Linux)
- Python 3.x
- Bash shell
- Sudo-rechten (alleen nodig voor automatische installatie van dependencies)

________________________________________________________________________________________________________

**WAT is dit voor script**
Dit is een Automatische Web/Netwerkscanner, die 4 verschillende netwerkscan tools combineert tot een gehele reconnaissance fase.

**Gebruikte tools**
- Nmap: Netwerkscanning en service-detectie
- Nikto: Webserver vulnerability scanning
- Gobuster: Directory en endpoint brute forcing
- Nuclei: Template-based vulnerability scanning

**Waarom is dit script in het leven geroepen?**
Dit script is het leven geroepen omdat handmatig scannen teveel verschillende files aanbiedt, daardoor kan de verwarring tussen files kan oplopen.
Daarom moest er een combinatie gemaakt worden van alle verschillende scanners die regelmatig gebruikt worden en deze bevindingen worden allemaal in een bestand waardoor alles inzichtelijk blijft.

**Wat is de relevantie voor in real life projecten**
Deze heeft relevantie tot Purple teaming (Advies rapporten schrijven) en Red teaming (Attack Surface bepaling).

**Voor wie is dit script bedoeld?**
Dit script is bedoeld voor studenten en professionals die bezig zijn met web- en netwerkanalyse binnen security-onderzoeken, zoals bij Purple Teaming en Red Teaming. Het script is niet bedoeld voor illegaal gebruik en mag uitsluitend worden ingezet op systemen waarvoor expliciet toestemming is verkregen.

________________________________________________________________________________________________________

**Hoe werkt dit script?**
Dit script run je door middel van het bijgeleverde bash script uitvoerbaar te maken en vervolgens te runnen.

1. Maak het bash script uitvoerbaar:
   chmod +x BashScriptRunner.sh
2. Start de scanner:
   sudo ./BashScriptRunner.sh
3. Volg de instructies in de terminal.


__sudo ./BashScriptRunner__
Als je dit commando gebruikt controleert het script eerst of Python3 geinstalleerd is binnen de werkomgeving.
Vervolgens runt hij de dependency checker om te controleren of de tools aanwezig zijn.
Als dit allemaal klopt opent hij de daadwerkelijke scanner om je webtargets te scannen.

**Wat wordt er gescand?**
De scanner voert een reconnaissance-fase uit op targets binnen een Subnet. 
Hierbij wordt onder andere gekeken naar:
- Openstaande poorten en services
- Webserverconfiguraties
- Mogelijke bekende kwetsbaarheden
- Verborgen directories en endpoints

**Resultaat**
Na afloop genereert het script één overzichtelijk outputbestand waarin de resultaten van alle scanners zijn samengevoegd. Dit bestand kan worden gebruikt als basis voor verdere analyse of rapportage.
