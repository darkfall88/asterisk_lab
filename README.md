# ASTERISK TRUNK WITH TLS AND SRTP SUPPORT

Interaktivní veřejná dokumentace fyzické laboratoře Asterisk (Streamlit), listopad 2026.

**Autoři:** Oryna Borovyk (`bor0250`) a David Kunčík (`kun212`).

| Činnost | Autorství |
|---|---|
| Návrh laboratorního řešení | Oryna Borovyk |
| Konfigurace a testování | Oryna Borovyk, David Kunčík |
| Dokumentace a vizualizace | David Kunčík |

## Co je v tomto balíčku

- `asterisk_lab.py` – webová dokumentace, devět původních kapitol a nová kapitola **Archiv laboratorních souborů**.
- `assets/topologie.png` – kombinované schéma fyzické a logické topologie (dvě Wi-Fi VLAN, dva Asterisk servery, dva SIP telefony, obousměrný trunk).
- `assets/photos/` – skutečné fotografie zapojení a obrazovky MizuDroidu.
- `assets/wireshark/` – 9 skutečných screenshotů z Wiresharku.
- `data/*.csv` – výsledky 3 testovacích scénářů (60s datový tok, průměrné CPU/RAM, velikosti paketů).
- `collect_public_evidence.py` – pomocný program pro import skutečných souborů Asterisk 1 a 2 z lokálních zdrojů na ThinkPadu.
- `originals/` – složka pouze pro upravované konfigurace, jejich pracovní zálohy, logy, PCAP a veřejné certifikáty.

**Důležitá informace k úplnosti:** V dodaném ZIP jsou skutečné screenshoty, fotografie a souhrnná měření. Původní `asterisk1-complete.tar.gz`, PCAP a logy z obou serverů nebyly v konverzaci nahrány a tento ZIP je proto nemůže obsahovat, dokud se neprovede níže uvedený import na ThinkPadu. Aplikace rozdíl transparentně zobrazí. Jakmile jsou naimportované, jejich výpisy a stažení fungují přímo v aplikaci.

## Spuštění aplikace

Na Linux Mint / Ubuntu:

```bash
cd asterisk_tls_srtp_verejna_verze
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run asterisk_lab.py
```

Typická lokální adresa je `http://localhost:8501`.

## Doplnění skutečných originálních souborů z ThinkPadu

Nejdříve přenes tuto rozbalenou složku na ThinkPad L380. Na ThinkPadu už je uložená archivní kopie Asterisku 1:

`/home/gh44sh/asterisk-project/asterisk1/asterisk1-complete.tar.gz`

Asterisk 2 má svoji vlastní konfiguraci a PCAP v lokálním souborovém systému. Ve složce aplikace spusť:

```bash
sudo python3 collect_public_evidence.py \
  --asterisk1-archive /home/gh44sh/asterisk-project/asterisk1/asterisk1-complete.tar.gz \
  --include-asterisk2
```

Pokud existuje také samostatná záloha Asterisku 2, lze namísto čtení běžícího systému použít parametr `--asterisk2-archive /cesta/k/archivu.tar.gz` (veřejný export pak odpovídá stavu z vybrané zálohy).

Při běhu programu se načte relevantní obsah:

| Zdroj | Co se exportuje |
|---|---|
| Asterisk 1 – archiv | Jen upravované `pjsip.conf`, `extensions.conf`, jejich projektové zálohy, `/etc/hosts`, měření `plain/encrypted/gsm`, veřejné certifikáty/CSR/EXT a logy Asterisk |
| Asterisk 2 – místní systém nebo archiv | Stejný omezený výběr konfigurací a logů, měření `plain/encrypted/gsm` z adresáře uživatele `gh44sh` a veřejné certifikáty/CSR/EXT |

### Rozsah konfiguračních souborů

Pro zveřejnění se vybírají pouze konfigurace, které jsme upravovali při stavbě
laboratoře: `/etc/asterisk/pjsip.conf` a `/etc/asterisk/extensions.conf`.
Zahrnuty mohou být také jejich výslovně pojmenované pracovní zálohy
(`backup-plain`, `before-tls`, `before-srtp`, `tls-srtp-alaw`), protože ukazují
jednotlivé fáze experimentu. Pro překlad názvů ústředen je zahrnut i upravený
`/etc/hosts`. Z výchozí instalace Asterisku se jiné soubory (`modules.conf`,
`logger.conf`, `features.conf`, `indications.conf`, výchozí *.conf apod.)
nepřenášejí, stejně jako obsah `/var/lib/asterisk` a `/var/spool/asterisk`.

Pokud jste ručně měnili také `/etc/asterisk/rtp.conf`, přidejte k importnímu
příkazu přepínač `--include-rtp-conf`. Bez něj se soubor nezveřejní, protože
z dostupných podkladů nelze potvrdit, že byl změněn.

Soubory `*.crt`, `*.csr`, příslušné soubory `*.ext`, PCAP, textová měření a
relevantní logy se stále publikují podle dřívějšího zadání; jejich výběr
neznamená zveřejnění výchozích Asterisk konfigurací.

Příkazy nikdy nemění běžící konfiguraci ani původní zálohy. Vytvoří:

- `originals/asterisk1/...` a `originals/asterisk2/...` – importované soubory, zachovaná cesta v rámci každého serveru;
- `originals/manifest.json` – seznam souborů, SHA-256, informace o případném maskování a vynechaných položkách;
- `originals_public.zip` – samostatný archiv veřejně publikovatelných zdrojových souborů.

Vzhledem k použití `sudo` doporučujeme po exportu vrátit vlastnictví výstupů uživateli (ve složce aplikace):

```bash
sudo chown -R gh44sh:gh44sh originals originals_public.zip
```

Pro sestavení jednoho finálního zveřejnitelného ZIPu se všemi importovanými podklady (po importu a kontrole) spusťte:

```bash
python3 build_release_zip.py --require-originals
```

Vznikne soubor `../asterisk_tls_srtp_verejna_verze_FINAL.zip`. Parametr `--require-originals` zabrání sestavení označenému jako finální, pokud chybějí data některé ústředny. Sestavovací skript také odmítne zjevné soubory soukromých klíčů a nebezpečně přiložené původní záložní archivy.

Po zkopírování aktualizované složky do veřejného repozitáře / na server budou soubory dostupné přes kapitolu **Archiv laboratorních souborů** (prohlížení konfigurací, logů, veřejných certifikátů, kontrolní součty, jednotlivá stažení a ZIP). PCAP se stahují v plné binární podobě a otevírají ve Wiresharku.

### Jak soubory před zveřejněním zabezpečuje import

- Nekopíruje soukromé klíče (`*.key`, privátní PEM bloky, klíče CA), heslové soubory ani obsah označený jako privátní.
- Ve veřejně exportovaných textových konfiguracích a logách maskuje hesla, `secret`, autentizační hlavičky a obdobné hodnoty. Tyto soubory se označují v manifestu jako `redacted` a nemohou být považovány za bitově totožné s originálem.
- Veřejné certifikáty (`*.crt`) a žádosti o jejich vydání (`*.csr`) ponechává beze změny. Obsahují veřejné klíče a identifikační informace, nikoli privátní klíčový materiál.
- PCAP ponechává nezměněné, aby šlo kontrolovat data v původním záznamu. Pozor: i PCAP mohou obsahovat IP adresy, SIP identity a Digest autentizační údaje.
- Záměrně přeskočí výchozí konfigurace, vnořené nezkontrolovatelné archivy, osobní hlasové soubory a některé jiné soubory. Přesný seznam vynechaných položek je v `manifest.json`.

Před veřejným vydáním proto ještě ručně prohlédněte `originals/` a výsledný `manifest.json`. Pokud byla jakákoli laboratorní hesla opakovaně použita mimo laboratoř, změňte je. Privátní CA klíč není nutný k doložení TLS experimentu a jeho publikace by narušila důvěryhodnost celé této certifikační autority.

## Tři laboratorní scénáře

| Scénář | Signalizace | Hlasový trunk | Kodek | IPv4 mediální paket |
|---|---|---|---|---:|
| A | SIP/UDP 5060 | RTP | G.711 A-law | 200 B |
| B | SIP/TLS 5061 | SRTP | G.711 A-law | 210 B |
| C | SIP/TLS 5061 | SRTP | GSM | 83 B |

Výsledky se vztahují ke konkrétním pokusům se záměrně zhoršenou Wi-Fi. Interpretace nezaměňuje rozdílný počet RTP paketů za režii šifrování.

## Ověření sestavení

```bash
python3 -m py_compile asterisk_lab.py collect_public_evidence.py build_release_zip.py
```

Závislosti Streamlit, pandas a Plotly se instalují přes `requirements.txt`. Pro plné prohlížení binárních PCAP lze použít libovolný aktuální Wireshark na pracovním počítači.
