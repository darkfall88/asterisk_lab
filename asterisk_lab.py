"""Interaktivní laboratorní dokumentace: ASTERISK TRUNK WITH TLS AND SRTP SUPPORT.

Praktická laboratorní dokumentace vytvořená ve Streamlitu, 22. listopadu 2026.
Spuštění: streamlit run asterisk_lab.py
"""
from pathlib import Path
import pandas as pd
import json
import mimetypes
import hashlib
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parent
D = ROOT / "data"
ASSETS = ROOT / "assets"
ORIGINALS = ROOT / "originals"
PERFORMANCE = pd.read_csv(D / "performance.csv")
FLOWS = pd.read_csv(D / "flows.csv")
PACKETS = pd.read_csv(D / "packets.csv")
SCENARIO_ORDER = ["plain", "encrypted", "gsm"]
SCENARIOS = {
    "plain": "SIP/UDP + RTP / G.711",
    "encrypted": "SIP/TLS + SRTP / G.711",
    "gsm": "SIP/TLS + SRTP / GSM",
}
PALETTE = {
    "plain": "#6b7e93",
    "encrypted": "#186f9a",
    "gsm": "#228268",
}

st.set_page_config(
    page_title="Asterisk TLS + SRTP – reálná laboratoř",
    page_icon="🔐",
    layout="wide",
)
st.title("ASTERISK TRUNK WITH TLS AND SRTP SUPPORT")
st.caption("Praktická realizace dvou ústředen Asterisk, zabezpečený SIP trunk, analýza RTP/SRTP a měření výkonu")
st.caption("Autoři: Oryna Borovyk (bor0250) · David Kunčík (kun212)")

PANELS = [
    "Přehled a současný stav",
    "Topologie a laboratorní podmínky",
    "Konfigurace Asterisku a zabezpečení",
    "Scénáře a metodika",
    "Síťová analýza a datový tok",
    "Výkon CPU a RAM",
    "Bezpečnostní ověření",
    "Fotodokumentace a Wireshark",
    "Archiv laboratorních souborů",
    "Závěr, přínos a zdroje",
]
panel = st.sidebar.radio("Obsah projektu", PANELS)

def table(df, **kwargs):
    st.dataframe(df, hide_index=True, use_container_width=True, **kwargs)


def proof_image(relative_path: str, caption: str, width=None):
    path = ASSETS / relative_path
    if path.is_file():
        st.image(str(path), caption=caption, use_container_width=width is None, width=width)
    else:
        st.info(f"Obrázek zatím není doplněn: assets/{relative_path}")


def photo_grid(items):
    cols = st.columns(2)
    for i, (filename, caption) in enumerate(items):
        with cols[i % 2]:
            proof_image(f"photos/{filename}", caption)


def scenario_table():
    table(pd.DataFrame([
        {"Scénář": "A – referenční", "SIP signalizace": "UDP 5060", "Média": "RTP", "Kodek trunku": "G.711 A-law", "Zabezpečení trunku": "Ne"},
        {"Scénář": "B – zabezpečený", "SIP signalizace": "TLS/TCP 5061", "Média": "SDES-SRTP", "Kodek trunku": "G.711 A-law", "Zabezpečení trunku": "Ano"},
        {"Scénář": "C – doplňkový", "SIP signalizace": "TLS/TCP 5061", "Média": "SDES-SRTP", "Kodek trunku": "GSM Full Rate", "Zabezpečení trunku": "Ano"},
    ]))


def source_files():
    """Pouze skutečné naimportované soubory, bez symlinků a pomocných manifestů."""
    if not ORIGINALS.is_dir():
        return []
    return sorted(p for p in ORIGINALS.rglob("*")
                  if p.is_file() and not p.is_symlink()
                  and p.name not in {"manifest.json", "README.md"})


def source_tag(path):
    rel = path.relative_to(ORIGINALS)
    chunks = rel.parts
    if "asterisk1" in chunks:
        server = "Asterisk 1"
    elif "asterisk2" in chunks:
        server = "Asterisk 2"
    else:
        server = "Ostatní"
    ext = path.suffix.lower()
    if ext in {".pcap", ".pcapng", ".cap"}:
        group = "PCAP / paketové záznamy"
    elif ext in {".crt", ".cer", ".csr"}:
        group = "Veřejné certifikáty a žádosti"
    elif "asterisk-measurements" in chunks and ext in {".txt", ".csv", ".log"}:
        group = "CPU/RAM a výstupy měření"
    elif "log" in chunks or ext in {".log", ".gz", ".xz"}:
        group = "Provozní logy"
    elif "asterisk" in chunks or ext in {".conf", ".ini", ".cfg"}:
        group = "Konfigurace"
    else:
        group = "Další zdrojové soubory"
    return server, group


def readable_size(n):
    for unit in ["B", "KiB", "MiB", "GiB"]:
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def preview_original(path):
    # Textový náhled je omezený: binární PCAP se poskytuje ke stažení.
    ext = path.suffix.lower()
    if ext in {".pcap", ".pcapng", ".cap"}:
        st.info("Binární PCAP otevřete v aplikaci Wireshark. Zde je k dispozici původní záznam ke stažení.")
        return
    if ext in {".jpg", ".jpeg", ".png", ".webp"}:
        st.image(str(path), use_container_width=True)
        return
    if ext in {".gz", ".xz", ".zip", ".sqlite", ".db", ".so"}:
        st.info("Binární nebo komprimovaný soubor je k dispozici ke stažení.")
        return
    max_bytes = 110_000
    with path.open("rb") as f:
        data = f.read(max_bytes + 1)
    trunc = len(data) > max_bytes
    txt = data[:max_bytes].decode("utf-8", errors="replace")
    st.code(txt, language="text")
    if trunc:
        st.caption("Náhled je zkrácen na 110 kB. Stažený soubor obsahuje celý importovaný obsah.")


def related_originals(title, predicate, limit=8):
    matches = [p for p in source_files() if predicate(p)]
    if not matches:
        return
    with st.expander(title, expanded=False):
        for p in matches[:limit]:
            rel = p.relative_to(ORIGINALS).as_posix()
            col1, col2 = st.columns([5, 2])
            with col1:
                st.caption(f"`{rel}`  ·  {readable_size(p.stat().st_size)}")
            with col2:
                with p.open("rb") as f:
                    st.download_button("Stáhnout", f, file_name=p.name,
                                       mime="application/octet-stream",
                                       key="related-" + hashlib.sha256((panel + rel).encode()).hexdigest()[:16])
        if len(matches) > limit:
            st.caption(f"Dalších {len(matches)-limit} souborů najdete v archivu laboratorních souborů.")


if panel == "Přehled a současný stav":
    st.header("Úvod a cíl projektu")
    st.markdown("""
    Cílem projektu bylo sestavit dvě skutečné ústředny Asterisk ve vzájemně
    oddělených VLAN, zprovoznit mezi nimi obousměrný SIP trunk a experimentálně
    porovnat nezabezpečenou variantu SIP/UDP + RTP s variantou
    SIP/TLS + SDES-SRTP. Použili jsme dvě fyzická zařízení s Linux Mint,
    dva telefony Android s klientem MizuDroid a směrovač MikroTik hAP ac².

    Uskutečnili jsme skutečné hlasové hovory mezi čísly
    `1001` a `2001`, provedli paketové záznamy na obou Asterisk serverech,
    zkontrolovali certifikáty a TLS autentizaci a změřili CPU, RAM, velikost
    mediálních paketů a průměrný datový tok. Navíc jsme vyzkoušeli GSM Full Rate na šifrovaném trunku.
    """)
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Asterisk servery", "2")
    c2.metric("Testované režimy", "3")
    c3.metric("SRTP režie / paket", "+10 B")
    c4.metric("GSM + SRTP při 50 pps", "33,2 kb/s")
    st.subheader("Co jsme chtěli ověřit")
    st.markdown("""
    - Zda funguje směrování hovorů mezi dvěma Asterisk servery přes oddělené VLAN.
    - Zda SIP/TLS 1.2 s certifikáty vlastní CA a SDES-SRTP zajistí funkční zabezpečený trunk.
    - Jak se změní velikost mediálních paketů, měřený datový tok a využití CPU/RAM.
    - Zda GSM kodek sníží datový tok a jakou zátěž přidá překódování `alaw ↔ gsm`.
    - Jak se projeví záměrně zhoršené podmínky Wi-Fi na subjektivní kvalitě hovoru.
    """)
    st.subheader("Přehled testovaných variant")
    scenario_table()
    st.subheader("Současný stav a použité technologie")
    st.markdown("""
    SIP zajišťuje signalizaci hovoru (registrace, sestavení a ukončení),
    RTP přenáší časově citlivá hlasová data. TLS chrání SIP signalizaci
    na trunku včetně SDP, v němž jsou při SDES přenášeny informace potřebné ke
    sjednání SRTP. SRTP následně chrání hlasové pakety; v našem zapojení
    zůstává jejich transportem UDP. TLS tedy samo o sobě nezajišťuje
    doručování hlasových paketů ani neopravuje jitter Wi-Fi.

    G.711 A-law představuje 64kb/s PCM kodek s logaritmickým kvantováním v užším
    telefonním pásmu, kdežto GSM Full Rate používá kompresi s přibližně
    13,2 kb/s užitečných hlasových dat. V naší konfiguraci byly na trunku
    odesílány 20ms rámce, takže je třeba k hlasovému payloadu připočítat
    hlavičky IP/UDP/RTP a v šifrovaných variantách autentizační tag SRTP.
    """)
    with st.expander("Zásadní metodická omezení a interpretace"):
        st.markdown("""
        Nejde o izolovaný laboratorní benchmark kryptografie. Tři režimy
        byly měřeny v různých časových úsecích a při záměrně slabším Wi-Fi
        signálu. V režimech G.711 byl navíc v některých směrech skutečně
        zachycen menší počet mediálních paketů. Proto rozdíly celkového
        datového toku nelze celé připsat TLS/SRTP. Přímou režii lze lépe
        vyjádřit rozdílem velikosti *stejně strukturovaného paketu*.

        Pozorovaný lepší zvuk v šifrovaných scénářích neprokazuje, že TLS
        snížilo ztráty RTP. SDES-SRTP stále využívá UDP. Výsledky se vztahují
        ke konkrétní sestavě a jednotlivým pokusům.
        """)

elif panel == "Topologie a laboratorní podmínky":
    st.header("Topologie, fyzické zapojení a záměrně zhoršená Wi-Fi")
    st.markdown("""
    MikroTik hAP ac² (RouterOS 6.49.17) odděloval bezdrátové klienty do dvou
    VLAN a směroval provoz mezi podsítěmi. Každý Asterisk server měl vlastní
    IP adresu a vlastní Android SIP klient.
    """)
    proof_image("topologie.png", "Kombinovaná fyzická a logická topologie se dvěma VLAN, Wi-Fi klienty a zabezpečeným trunkem")
    st.subheader("Adresace a klienti")
    table(pd.DataFrame([
        {"Prvek": "MikroTik – VLAN 10", "IP": "10.0.10.1", "SSID": "asterisk1", "Role": "Brána podsítě 10.0.10.0/24"},
        {"Prvek": "MikroTik – VLAN 20", "IP": "10.0.20.1", "SSID": "asterisk2", "Role": "Brána podsítě 10.0.20.0/24"},
        {"Prvek": "Lenovo IdeaPad Gaming 3", "IP": "10.0.10.200", "SSID": "asterisk1", "Role": "Asterisk 1"},
        {"Prvek": "Xiaomi 15", "IP": "10.0.10.198", "SSID": "asterisk1", "Role": "MizuDroid 1001"},
        {"Prvek": "Lenovo ThinkPad L380", "IP": "10.0.20.101", "SSID": "asterisk2", "Role": "Asterisk 2"},
        {"Prvek": "Samsung Galaxy S24", "IP": "10.0.20.100", "SSID": "asterisk2", "Role": "MizuDroid 2001"},
    ]))
    st.subheader("Fyzické rozmístění")
    st.markdown("""
    MikroTik byl v jiné místnosti za dvěma stěnami a byl umístěn přímo na
    Wi-Fi routeru poskytovatele. Samsung Galaxy S24 byl během experimentu
    ve stejné místnosti jako MikroTik. Oba notebooky a Xiaomi 15 se nacházely
    společně v druhé místnosti.

    Slabší Wi-Fi byla záměrná. Chtěli jsme vytvořit náročnější prostředí,
    v němž lze lépe slyšet a analyzovat možné problémy se ztrátou paketů,
    zpožděním nebo jitterem.
    """)
    st.subheader("Použitá zařízení")
    table(pd.DataFrame([
        {"Zařízení": "IdeaPad Gaming 3 15ACH6", "Systém": "Linux Mint 22.2", "CPU": "AMD Ryzen 5 5600H / 6C 12T", "RAM": "5,6 GiB", "Rozhraní": "wlo1"},
        {"Zařízení": "ThinkPad L380", "Systém": "Linux Mint 22.2", "CPU": "Intel Core i5-8250U / 4C 8T", "RAM": "15 GiB", "Rozhraní": "wlp2s0"},
        {"Zařízení": "MikroTik hAP ac²", "Systém": "RouterOS 6.49.17", "CPU": "–", "RAM": "–", "Rozhraní": "Wi-Fi + VLAN"},
        {"Zařízení": "Xiaomi 15 / Galaxy S24", "Systém": "Android + MizuDroid", "CPU": "–", "RAM": "–", "Rozhraní": "Wi-Fi"},
    ]))
    st.caption("Oba Asterisk servery: balíček Asterisk 20.6.0, PJSIP a modul res_srtp.")
    st.subheader("Orientační stav Wi-Fi v průběhu práce")
    table(pd.DataFrame([
        {"Stanice": "IdeaPad", "RSSI": "−67 dBm", "SNR": "34 dB", "TX-CCQ": "57 %"},
        {"Stanice": "ThinkPad", "RSSI": "−68 dBm", "SNR": "33 dB", "TX-CCQ": "65 %"},
        {"Stanice": "Xiaomi 15", "RSSI": "−77 dBm", "SNR": "24 dB", "TX-CCQ": "58 %"},
        {"Stanice": "Samsung S24", "RSSI": "−65 dBm", "SNR": "36 dB", "TX-CCQ": "64 %"},
    ]))
    st.caption("Jedná se o orientační okamžitý výpis registrační tabulky MikroTiku")
    st.subheader("Fotografie reálné laboratoře")
    photo_grid([
        ("972.jpg", "MikroTik hAP ac² u Wi-Fi routeru poskytovatele; skutečné umístění."),
        ("971.jpg", "Obě ústředny Asterisk na oddělených fyzických noteboocích."),
    ])

elif panel == "Konfigurace Asterisku a zabezpečení":
    st.header("Topologie PJSIP, konfigurace trunků a certifikáty")
    st.markdown("""
    Oba servery používaly Asterisk 20.6.0 s `res_pjsip` a `res_srtp`.
    Lokální telefony byly registrovány vůči příslušnému serveru pomocí
    SIP/UDP 5060; jejich připojení nebylo v rámci hlavního experimentu
    přepínáno na TLS. K zabezpečení docházelo pouze mezi ústřednami.
    """)
    t1,t2,t3,t4 = st.tabs(["Původní RTP trunk", "TLS transport a certifikáty", "SRTP a dialplan", "GSM kodek"])
    with t1:
        st.markdown("Referenční režim – pouze trunkové části endpointů")
        st.code("""; IdeaPad – [trunk-a2] (výňatek)
transport=transport-udp
disallow=all
allow=alaw
direct_media=no
media_encryption=no
; AOR: contact=sip:10.0.20.101:5060

; ThinkPad – [trunk-a1] (výňatek)
transport=transport-udp
disallow=all
allow=alaw
direct_media=no
media_encryption=no
; AOR: contact=sip:10.0.10.200:5060""", language="ini")
        st.markdown("V tomto režimu byl mezi servery čitelný SIP na UDP 5060 a běžný RTP s G.711 A-law.")
        with st.expander("Wireshark: čitelný SIP INVITE a parametry SDP", expanded=False):
            proof_image("wireshark/plain_sip_invite_sdp.png", "SIP/UDP 5060 – INVITE a čitelné SDP, včetně PCMA/8000 a ptime:20.")
    with t2:
        st.markdown("""
        Na IdeaPadu byla vytvořena vlastní laboratorní CA
        (`CN=Asterisk Lab Root CA`) a podepsány certifikáty pro
        `asterisk1.lab` a `asterisk2.lab` (včetně DNS/IP SAN).
        Certifikáty byly následně nasazeny na oba servery.
        """)
        st.code("""; IdeaPad – /etc/asterisk/pjsip.conf (výňatek transportu)
[transport-tls]
type=transport
protocol=tls
bind=10.0.10.200:5061
method=tlsv1_2
cert_file=/etc/asterisk/keys/asterisk1.crt
priv_key_file=/etc/asterisk/keys/asterisk1.key
ca_list_file=/etc/asterisk/keys/ca.crt
verify_server=yes
verify_client=yes
require_client_cert=yes

; ThinkPad: analogicky 10.0.20.101:5061 a asterisk2.crt/.key""",language="ini")
        st.markdown("""
        Pro vzájemné rozlišení certifikátů byly v `/etc/hosts` použity názvy
        `asterisk1.lab` a `asterisk2.lab`. Pro změny TLS transportu byl
        proveden restart služby Asterisk; přítomnost portu 5061 byla
        potvrzena příkazem `pjsip show transports`.
        """)
        st.code("""sudo asterisk -rx "pjsip show transports"
# Na IdeaPadu: transport-tls 10.0.10.200:5061
# Na ThinkPadu: transport-tls 10.0.20.101:5061

sudo systemctl restart asterisk""",language="bash")
        st.caption("Původní konfigurační soubory a veřejné certifikáty lze prohlížet a stáhnout v sekci Archiv laboratorních souborů, jakmile jsou naimportovány. Hesla a soukromé klíče se do veřejného vydání nekopírují.")
    with t3:
        st.markdown("Zabezpečený trunk – reprezentativní výňatek naměřené konfigurace:")
        st.code("""; IdeaPad – endpoint [trunk-a2]
transport=transport-tls
aors=trunk-a2
context=from-a2
disallow=all
allow=alaw
direct_media=no
media_encryption=sdes
media_encryption_optimistic=no
; AOR: contact=sips:asterisk2.lab:5061
; Identify: match=10.0.20.101

; ThinkPad – endpoint [trunk-a1]
transport=transport-tls
aors=trunk-a1
context=from-a1
disallow=all
allow=alaw
direct_media=no
media_encryption=sdes
media_encryption_optimistic=no
; AOR: contact=sips:asterisk1.lab:5061
; Identify: match=10.0.10.200""",language="ini")
        st.markdown("""
        `media_encryption=sdes` vyžaduje sjednání SRTP přes SDP.
        Nastavení `media_encryption_optimistic=no` nepovoluje automatické
        pokračování bez šifrování, pokud zabezpečené médium nelze sjednat.
        `direct_media=no` udržuje mediální cestu přes příslušné Asterisk servery.
        """)
        st.subheader("Telefonní účty a číslovací plán")
        st.code("""Xiaomi 15 → Asterisk 1: účet 1001, SIP/UDP 5060, G.711 A-law
Samsung S24 → Asterisk 2: účet 2001, SIP/UDP 5060, G.711 A-law

; Základní logika odchozího směrování – výňatek
; IdeaPad: _2XXX → Dial(PJSIP/${EXTEN}@trunk-a2,30)
; ThinkPad: _1XXX → Dial(PJSIP/${EXTEN}@trunk-a1,30)
; Echo test na každém serveru: číslo 600 (Answer/Echo/Hangup)""",language="text")
        st.caption("Zde jsou vysvětlující výňatky. Původní konfigurační soubory (po odstranění hesel) jsou přístupné přes Archiv laboratorních souborů, pokud byly importovány.")
    with t4:
        st.markdown("""
        V dodatečném experimentu se změnil jen povolený kodek trunku.
        Lokální klienti nadále používali G.711 A-law, a proto oba servery
        prováděly překódování mezi `alaw` a `gsm`. Modul `codec_gsm.so` byl
        na obou systémech ve stavu `Running`.
        """)
        st.code("""; V endpointu trunk-a2 a trunk-a1:
disallow=all
allow=gsm

; Ostatní beze změny:
transport=transport-tls
media_encryption=sdes
media_encryption_optimistic=no""", language="ini")
        st.code("""NativeFormats: (gsm)
WriteTranscode: Yes (slin@8000)->(gsm@8000)
ReadTranscode: Yes (gsm@8000)->(slin@8000)""", language="text")
        st.caption("Výpis pochází z aktivního trunkového kanálu `PJSIP/trunk-a1-...` na ThinkPadu.")
    st.caption("Původní soubory Asterisk 1 a 2 se zpřístupňují v archivu zdrojů po importu ze zálohy na ThinkPadu. PCAP se přenášejí beze změny, u konfigurací se skrývají autentizační hesla.")

    related_originals("Upravované konfigurační soubory a jejich zálohy (ke stažení)",
        lambda p: "etc" in p.parts and "asterisk" in p.parts
        and (p.name.startswith("pjsip.conf") or p.name.startswith("extensions.conf")
             or p.name == "rtp.conf"), limit=12)
    related_originals("Veřejné laboratorní certifikáty (ke stažení)",
        lambda p: p.suffix.lower() in {".crt", ".csr"}, limit=12)

elif panel == "Scénáře a metodika":
    st.header("Metodika a průběh praktického měření")
    scenario_table()
    st.subheader("Provedení hlasových testů")
    st.markdown("""
    Na telefonech s MizuDroid jsme ověřili registraci a Echo test na čísle
    `600`. Poté jsme provedli obousměrné hovory `1001 ↔ 2001` přes trunk.
    Při měření mediálního toku byl použit přibližně 110sekundový hovor;
    pro srovnání přenosové rychlosti bylo ze záznamů vyhodnoceno 60 sekund
    od relativního času 30 s do 90 s. Zatížení Asterisk procesu jsme
    samostatně zaznamenávali 90 vzorky pidstat po 1 sekundě.

    Záznamy z obou serverů nebyly synchronizovány na přesnou společnou
    značku začátku hovoru a měření CPU nebylo dokonale sladěno s 60s
    analytickým oknem. Výsledky proto slouží k orientačnímu
    srovnání na stejné sestavě, nikoliv ke statisticky přesnému měření
    čistých kryptografických nákladů.
    """)
    st.subheader("Nástroje a postup zachytávání")
    st.code("""# IdeaPad: Asterisk 1, rozhraní wlo1
sudo tcpdump -i wlo1 -nn -s 0 -B 8192 -w asterisk1_encrypted.pcap \
 'host 10.0.20.101 and (tcp port 5061 or udp portrange 10000-20000)'

# ThinkPad: Asterisk 2, rozhraní wlp2s0
sudo tcpdump -i wlp2s0 -nn -s 0 -B 8192 -w asterisk2_encrypted.pcap \
 'host 10.0.10.200 and (tcp port 5061 or udp portrange 10000-20000)'

# CPU a RAM procesu Asterisk
PID=$(systemctl show -p MainPID --value asterisk)
LC_ALL=C pidstat -u -r -p "$PID" 1 90 > asterisk_cpu_ram.txt""", language="bash")
    st.caption("V nešifrovaném scénáři se místo TCP 5061 zachytávala SIP signalizace na UDP 5060. Názvy souborů se pro jednotlivé scénáře lišily.")
    st.subheader("Výpočet datového toku")
    st.markdown("""
    Pro zvolený interval o délce 60 s jsme u obou směrů sečetli
    `ip.len` všech mediálních IPv4 paketů. Přenosová rychlost
    v kb/s je tedy `součet(IP bajtů) × 8 / 60 / 1000`.
    Do této metriky není zahrnuta další režie Ethernetu/Wi-Fi ani
    TCP/TLS signalizační provoz.
    """)
    st.code("""tshark -r asterisk1_gsm.pcap \
 -Y 'frame.time_relative >= 30 && frame.time_relative < 90 && udp.port == 15310 && udp.port == 10176' \
 -T fields -e ip.src -e ip.len | \
 LC_ALL=C awk 'NF==2{count[$1]++;bytes[$1]+=$2} END{for(ip in count) printf "%s %d paketů, %.2f kb/s\\n",ip,count[ip],bytes[ip]*8/60000}'""", language="bash")
    st.subheader("Subjektivní posouzení hovoru")
    table(pd.DataFrame([
        {"Režim": "Nešifrovaný SIP/UDP + RTP / G.711", "Pozorování": "Přerušovaný hlas; subjektivní dojem vysokého jitteru"},
        {"Režim": "SIP/TLS + SRTP / G.711", "Pozorování": "Hovor bez slyšitelných problémů"},
        {"Režim": "SIP/TLS + SRTP / GSM", "Pozorování": "Hovor bez slyšitelných problémů; bez postřehnutelného rozdílu oproti G.711"},
    ]))
    
    related_originals("Původní záznamy a soubory měření", 
        lambda p: p.suffix.lower() in {".pcap", ".pcapng", ".txt"} and "asterisk-measurements" in p.parts, limit=14)

elif panel == "Síťová analýza a datový tok":
    st.header("Analýza RTP, SRTP a vlivu kodeku na síť")
    st.subheader("Velikost jednoho mediálního IPv4 paketu")
    a,b,c = st.columns(3)
    a.metric("RTP / G.711", "200 B")
    b.metric("SRTP / G.711", "210 B", "+10 B")
    c.metric("SRTP / GSM", "83 B", "−127 B vs. SRTP/G.711")
    parts = pd.DataFrame([
        {"Scénář": "RTP / G.711", "IP + UDP": 28, "RTP": 12, "Audio": 160, "SRTP tag": 0},
        {"Scénář": "SRTP / G.711", "IP + UDP": 28, "RTP": 12, "Audio": 160, "SRTP tag": 10},
        {"Scénář": "SRTP / GSM", "IP + UDP": 28, "RTP": 12, "Audio": 33, "SRTP tag": 10},
    ])
    fig = px.bar(parts, x="Scénář", y=["IP + UDP", "RTP", "Audio", "SRTP tag"],
                 barmode="stack", title="Složení mediálního IPv4 paketu", labels={"value": "Bajty na paket", "variable": "Část paketu"},
                 color_discrete_sequence=["#91a6b9", "#4c7eb5", "#35a88d", "#de9850"])
    fig.update_layout(legend_title_text="Složka", height=425)
    st.plotly_chart(fig, use_container_width=True)
    st.markdown("""
    Z ukázek `tcpdump` byly naměřeny UDP payloady 172, 182 a 55 bajtů;
    po připočtení 20B IPv4 a 8B UDP hlavičky jde o 200, 210 a 83 bajtů.
    Rozdíl 10 B mezi RTP a SRTP/G.711 odpovídá použitému 80bitovému
    autentizačnímu tagu SRTP (5 % velikosti původního IPv4 paketu).
    V GSM záznamu IdeaPadu mělo všech 11 151 analyzovaných média
    paketů velikost 83 B.
    """)
    st.subheader("Wireshark: porovnání skutečných paketů")
    tab_rtp, tab_srtp, tab_gsm = st.tabs(["RTP / G.711", "SRTP / G.711", "SRTP / GSM"])
    with tab_rtp:
        proof_image("wireshark/plain_rtp_packet.png", "RTP s G.711 – ethernetový rámec 214 B, IPv4 paket 200 B.")
    with tab_srtp:
        proof_image("wireshark/srtp_alaw_210b.png", "Média s konfigurací SDES-SRTP a G.711 – ethernetový rámec 224 B, IPv4 paket 210 B.")
    with tab_gsm:
        proof_image("wireshark/srtp_gsm_83b.png", "Média s konfigurací SDES-SRTP a GSM – ethernetový rámec 97 B, IPv4 paket 83 B.")

    st.subheader("Skutečně naměřený datový tok – pevné 60sekundové okno")
    chart_flows = FLOWS.copy()
    chart_flows["Režim"] = chart_flows["scenar"].map(SCENARIOS)
    fig = px.bar(chart_flows, x="Režim", y="bitrate_kbps", color="smer", barmode="group",
                 title="Naměřený mediální datový tok na IPv4 vrstvě", labels={"bitrate_kbps": "kb/s", "smer": "Směr", "Režim": ""},
                 category_orders={"Režim": [SCENARIOS[x] for x in SCENARIO_ORDER]},
                 color_discrete_sequence=["#177e96", "#b07b35"])
    fig.update_layout(height=465)
    st.plotly_chart(fig, use_container_width=True)
    flow_table = FLOWS.copy()
    flow_table["Scénář"] = flow_table["scenar"].map(SCENARIOS)
    table(flow_table[["Scénář", "smer", "pocet_paketu", "ip_bytes", "bitrate_kbps"]].rename(columns={
        "smer": "Směr", "pocet_paketu": "Počet paketů", "ip_bytes": "IP bajtů / 60 s", "bitrate_kbps": "kb/s"
    }).round({"kb/s": 2}))
    st.warning("Nárůst naměřeného datového toku ze scénáře A do B není přímo šifrovací režie: počty paketů v režimu G.711 se mezi dvěma pokusy lišily. V prvním referenčním RTP pokusu byl ve směru Asterisk 1 → 2 zachycen významný pokles frekvence paketů.")
    st.subheader("Srovnatelný model při 50 paketech za sekundu")
    model = PACKETS.copy()
    model["Režim"] = model["scenar"].map(SCENARIOS)
    fig = px.bar(model, x="Režim", y="model_kbps_50pps",
                 color="scenar", color_discrete_map=PALETTE,
                 title="Modelový mediální datový tok při 20ms paketech a 50 pps",
                 labels={"model_kbps_50pps": "kb/s", "Režim": ""},
                 category_orders={"Režim": [SCENARIOS[x] for x in SCENARIO_ORDER]})
    fig.update_layout(showlegend=False, height=400)
    st.plotly_chart(fig, use_container_width=True)
    table(pd.DataFrame([
        {"Scénář": "RTP/G.711", "IPv4 paket": "200 B", "Paketů/s": 50, "Teoretický tok": "80,0 kb/s"},
        {"Scénář": "SRTP/G.711", "IPv4 paket": "210 B", "Paketů/s": 50, "Teoretický tok": "84,0 kb/s"},
        {"Scénář": "SRTP/GSM", "IPv4 paket": "83 B", "Paketů/s": 50, "Teoretický tok": "33,2 kb/s"},
    ]))
    st.markdown("""
    Při stejné frekvenci paketů by SRTP/G.711 zvýšilo tok proti RTP/G.711
    o 4 kb/s na směr, zatímco GSM + SRTP by proti šifrovanému
    G.711 ušetřilo přibližně 60,5 % mediální kapacity na IP vrstvě.
    V GSM testu bylo v obou směrech reálně naměřeno 3 000 paketů za 60 s,
    tedy 33,2 kb/s na směr, což odpovídá modelu.
    """)
    with st.expander("Pozorované nepravidelnosti původního RTP"):
        st.markdown("""
        Wireshark ve starším RTP záznamu indikoval ve směru
        Asterisk 1 → 2 přibližně 43 % chybějících RTP sekvenčních čísel;
        v opačném směru přibližně 3,4 %. Mezi pakety se vyskytl
        mimořádně dlouhý interval asi 24,06 s doprovázený skokem
        sekvenčního čísla. Tento jev byl vidět už v záznamu na
        odesílajícím IdeaPadu. Nelze jej proto automaticky interpretovat
        jako síťovou ztrátu všech odpovídajících paketů mezi notebooky.
        Možné vlivy zahrnují chování odesílání, zpracování médií, stav
        Wi-Fi i zachytávací systém. Jde o konkrétní anomálii a limit
        srovnatelnosti, nikoliv o prokázaný 43% Wi-Fi packet loss.
        """)
    st.subheader("Wireshark: nepravidelnosti původního RTP toku")
    with st.expander("Statistiky RTP Stream Analysis – Asterisk 1 → 2", expanded=False):
        proof_image("wireshark/plain_rtp_analysis.png", "Wireshark: 2 959 RTP paketů, odhad 2 260 chybějících sekvencí (43,30 %), průměrný jitter 26,655 ms, max. mezera 24,06 s.")
        st.caption("Chybějící sekvence nejsou automaticky důkazem ztrát na Wi-Fi; anomálie byly patrné také na vysílajícím serveru.")
    with st.expander("Graf jitteru a časových mezer", expanded=False):
        proof_image("wireshark/plain_rtp_jitter_graph.png", "Jitter nešifrovaného RTP toku; výpadky souvislých bodů představují mezery v dostupných vzorcích.")
    st.subheader("Export zdrojových tabulek")
    st.download_button("Stáhnout síťová měření (CSV)", FLOWS.to_csv(index=False).encode("utf-8"), "flows.csv", "text/csv")

    related_originals("Původní paketové záznamy (PCAP)",
        lambda p: p.suffix.lower() in {".pcap", ".pcapng"}, limit=8)

elif panel == "Výkon CPU a RAM":
    st.header("Vliv TLS/SRTP a kodeku GSM na proces Asterisk")
    st.markdown("""
    Monitorovali jsme konkrétní proces `asterisk` pomocí `pidstat -u -r`.
    Jedná se o průměrné procento CPU uváděné pro proces (v měřítku
    použitých procesorových kapacit nástroje), nikoliv o vytížení
    celého počítače. Paměť vyjadřujeme jako RSS v MiB.
    """)
    perf = PERFORMANCE.copy()
    perf["Režim"] = perf["scenar"].map(SCENARIOS)
    fig = px.bar(perf, x="server", y="cpu_pct", color="Režim", barmode="group",
                 title="Průměrné CPU procesu Asterisk (90 s)",
                 labels={"server": "Server", "cpu_pct": "% CPU"},
                 category_orders={"Režim": [SCENARIOS[x] for x in SCENARIO_ORDER]},
                 color_discrete_map={SCENARIOS[k]:PALETTE[k] for k in SCENARIO_ORDER})
    fig.update_layout(height=455)
    st.plotly_chart(fig, use_container_width=True)
    fig = px.bar(perf, x="server", y="rss_mib", color="Režim", barmode="group",
                 title="Rezidentní paměť procesu Asterisk (RSS)",
                 labels={"server": "Server", "rss_mib": "MiB"},
                 category_orders={"Režim": [SCENARIOS[x] for x in SCENARIO_ORDER]},
                 color_discrete_map={SCENARIOS[k]:PALETTE[k] for k in SCENARIO_ORDER})
    fig.update_layout(height=455)
    st.plotly_chart(fig, use_container_width=True)
    table(perf[["Režim", "server", "cpu_pct", "rss_mib"]].rename(columns={
        "server":"Server", "cpu_pct":"CPU (%)", "rss_mib":"RSS (MiB)"
    }).round(2))
    st.subheader("Interpretace naměřených změn")
    st.markdown("""
    - IdeaPad: CPU 1,63 → 2,11 → 2,39 % při přechodu RTP/G.711 → SRTP/G.711 → SRTP/GSM.
    - ThinkPad: CPU 0,93 → 1,26 → 1,54 % ve stejném pořadí.
    - V GSM režimu se CPU oproti zabezpečenému G.711 zvýšilo o 0,28 procentního bodu na obou serverech. To je slučitelné se zaznamenaným překódováním GSM ↔ lineární audio.
    - RSS paměť se mezi režimy pohybovala přibližně od 85 do 90,5 MiB, ale jednotlivé rozdíly jsou malé a závislé také na běhu programu a dalších proměnných.
    """)
    st.download_button("Stáhnout výkonová měření (CSV)", PERFORMANCE.to_csv(index=False).encode("utf-8"), "performance.csv", "text/csv")

    related_originals("Úplné výstupy pidstat z obou ústředen", 
        lambda p: "asterisk-measurements" in p.parts and "cpu_ram" in p.name, limit=8)

elif panel == "Bezpečnostní ověření":
    st.header("Ověření certifikátů, TLS handshake a vynucení SRTP")
    st.markdown("""
    Systém používal lokální kořenovou CA, dva serverové certifikáty
    s názvy `asterisk1.lab` / `asterisk2.lab` a na TLS transportech
    parametry `verify_server=yes`, `verify_client=yes` a
    `require_client_cert=yes`.
    """)
    st.subheader("Pozitivní testy – obousměrné TLS")
    table(pd.DataFrame([
        {"Směr": "IdeaPad → ThinkPad", "TLS": "1.2", "Šifra": "ECDHE-RSA-AES256-GCM-SHA384", "Ověřené jméno": "asterisk2.lab", "Výsledek": "Verification: OK"},
        {"Směr": "ThinkPad → IdeaPad", "TLS": "1.2", "Šifra": "ECDHE-RSA-AES256-GCM-SHA384", "Ověřené jméno": "asterisk1.lab", "Výsledek": "Verification: OK"},
    ]))
    st.code("""CONNECTION ESTABLISHED
Protocol version: TLSv1.2
Ciphersuite: ECDHE-RSA-AES256-GCM-SHA384
Peer certificate: CN = asterisk2.lab
Verification: OK
Verified peername: asterisk2.lab""",language="text")
    st.markdown("""
    Příkaz `openssl s_client` byl proveden se správnou laboratorní CA
    a s klientským certifikátem ústředny, takže se ověřila důvěra k
    protější straně a úspěšné navázání TLS handshake v obou směrech.
    """)
    with st.expander("Wireshark: šifrovaná SIP signalizace TLS 1.2", expanded=False):
        proof_image("wireshark/tls_application_data.png", "TLSv1.2 Application Data na TCP portu 5061 – bez čitelných SIP hlaviček a SDP.")
        st.caption("Záznam zachycuje navázanou TLS relaci. Samostatné ověření handshake bylo provedeno nástrojem OpenSSL.")
    st.subheader("Negativní test – klient bez certifikátu")
    st.markdown("""
    Při připojení IdeaPad → ThinkPad bez volby `-cert` a `-key`
    vyžádal ThinkPad klientský certifikát a handshake odmítl:
    """)
    st.code("""SSL_connect:SSLv3/TLS read server certificate request
SSL3 alert read:fatal:handshake failure
... SSL alert number 40""",language="text")
    
    st.subheader("Kontrola trunku a přenosu médií")
    st.code("""pjsip show endpoints
# trunk-a2 ↔ sips:asterisk2.lab:5061 ... Avail
# trunk-a1 ↔ sips:asterisk1.lab:5061 ... Avail

pjsip show endpoint trunk-a1
# allow                         : (alaw) / (gsm podle scénáře)
# media_encryption              : sdes
# media_encryption_optimistic   : false
# direct_media                  : false
# transport                     : transport-tls""",language="text")
    st.markdown("""
    V PCAP se objevuje TCP provoz na portu 5061 a samostatné
    mediální UDP toky s velikostí paketů odpovídající SRTP. Hlasový
    přenos byl při skutečných voláních funkční. Bez TLS klíčů nelze
    v běžném zachycení otevřít obsah šifrované SIP signalizace a
    automaticky získat SDES klíčový materiál.
    """)
    st.warning("MizuDroid ↔ lokální Asterisk zůstával SIP/UDP a RTP, což je vědomé omezení rozsahu experimentu.")

    related_originals("Veřejné certifikáty a logy zabezpečení",
        lambda p: p.suffix.lower() in {".crt", ".csr", ".log"}, limit=12)

elif panel == "Fotodokumentace a Wireshark":
    st.header("Fotodokumentace a obrazové důkazy")
    st.subheader("Skutečná laboratoř")
    photo_grid([
        ("971.jpg", "Dvě samostatné ústředny Asterisk, IdeaPad (vlevo) a ThinkPad (vpravo)."),
        ("972.jpg", "MikroTik hAP ac² umístěný přímo u routeru poskytovatele."),
    ])
    st.subheader("MizuDroid – konfigurace a funkční registrace")
    photo_grid([
        ("980.jpg", "MizuDroid na Xiaomi: SIP server 10.0.10.200, uživatel 1001."),
        ("977.jpg", "MizuDroid na Samsungu: SIP server 10.0.20.101, uživatel 2001."),
        ("973.jpg", "Samsung: stav Registered, účet 2001 a uložené testovací číslo 1001 a Echo 600."),
        ("975.jpg", "Samsung: probíhající Echo hovor na čísle 600."),
    ])
    st.subheader("Wireshark – obrazové důkazy z laboratorních PCAP")
    st.markdown("""
    Všechny obrázky v této části jsou originální screenshoty Wiresharku pořízené
    z naměřených PCAP souborů. Na snímcích je zachována filtrace, adresace
    serverů a protokolový strom. Číselné hodnoty doplňují výsledky TShark,
    tcpdump a Asterisk CLI uvedené v analytických kapitolách.
    """)
    proofs = [
        ("plain_sip_invite_sdp.png", "Nešifrovaný SIP INVITE a čitelné SDP", "asterisk1_plain.pcap", "udp.port == 5060", "SIP INVITE, PCMA/8000, ptime:20 a směrování hovoru 1001 → 2001."),
        ("plain_sip_overview.png", "Přehled nešifrované SIP signalizace", "asterisk1_plain.pcap", "udp.port == 5060", "Průběh signalizace INVITE, 100 Trying, 180 Ringing, 200 OK, ACK a BYE."),
        ("plain_rtp_packet.png", "Nešifrovaný RTP paket s G.711", "asterisk1_plain.pcap", "RTP mezi Asterisk 1 a 2", "RTP hlavička, PT 8 (PCMA), sekvenční číslo a 214B ethernetový rámec (200 B IPv4)."),
        ("plain_rtp_analysis.png", "RTP Stream Analysis a sekvenční nepravidelnosti", "asterisk1_plain.pcap", "Telephony → RTP → RTP Streams → Analyze", "Zvýrazněné chyby sekvence; průměrný jitter 26,655 ms, max. rozdíl příchodů 24,06 s."),
        ("plain_rtp_interarrival_graph.png", "Graf časových odchylek původního RTP", "asterisk1_plain.pcap", "RTP Stream Analysis → Graph", "Výrazné vrcholy série Difference; tyto vrcholy nejsou přímo hodnotou jitteru."),
        ("plain_rtp_jitter_graph.png", "Samostatný graf jitteru původního RTP", "asterisk1_plain.pcap", "RTP Stream Analysis → Graph → Jitter", "Graf ukazuje jitter v ms a dlouhé intervaly bez souvisle zaznamenaných hodnot."),
        ("tls_application_data.png", "Šifrovaná SIP signalizace – TLS 1.2", "asterisk1_encrypted.pcap", "tcp.port == 5061", "TLS Application Data bez čitelných SIP hlaviček a SDP."),
        ("srtp_alaw_210b.png", "SRTP / G.711 – IPv4 paket 210 B", "asterisk1_encrypted.pcap", "udp && ip.len == 210", "224B ethernetový rámec, 182B UDP payload; oproti RTP/G.711 +10 B na IPv4 vrstvě."),
        ("srtp_gsm_83b.png", "SRTP / GSM – IPv4 paket 83 B", "asterisk1_gsm.pcap", "udp && ip.len == 83", "97B ethernetový rámec, 55B UDP payload; GSM kodek ověřen v Asterisk CLI."),
    ]
    for filename, title, source, filt, desc in proofs:
        with st.expander(title, expanded=False):
            st.caption(f"Soubor: {source}  ·  Filtr / postup: {filt}")
            st.write(desc)
            proof_image(f"wireshark/{filename}", title)

elif panel == "Archiv laboratorních souborů":
    st.header("Původní laboratorní soubory a protokoly")
    st.markdown("""
    Tato část zpřístupňuje skutečné soubory exportované ze zálohy Asterisk 1
    a z notebooku Asterisk 2. Z konfigurací zařazujeme pouze soubory upravované
    při realizaci projektu: `pjsip.conf`, `extensions.conf`, jejich pracovní zálohy
    a `/etc/hosts` s laboratorními názvy. `rtp.conf` lze případně přidat pouze
    tehdy, pokud byl skutečně upravován. Výchozí systémové soubory Asterisku
    nejsou součástí archivu. U exportovaných konfigurací se maskují hesla a
    další autentizační hodnoty. Veřejné certifikáty (CRT) a žádosti (CSR)
    zůstávají dostupné v původní podobě.
    Soukromé klíče se do veřejného balíčku nepřenášejí.

    PCAP obsahují zachycený provoz laboratoře a jsou ponechány beze změny.
    Obrazové důkazy jsou navíc dostupné v sekci Fotodokumentace a Wireshark.
    """)

    paths = source_files()
    if not paths:
        st.warning("Původní konfigurační soubory, logy a PCAP zatím nebyly připojeny. Dokumentace, grafy a screenshoty jsou k dispozici; původní datové soubory je třeba naimportovat ze zálohy na ThinkPadu.")
        st.code('python3 collect_public_evidence.py --asterisk1-archive \\\n  ~/asterisk-project/asterisk1/asterisk1-complete.tar.gz --include-asterisk2', language="bash")
        st.caption("Podrobný postup najdete v README.md. Import nezmění soubory v původní záloze ani běžící Asterisk.")
    else:
        st.metric("Zveřejněné zdrojové soubory", len(paths))
        servers = sorted({source_tag(p)[0] for p in paths})
        groups = sorted({source_tag(p)[1] for p in paths})
        c1, c2 = st.columns(2)
        selected_server = c1.selectbox("Ústředna", ["Všechny"] + servers)
        selected_group = c2.selectbox("Kategorie", ["Všechny"] + groups)
        filtered = [p for p in paths if
                    (selected_server == "Všechny" or source_tag(p)[0] == selected_server)
                    and (selected_group == "Všechny" or source_tag(p)[1] == selected_group)]
        rows = []
        for p in filtered:
            a, g = source_tag(p)
            rows.append({"Ústředna": a, "Kategorie": g,
                         "Soubor": p.relative_to(ORIGINALS).as_posix(),
                         "Velikost": readable_size(p.stat().st_size)})
        if rows:
            table(pd.DataFrame(rows))
            labels = [p.relative_to(ORIGINALS).as_posix() for p in filtered]
            chosen = st.selectbox("Zobrazit nebo stáhnout soubor", labels)
            src = ORIGINALS / chosen
            st.caption(f"Velikost: {readable_size(src.stat().st_size)} · SHA-256: `{hashlib.sha256(src.read_bytes()).hexdigest()}`")
            manifest_file = ORIGINALS / "manifest.json"
            if manifest_file.is_file():
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                match = next((e for e in manifest.get("files", []) if e.get("exported_path") == chosen), None)
                if match and match.get("redacted"):
                    st.info("Soubor byl při veřejném exportu upraven: autentizační údaje byly skryty. Původní nepozměněná kopie zůstala ve zdrojové záloze.")
            with src.open("rb") as fh:
                st.download_button("Stáhnout vybraný soubor", fh, file_name=src.name,
                    mime=mimetypes.guess_type(src.name)[0] or "application/octet-stream",
                    key="download-original-" + hashlib.sha256(chosen.encode()).hexdigest()[:16])
            st.subheader("Náhled")
            preview_original(src)
        else:
            st.info("Pro zvolený filtr nejsou dostupné žádné soubory.")
        archive = ROOT / "originals_public.zip"
        if archive.is_file():
            with archive.open("rb") as fh:
                st.download_button("Stáhnout celý archiv originálních podkladů (ZIP)",
                                   fh, file_name="originals_public.zip", mime="application/zip")
        st.caption("Archiv slouží k vědecké reprodukovatelnosti. PCAP mohou obsahovat IP adresy, SIP identity a autentizační otisky; před zveřejněním si projděte jejich obsah.")

else:
    st.header("Závěrečné vyhodnocení projektu")
    st.success("Hlavní cíl projektu byl splněn: dvě Asterisk ústředny fungovaly přes nešifrovaný i zabezpečený trunk; součástí byly hovory, paketová analýza, ověření TLS a měření výkonu.")
    st.subheader("Hlavní experimentální zjištění")
    st.markdown("""
    **Funkční implementace:** Byly vytvořeny dvě VLAN s oddělenými
    SIP klienty. Hovory `1001 ↔ 2001` fungovaly nejprve přes
    SIP/UDP + RTP a následně přes SIP/TLS + SDES-SRTP.

    **TLS a identita serverů:** V obou směrech prošlo TLS 1.2 spojení
    se správným ověřením názvů serverů a podpisu laboratorní CA.
    ThinkPad navíc v negativním testu odmítl klienta bez certifikátu.

    **Velikost mediálních paketů:** Z naměřených hodnot bylo
    potvrzeno **200 B (RTP/G.711)**, **210 B (SRTP/G.711)** a
    **83 B (SRTP/GSM)** na IPv4 vrstvě. SRTP/G.711 přidává
    **10 B / 5 %** na mediální paket oproti RTP/G.711.

    **Úspora GSM:** Změna G.711 na GSM při zachování TLS/SRTP
    snížila modelový datový tok z **84,0 na 33,2 kb/s na směr**
    při 50 paketech/s. GSM měření přesně odpovídalo **3 000 paketům
    a 33,2 kb/s za 60 s v každém směru**.

    **Výpočetní režie:** CPU procesu Asterisk bylo v jednotlivých
    testech vyšší v šifrovaném režimu než v nešifrovaném a dále
    vzrostlo při GSM překódování. Paměť RSS se pohybovala přibližně
    v rozsahu 85–90,5 MiB.
    """)
    st.subheader("Subjektivní hodnocení a limity")
    st.markdown("""
    Podle poslechového hodnocení byl referenční UDP/RTP hovor
    přerušovaný s projevy vysokého jitteru. Oba zabezpečené scénáře
    (G.711 i GSM) byly bez slyšitelných výpadků; mezi GSM a G.711 nebyl
    zaznamenán zřetelný subjektivní rozdíl.

    Tuto zkušenost **nelze vysvětlovat tím, že TLS opravilo UDP packet
    loss**. Provoz SRTP nadále běží na UDP, bezdrátové podmínky byly
    proměnlivé a původní RTP záznam vykázal sekvenční anomálii
    viditelnou již na vysílající straně. Experiment má proto
    demonstrační hodnotu, nikoliv charakter opakovaného statisticky
    kontrolovaného QoS benchmarku.
    """)
    st.subheader("Vlastní přínos a názor autorů")
    st.markdown("""
    Za největší přínos považujeme praktickou realizaci dvou nezávislých
    ústředen s vlastní PKI a vzájemnou TLS autentizací, zaznamenání
    skutečných RTP/SRTP paketů na obou serverech, porovnání režie
    paketů a zkoušku GSM překódování na již zabezpečeném trunku.
    Díky skutečným PCAP a výstupům `pidstat` bylo možné oddělit
    **režii jednoho paketu** od zkreslení způsobeného různým počtem
    paketů v jednotlivých hovorech.

    Výsledky ukazují, že zabezpečený Asterisk trunk je použitelný
    i na běžných noteboocích a kompaktní bezdrátové laboratoři;
    u GSM je zajímavý kompromis mezi snížením síťového toku a
    mírně zvýšenou výpočetní náročností překódování.
    """)
    st.subheader("Rozdělení práce mezi autory")
    table(pd.DataFrame([
        {"Činnost": "Návrh projektu a laboratorního řešení", "Hlavní odpovědnost": "Oryna Borovyk (bor0250)"},
        {"Činnost": "Konfigurace Asterisk ústředen, certifikátů a trunků", "Hlavní odpovědnost": "Oryna Borovyk a David Kunčík (společně)"},
        {"Činnost": "Telefonní hovory, bezpečnostní testy a měření", "Hlavní odpovědnost": "Oryna Borovyk a David Kunčík (společně)"},
        {"Činnost": "Vyhodnocení, grafy a webová dokumentace", "Hlavní odpovědnost": "David Kunčík (kun212)"},
    ]))
    st.subheader("Použité zdroje")
    st.markdown("""
    1. [Asterisk 20 – konfigurace res_pjsip](https://docs.asterisk.org/Asterisk_20_Documentation/API_Documentation/Module_Configuration/res_pjsip/)
    2. [Asterisk – PJSIP Configuration Sections and Relationships](https://docs.asterisk.org/Configuration/Channel-Drivers/SIP/Configuring-res_pjsip/PJSIP-Configuration-Sections-and-Relationships/)
    3. [RFC 3261 – SIP](https://www.rfc-editor.org/rfc/rfc3261)
    4. [RFC 3550 – RTP](https://www.rfc-editor.org/rfc/rfc3550)
    5. [RFC 3711 – Secure Real-time Transport Protocol](https://www.rfc-editor.org/rfc/rfc3711)
    6. [RFC 3551 – RTP Profile / GSM Full Rate](https://www.rfc-editor.org/rfc/rfc3551)
    7. [Wireshark User's Guide – RTP Analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChTelRTP.html)
    8. [Streamlit – oficiální dokumentace](https://docs.streamlit.io/)
    9. **Vlastní laboratorní data:** konfigurace ústředen, příkazové výstupy Asterisk a OpenSSL,
       PCAP záznamy, výstupy TShark a pidstat, snímky MizuDroid a fotografie zapojení,
       22. listopadu 2026.
    """)

st.divider()
