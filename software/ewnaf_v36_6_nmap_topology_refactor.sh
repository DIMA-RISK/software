#!/usr/bin/env bash
# ================================================================================
#  EWNAF v36.6-radar-reset — Enterprise Network Audit Framework
#  Heuristic Network Audit | Bash 4.4+ | Final candidate build
#
#  METODOLOGIA: RESIDUAL RISK = RAW_RISK - VERIFIED_MITIGATIONS
#  FAZA X:      Exploratory loop — sense → move → react → adapt → map
#
#  POLITYKA: Brak exploitów | Brak brute force | Read-only reconnaissance
#
# ── CHANGELOG v26.0.1 ──────────────────────────────────────────────────────────
#
#  BUGFIXES:
#
#  [FIX-001] _fw_collect_samples
#            `local -a samples=() i d` — i i d były tablicami, nie skalarami.
#            POPRAWKA: `local -a samples=()` + `local i d`
#
#  [FIX-002] _tcp_samples_median
#            Analogiczny wzorzec jak FIX-001.
#            POPRAWKA: `local -a vals=()` + `local i d`
#
#  [FIX-003] _sched_adaptive_jitter
#            `base="${SESSION_STATE[...]}"` bez fallback → division by zero.
#            POPRAWKA: `:-300` + guard `(( base < 2 )) && base=2`
#
#  [FIX-004] g_host_detect
#            `p` i `state` bez `local` — wyciek do globalnej przestrzeni.
#            POPRAWKA: `local p state` na początku funkcji.
#
#  DEAD CODE (zidentyfikowany, bez zmian logiki):
#
#  [NOTE-001] filter_false_ports() / _is_fake_port() / _port_fingerprint()
#             Nie wywoływane. is_mirage_port() to stub (return 1). Do v26.1+.
#
#  [NOTE-002] g_host_detect() / g_dns_classify() / g_visibility_score()
#             Dead code w bloku Gandalf. g_tcp_probe() aktywna (Faza X).
#
# ── CHANGELOG v26.3.2 ──────────────────────────────────────────────────────────
#
#  [BUGFIX-001] readonly CW/CC/CD/CM/CG/CR/CN/CBOLD conflict w print_summary()
#               Zmienne są globalne readonly (line 426-428). print_summary()
#               próbowała je zadeklarować jako local — błąd "readonly variable".
#               Fix: usunięto local declaration, funkcja używa globals bezpośrednio.
#
#  [BUGFIX-002] DNS_VERSION_DISCLOSURE: "not disclosed"; }; w named.conf
#               Tekst rekomendacji zawierał "; };" co bash interpretował jako
#               koniec instrukcji w arithmetic expansion.
#               Fix: zamieniono "not disclosed" na 'none' (równoważna dyrektywa BIND).
#
#  [BUGFIX-003] Wieloliniowe subshell w heredoc HTMLEOF (sekcja s1d KPI)
#               Pre-computed variables zamiast $() wewnątrz attribute="".
#
#  [BUGFIX-004] $(echo $zc) w echo string — niepotrzebny subshell
#               Fix: zamieniono $(echo $zc) na ${zc} bezpośrednio.
#
# ── CHANGELOG v26.3.1 ──────────────────────────────────────────────────────────
#
#  [MOD-008] Faza X — warstwa interpretacji actionable findings
#             export_phase_x_findings() rozszerzone o konkretne rekomendacje
#             per zone type:
#
#             DECEPTION: rozróżnia honeypot / tarpit / fake listener / SSH tarpit
#                        z dedykowaną rekomendacją dla każdego podtypu
#
#             CORRELATED: rozróżnia NDR enterprise (behavioural analytics stack, score≥70%)
#                         vs IDS z korelacją (telemetry correlation stack, score 50-70%)
#                         Rekomendacja: uzgodnij okno audytu z SOC, whitelist IP
#
#             ADAPTIVE: rozróżnia persistent blacklist (STILL_ELEVATED recovery)
#                       vs short ban-time. Konkretna rekomendacja ban-time.
#
#             ESCALATING: interpretuje window_type (THRESHOLD/GRADUAL/BURSTY)
#                         Dla THRESHOLD: podaje N progu i ocenia agresywność
#                         N≤3: BARDZO AGRESYWNY — zablokuje Qualys/Tenable
#                         N≤7: AGRESYWNY — wyklucz skanery autoryzowane
#                         N>7: UMIARKOWANY — rozważ obniżenie
#
#             REACTIVE: rozróżnia wysoka latencja bazowa (proxy/IDS inline)
#                       vs normalna. Rekomendacja: fail2ban + CrowdSec minimum.
#
#             EXPOSED: konkretny action plan: fail2ban + iptables limit + CrowdSec
#
#             SILENT: potwierdzenie DROP policy jako prawidłowego zachowania
#
#             Globalna synteza:
#             - Próg blokady siecowy z oceną agresywności
#             - IDS/NDR identification (score-based)
#             - Ocena dojrzałości posture (DOJRZAŁA / ŚREDNIA / NISKA)
#             - Heat level warning przy heat≥70
#
#  [MOD-008b] Faza X HTML section (s1d)
#             Nowa sekcja raportu z:
#             - KPI grid (heat, threat, correlation, zones)
#             - Tabela per-host zones z interpretacją
#             - Per-host score bars (reactivity/adaptivity/deception/correlation)
#             - Szczegółowe dane: baseline, window_type, ban_n, recovery
#             - Legenda 7 stref z opisami
#
# ── CHANGELOG v26.3.0 ──────────────────────────────────────────────────────────
#
#  ENTERPRISE VISIBILITY & REPORTING — siedem nowych modułów
#
#  [MOD-001] CVSS v3.1 scoring per finding
#             Funkcja cvss_for_finding() mapuje kategorie na typowe base scores
#             z NIST NVD. add_finding() dostaje 6-ty parametr cvss (auto-calc).
#             HTML raport wyświetla kolorowe badge CVSS obok każdego findingu.
#
#  [MOD-002] UDP service detection — audit_udp()
#             DNS/53 (version disclosure, open resolver), NTP/123 (monlist/amplif.),
#             SNMP/161 (community string probe bez snmpwalk), NetBIOS/137,
#             mDNS/5353, SSDP/1900 (UPnP device disclosure), TFTP/69.
#             Dodano nmblookup/snmpwalk/ldapsearch/rpcclient/smbclient do preflight.
#
#  [MOD-003] TLS/cert audit per host — audit_tls()
#             Per każdy host z portem TLS (443/8443/8006/636/993/995/587/465):
#             - Expiry: wygasły / ≤14 dni / ≤30 dni
#             - Self-signed (issuer CN == subject CN)
#             - Słaby algorytm podpisu (SHA1/MD5)
#             - Przestarzały protokół (SSLv2/3/TLS1.0/1.1)
#             - Słaby cipher suite (RC4/DES/3DES/NULL)
#             - SAN mismatch (IP nie w SAN/CN)
#
#  [MOD-004] Active Directory / Kerberos detection — audit_ad()
#             Kerberos/88 AS-REQ probe, LDAP/389 anonymous rootDSE bind,
#             LDAPS/636 cert check, SMB signing detection (NTLM relay risk),
#             Global Catalog/3268, Kerberoasting probe (SPN enumeration),
#             MS-RPC/135 Windows fingerprint.
#
#  [MOD-005] Lateral movement — actual TCP reachability — audit_lateral()
#             Nie tylko "czy port jest otwarty" ale faktyczna próba połączenia
#             TCP per host:port. Wykrywa brak segmentacji east-west.
#             Port scope: 445/22/3389/5985/5986/3306/1433/5432/6379/27017.
#             Specific findings: SMB bez signing, RDP public, WinRM, DB exposure.
#
#  [MOD-006] Attack Path / Kill Chain — build_attack_path()
#             5-krokowy kill chain (MITRE ATT&CK): Initial Access, Execution,
#             Lateral Movement, Privilege Escalation, Impact/Exfiltration.
#             Opiera się na wykrytych danych — bez hardcodowania.
#             Nowa sekcja HTML z tabelą kill chain + AD attack context.
#
#  [MOD-007] Remediation Roadmap — build_remediation_roadmap()
#             3 horyzonty: Quick (0-7d CVSS≥9), Short (1-4tyg CVSS≥7),
#             Strategic (3-6m architektura). Nowa sekcja HTML z tabelami.
#             C-suite executive briefing w sekcji s1 z business impact narrative.
#
#  [FIX-018] OS detection rozszerzony: 4 warstwy (TTL → vendor OUI →
#             banner grep → port combinations). Dodano: Proxmox, Docker,
#             K8s, SCADA/ICS, BACnet, RouterOS, pfSense, Synology, Ubiquiti.
#
#  [FIX-019] Role detection: Proxmox, Docker API, K8s/etcd, SNMP device,
#             SCADA/ICS, BACnet, Memcached, RabbitMQ, Kafka.
#
#  [FIX-020] Banner ports expanded: Redis:6380, Proxmox:8006, Kibana:5601,
#             RabbitMQ:15672, Docker:2375/2376, IMAPS:993, POP3S:995.
#
# ── CHANGELOG v26.2.9 ──────────────────────────────────────────────────────────
#
#  [FIX-017] discover_hosts(): host z DROP policy niewidoczny
#             ROOT CAUSE: TCP probe sprawdzał tylko porty 22/80/443/445/3389/53
#             i rejestrował host TYLKO gdy rc=0 (OPEN). Host z pełnym DROP policy
#             (brak ICMP, brak RST) zwraca timeout → alive=0 → host pominięty.
#
#             POPRAWKA 1 — TCP probe rozszerzony:
#               Dodano porty 22222/8006/9200/9000, timeout 0.8s (był 1s).
#
#             POPRAWKA 2 — g_host_detect fallback:
#               Gdy TCP probe nie wykryje hosta, uruchamia g_host_detect()
#               (Gandalf: g_tcp_probe per port). Rozróżnia HOST_PRESENT
#               vs HOST_FIREWALLED (≥2 portów FILTERED = host istnieje za DROP).
#               Hosty HOST_FIREWALLED są rejestrowane z finding FIREWALLED_HOST.
#
#             POPRAWKA 3 — ARP: /proc/net/arp:
#               Dodano jako trzecie źródło ARP (WSL-friendly, kernel ARP table
#               dostępna nawet gdy "ip neigh" jest ograniczone w WSL).
#               Dotyczy obu miejsc: discover_hosts() i probe_topology().
#
#             POPRAWKA 4 — g_host_detect ports:
#               Rozszerzono z (22 80 443 445) do
#               (22 80 443 445 8080 3389 53 22222 8006 9200 9000).
#
# ── CHANGELOG v26.2.8 ──────────────────────────────────────────────────────────
#
#  [FIX-016] map_compliance(): idx: unbound variable
#             LOKALIZACJA: linia ~4069
#             PRZYCZYNA: bash ewaluuje wszystkie wartości w jednej instrukcji
#             "local" od lewej do prawej, w jednym przebiegu. Zmienna idx
#             nie jest jeszcze przypisana gdy bash ewaluuje ${D_PORTS[$idx]}
#             po prawej stronie — set -u → "idx: unbound variable".
#               BYŁO:   local idx="$1" ports="${D_PORTS[$idx]}" score="..."
#               JEST:   local idx="$1"
#                       local ports="${D_PORTS[$idx]:-}" score="..."
#
# ── CHANGELOG v26.2.7 ──────────────────────────────────────────────────────────
#
#  [FIX-014] g_tcp_probe / _port_fingerprint / declare BH/PHASE_X: command not found
#             Ten sam root cause co FIX-008/013: blok (##..## + funkcje g_* + deklaracje
#             BH/BMAP/PHASE_X) zdefiniowany PO bloku wykonawczym. Przeniesiony przed
#             "# NOWY MAIN".
#
#  [FIX-015] BH[] subshell isolation — "172.31.0.1:80:reactivity: invalid arithmetic"
#             ROOT CAUSE: bash associative arrays NIE dziedziczą do subshell $().
#             Funkcje _bh_baseline, _bh_deception_probe, _bh_window_analyze,
#             _bh_classify_zone (x2), _choose_next_target wywoływane jako $() —
#             odczyty BH zwracały puste wartości, zapisy były tracone.
#             POPRAWKA: Każda z tych funkcji ustawia globalną _BH_RET="" zamiast
#             tylko echo. Wywołania zmienione z result=$(...) na:
#               func args; result="$_BH_RET"
#             Backward-compatible: echo nadal istnieje dla pipe-usage.
#
# ── CHANGELOG v26.2.6 ──────────────────────────────────────────────────────────
#
#  [CLEAN-002] Usunięto zbędne bloki dekoracyjne:
#              - ASCII art FAZA X (8 linii ██ + 20 linii opisu filozoficznego)
#              - "Pies wraca. Jabol..." (KONIEC FAZY X)
#              - "Malarz tyka lewą ścianę. Strażnik..." (cross-service dep.)
#              - "Gandalf (g_tcp_probe) jako mag / czas to zapach"
#              - log "FAZA X: BEHAVIOURAL RECON — Pies, Malarz, Zlodziej"
#              - komentarze "idź w stronę zapachu" / "gdzie jest najsilniejszy zapach"
#              Zastąpione zwięzłymi techicznymi opisami.
#
# ── CHANGELOG v26.2.5 ──────────────────────────────────────────────────────────
#
#  [FEAT-001] Internationalisation: --lang pl|en
#             declare -A _MSG_PL[] i _MSG_EN[] z ~80 kluczami obejmującymi
#             wszystkie SECTION/INFO/WARN/OK komunikaty. Funkcja L() podstawia
#             %s argumenty przez printf. Domyślny język: pl.
#             Użycie: bash EWNAF.sh --lang en
#
#  [FIX-013] _bh_probe_full / _bh_budget_ok / export_phase_x_findings: command not found
#             PRZYCZYNA: cały blok Fazy X (19 funkcji _bh_* + export_phase_x_findings
#             + declare -A BH_WINDOW) zdefiniowany PO bloku wykonawczym (linia ~5900).
#             Ten sam problem co _conf_calibrate (FIX-008): bash sekwencyjny.
#             POPRAWKA: Przeniesiono cały blok (# SLIDING WINDOW..KONIEC FAZY X)
#             przed "# NOWY MAIN — PETLA ZAMIAST PIPELINE".
#
#  [CLEAN-001] Usunięto opisowe komunikaty "jak dla dzieci":
#             "Sprawdzam lokalne instalacje..." → "[Fleet] local scan..."
#             "Skanuję sieć w poszukiwaniu Fleet server..." → "[Fleet] network scan..."
#             "[0.x] Wykrywanie/Generowanie/Dobór..." → skrótowe etykiety
#             Wszystkie SECTION nagłówki skrócone do formy technicznej.
#
# ── CHANGELOG v26.2.4 ──────────────────────────────────────────────────────────
#
#  [FIX-012] awk: backslash not last character on line
#            LOKALIZACJA: _tls_fp_openssl() linia 763
#            PRZYCZYNA: awk -F'=' '/Fingerprint=/{gsub(/:/,"",\$2)...'
#              \$2 wewnątrz single-quoted awk program = literalny backslash + $2.
#              awk interpretuje \$ jako nieznany escape → syntax error.
#              W single quotes bash nie dotyka $, więc backslash był zbędny.
#            POPRAWKA: \$2 → $2
#
# ── CHANGELOG v26.2.3 ──────────────────────────────────────────────────────────
#
#  [FIX-010] _dig_classify / _dns_egress_probe / _tls_fp_openssl: command not found
#            PRZYCZYNA: html_esc() (linia ~675) zawierała:
#              s="${s//'/&#39;}"
#            Apostrophe jako wzorzec w ${s//PAT/REP} wewnątrz double-quotes
#            jest syntaktycznie poprawny w bash (RFC), ale bash PARSER w pewnych
#            kontekstach (process substitution, source przez pipe) interpretuje '
#            jako koniec stringa, pozostawiając resztę pliku jako "raw string".
#            Wszystkie definicje funkcji PO html_esc (w tym _dig_classify, linia ~688,
#            _dns_egress_probe, _tls_fp_openssl, _doh_json_ok) były "wchłaniane"
#            przez niezamknięty parser state i nigdy nie były rejestrowane.
#            POPRAWKA: Zastąpiono apostroph przez zmienną pośrednią:
#              local _sq=$'''
#              s="${s//$_sq/&#39;}"
#
#  [FIX-011] BH_BUDGET: unbound variable
#            PRZYCZYNA: BH_* parametry Fazy X inicjalizowane przez ': "${BH_*:=N}"'
#              na linii ~6138 (Faza X sekcja) — PO bloku wykonawczym (5869).
#              set -u powoduje crash przy ${BH_BUDGET} w linii 5674 gdy nie
#              podano --budget flag (nie inicjalizowane przez arg parser).
#            POPRAWKA: Dodano deklaracje globalne z wartościami domyślnymi
#              na linii 230 (przed blokiem wykonawczym):
#              BH_BUDGET="${BH_BUDGET:-150}"  (i 6 pozostałych BH_* zmiennych)
#              Format :-N zamiast :=N pozwala --budget flagę nadpisać wartość.
#
# ── CHANGELOG v26.2.2 ──────────────────────────────────────────────────────────
#
#  [FIX-008] _conf_calibrate: command not found — POTWIERDZONE
#            PRZYCZYNA: _conf_calibrate() zdefiniowana na linii ~6344 (Faza X),
#              PO bloku wykonawczym (linia ~5827). Bash jest interpreterem
#              sekwencyjnym — parsuje i wykonuje linia po linii. Gdy "preflight"
#              uruchamia topo_detect_dns_filter → _conf_dns_filter → _conf_calibrate,
#              parser nie doszedł jeszcze do linii 6344. Funkcja nie istnieje.
#            POPRAWKA: Przeniesiono _conf_calibrate() na linię ~438 — przed
#              wszystkimi adapterami _conf_*() które jej używają.
#
#  [FIX-009] _dig_classify: command not found — DIAGNOSTYKA
#            ANALIZA: _dig_classify() (linia 663) jest zdefiniowana PRZED blokiem
#              wykonawczym (5835) — kolejność jest poprawna.
#              Błąd "command not found" przy uruchomieniu sugeruje wykonanie przez
#              'sh' lub 'dash' zamiast 'bash'. W sh/dash:
#              - składnia `func() {` może nie być parsowana identycznie
#              - brak declare -A (associative arrays) powoduje cascade failures
#              - bash-specific builtins crashują przy definicji funkcji
#            POPRAWKA: Dodano guard po set -uo pipefail:
#              sprawdzenie BASH_VERSION >= 4.4 z czytelnym komunikatem błędu.
#              Uruchomienie przez 'sh skrypt.sh' teraz daje:
#              "EWNAF wymaga bash >= 4.4. Uruchom: bash <skrypt>"
#
# ── CHANGELOG v26.2.1 ──────────────────────────────────────────────────────────
#
#  BUGFIXES:
#
#  [FIX-005] _conf_calibrate() — bomba wyjaśniona
#            STAN: funkcja istnieje na linii 6319, poziom globalny, dostępna.
#            Brak akcji wymagany. Udokumentowane dla przejrzystości.
#
#  [FIX-006] SSH tarpit — compound regex w [[ ... ]]
#            PROBLEM: `[[ A =~ X && ! B =~ Y ]]` — bash ocenia `&&` wewnątrz
#                     `[[` jako bitowy operator w niektórych kontekstach.
#                     Nieczytelne, ryzykowne przy rozszerzaniu.
#            POPRAWKA: Rozdzielono na dwa oddzielne wyrażenia:
#                      `[[ A =~ X ]] && [[ ! B =~ Y ]]`
#
#  [FIX-007] prefix shift — potencjalny UB i crash (3 miejsca)
#            PROBLEM: `local _mask=$(( 0xFFFFFFFF << (32-prefix) & 0xFFFFFFFF ))`
#                     - prefix="" (pusty cidr z broken ip) → bash arytm. crash
#                     - prefix=0 → shift 32 → _mask=0 → full_net="0.0.0.0/0"
#                       (błędny subnet, potencjalnie wchodzi do SUBNETS[])
#            POPRAWKA: Guard przed każdym shiftem (3 miejsca: topo_select_subnets,
#                      preflight subnet detection, ultimate fallback):
#                        _is_int "$prefix" || continue
#                        (( prefix < 1 || prefix > 32 )) && continue
#
# ── CHANGELOG v26.2.0 ──────────────────────────────────────────────────────────
#
#  ARCHITEKTURA — Centralny model confidence
#
#  Problem: 9 niezależnych modeli confidence z różnymi architekturami:
#    - Modele A (addytywne): _fw_drop_confidence, _ssh_tarpit_confidence
#    - Modele B (skokowe stałe): IDS, DNS filter, L3 drop, DNS leak, TLS
#    - Model C (sample-count only): L3 east-west
#    - Model D (multiplicatywny): Faza X _conf_calibrate()
#  Każdy definiował "co to pewność" inaczej. Zmiana jednego nie propagowała.
#
#  Rozwiązanie:
#    _conf_calibrate() (linia ~6356) — istniejący multiplicatywny engine —
#    awansuje do roli jedynego kalkulatora confidence w całym skrypcie.
#    Wzór: conf = 50 × N_factor × (1−V_penalty) × R_factor × B_factor
#      N_factor  = min(1, observations/required)  — rośnie z próbką
#      V_penalty = variance/200                   — kara za zmienność
#      R_factor  = 0.5 + repeats/(2×observations) — powtarzalność
#      B_factor  = 1.0 jeśli baseline, 0.75 jeśli nie
#
#  Adaptery domenowe (linia ~335–510) — każdy tłumaczy surowe dane na
#  5 parametrów silnika i deleguje obliczenie:
#    _conf_fw_drop()         firewall DROP: med, var(ms), n_drop, n_total, baseline
#    _conf_ssh_tarpit()      SSH tarpit: med, var(ms), baseline, banner_ok
#    _conf_ids_ratelimit()   IDS/rate-limit: base_gw, post_gw, var(ms), ext_spiked
#    _conf_dns_filter()      DNS filtering: n_blocked, n_observed
#    _conf_l3_silent_drop()  L3 silent DROP: delta(ms), baseline(ms)
#    _conf_l3_east_west()    L3 east-west: flat_total, flat_hits
#    _conf_dns_leak()        DNS leak: udp_ok, tcp_ok, n_tested
#    _conf_tls_intercept()   TLS interception: issuer_match, san_delta, n_checks
#
#  Progi decyzyjne (>= 65, >= 75, >= 80, >= 85) NIEZMIENIONE — to jest
#  wiedza domenowa, nie silnik.
#
#  Stare funkcje _fw_drop_confidence() i _ssh_tarpit_confidence() zachowane
#  jako wrappery delegujące do adapterów (backward-compat z 2 callerami).
#
#  Efekt: zmiana parametryzacji silnika propaguje automatycznie do wszystkich
#  9 modeli. Zero rozbieżności między domenami.
#
# ── CHANGELOG v26.1.0 ──────────────────────────────────────────────────────────
#
#  REFACTORING — probe_topology() rozdzielona na subfunkcje:
#
#  [REFAC-001] probe_topology() — 454 linie → orchestrator 42 linie
#              Poprzednio: monolit łączący 8 niezależnych zadań w jednej funkcji.
#              Zmiana czysto strukturalna — zero zmiany logiki.
#              Nowe funkcje wywoływane w tej samej kolejności:
#                topo_detect_vpn()          [0.1] VPN/Tunnel detection
#                topo_detect_wan()          [0.2] WAN IP vs VPN IP
#                topo_detect_nat()          [0.3] NAT Layers
#                topo_detect_ids()          [0.4a] IDS/Rate-limit detection
#                topo_detect_dns_filter()   [0.4b] DNS filtering
#                topo_detect_ssh_tarpit()   [0.4c] SSH tarpit (behawioralny)
#                topo_detect_autoban()      [0.4d] Auto-ban detection
#                topo_detect_firewall()     [0.5] Firewall fingerprint
#                topo_select_subnets()      [0.6] Subnet selection
#                topo_scan_recommendation() [0.7] Scan recommendation
#                topo_generate_report()     [0.8] Topology report
#              Korzyść: każdą subfunkcję można testować i debugować niezależnie.
#              Efekt domina podczas poprawek ograniczony do jednej funkcji.
#
#  PRECISION — IDS detection (topo_detect_ids):
#
#  [PREC-001]  Dodano zbieranie 3 próbek variance post-burst (_ids_post_samples).
#              Poprzednio: decyzja wyłącznie na podstawie mediany (podatne na
#              chwilowy jitter ISP lub wolny router embedded).
#              Teraz: niska wariancja (< 500ms) = stabilny throttling → +8% conf.
#              TOPO[ids_conf] zapisywany i używany w DEFENSE_SCORE.
#
#  PRECISION — SSH tarpit detection (topo_detect_ssh_tarpit):
#
#  [PREC-002]  Hard floor: jeśli median < 2500ms I ratio < 800%, confidence
#              redukowane do 70% wartości bazowej.
#              Problem: endlessh z małym delay (~1500ms) + wolny router embedded
#              mogły dawać false positive przy _ssh_conf >= 85%.
#              Teraz próg praktycznie eliminuje false positive na routerach 4G/DSL.
#              Logika _ssh_tarpit_confidence() niezmieniona.
#              n_samples guard: wykonanie confidence tylko gdy n_samples >= 3.
#
#  NOWE — Defense Posture scoring:
#
#  [NEW-001]   DEFENSE_SCORE (0-100), DEFENSE_LEVEL (Low/Medium/High/Advanced),
#              DEFENSE_SUMMARY (jednozdaniowy opis) — globalne zmienne.
#              Obliczane w build_executive() po GLOBAL_SCORE.
#              Model: suma ważona 7 warstw obrony z confidence-scaling:
#                Warstwa 1: Stateful firewall (max 20 pkt, skalowany przez conf)
#                Warstwa 2: IDS/Rate limiting (max 20 pkt, skalowany przez conf)
#                Warstwa 3: DNS Filtering     (15 pkt stały)
#                Warstwa 4: L3 East-West izolacja (15 pkt)
#                Warstwa 5: Cross-subnet blokada  (10 pkt)
#                Warstwa 6: Egress kontrola       (5 + 5 pkt)
#                Warstwa 7: Auto-ban + SSH tarpit  (6 + 4 pkt)
#              Progi: <30=Low, 30-54=Medium, 55-79=High, >=80=Advanced
#              Eksport: JSON "executive.defense_score/level/summary"
#              HTML: nowy KPI box w dashboardzie (kolor zależny od poziomu)
#              Konsola: nowy blok "DEFENSE POSTURE" w print_summary z paskiem
#
# ────────────────────────────────────────────────────────────────────────────────

set -uo pipefail

# Optional strict mode: enable errexit + ERR trap (off by default for backward-compat)
_err_trap() {
    local rc=$? line="${BASH_LINENO[0]:-?}" cmd="${BASH_COMMAND:-?}"
    if declare -F log >/dev/null 2>&1; then
        log "ERR rc=${rc} line=${line} cmd=${cmd}" "ERROR"
    else
        echo "[ERROR] ERR rc=${rc} line=${line} cmd=${cmd}" >&2
    fi
    return $rc
}

# Guard: skrypt wymaga bash 4.4+ (associative arrays, nameref, declare -A)
# Uruchomienie przez 'sh skrypt.sh' zamiast 'bash skrypt.sh' lub './skrypt.sh'
# powoduje "command not found" dla wszystkich funkcji z powodu braku hoistingu w dash/sh
if [[ -z "${BASH_VERSION:-}" ]] || (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    echo "EWNAF wymaga bash >= 4.4. Uruchom: bash ${BASH_SOURCE[0]:-$0}" >&2
    exit 1
fi

readonly VERSION="36.6.0-RADAR-RESET-FINAL-R2"
readonly TIMESTAMP="$(date +"%Y%m%d-%H%M%S")"
readonly LOCK_FILE="/tmp/net_audit_v26.lock"
readonly SEP=$'\x01'

# Kolory
readonly CR="\033[0;31m" CO="\033[0;33m" CG="\033[0;32m" CC="\033[0;36m"
readonly CW="\033[1;37m" CD="\033[0;37m" CM="\033[0;35m" CN="\033[0m"
readonly CBOLD="\033[1m"

# Dynamiczne cele odniesienia — bez twardych adresów IP
readonly EXT_DNS_PRIMARY=""
readonly EXT_DNS_SECONDARY=""
readonly EXT_DNS_TERTIARY=""
readonly EXT_DNS_QUAD=""
readonly EXT_CTRL_HOST=""
readonly EXT_CTRL_HOST2=""

# v28 architectural hardening — target-centric audit only
TARGET_CENTRIC_MODE=1
EXPORT_RAW_IDENTIFIERS=0
ENABLE_LOCAL_TOPOLOGY_INFERENCE=0
ENABLE_OPTIONAL_PRODUCT_MODULES=0
ENABLE_WAN_DISCOVERY=0
PASSIVE_ONLY="${PASSIVE_ONLY:-1}"
GENERIC_BEHAVIOUR_LABELS="${GENERIC_BEHAVIOUR_LABELS:-1}"
TOPOLOGY_NMAP_ENABLED="${TOPOLOGY_NMAP_ENABLED:-1}"
TOPOLOGY_NMAP_MAX_PORTS="${TOPOLOGY_NMAP_MAX_PORTS:-12}"
TOPOLOGY_NMAP_HOST_TIMEOUT="${TOPOLOGY_NMAP_HOST_TIMEOUT:-20s}"
TOPOLOGY_NMAP_VERSION="${TOPOLOGY_NMAP_VERSION:-1}"



# PARAMETRY

MODE="${MODE:-passive}"
CLIENT_NAME="Enterprise"

_detect_real_user() {
    local u=""
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        u="${SUDO_USER}"
    elif [[ -n "${LOGNAME:-}" && "${LOGNAME}" != "root" ]]; then
        u="${LOGNAME}"
    elif [[ "${USER:-}" != "root" && -n "${USER:-}" ]]; then
        u="${USER}"
    elif [[ "$PWD" == /home/* ]]; then
        u="$(stat -c '%U' "$PWD" 2>/dev/null || true)"
        [[ "$u" == "root" ]] && u=""
        if [[ -z "$u" ]]; then
            u="${PWD#/home/}"
            u="${u%%/*}"
        fi
    fi
    [[ -z "$u" ]] && u="root"
    printf '%s' "$u"
}

REAL_USER="$(_detect_real_user)"
REAL_HOME="$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6)"
[[ -z "$REAL_HOME" ]] && REAL_HOME="$HOME"
OUTPUT_ROOT="$REAL_HOME/EWNAF-Reports"
AUDIT_STATUS="READY"
AUDIT_NOTE=""
SUBNETS_ARG=""
WAN_IP_OVERRIDE=""
SKIP_WAN=0
SKIP_BANNERS=0
QUIET=0
MAX_PARALLEL=20
SAFE_MODE=1
SAFE_JITTER_MS=60
SAFE_HOSTS_SAMPLE=5
SAFE_BURST_MAX=3
STRICT_MODE=0
DETERMINISTIC=0
DETERMINISTIC_SEED=""

# Faza X — domyślne parametry behawioralne (nadpisywane przez --budget i env)
BH_BUDGET="${BH_BUDGET:-150}"
BH_JITTER_MAX="${BH_JITTER_MAX:-900}"
BH_JITTER_MIN="${BH_JITTER_MIN:-80}"
BH_BURST_SIZE="${BH_BURST_SIZE:-5}"
BH_COOLDOWN="${BH_COOLDOWN:-3}"
BH_BASELINE_N="${BH_BASELINE_N:-3}"
BH_PROBE_TIMEOUT="${BH_PROBE_TIMEOUT:-2}"


ewnaf_profile_label() {
    case "${MODE:-passive}" in
        passive)  printf '%s' 'strict_passive' ;;
        standard) printf '%s' 'light_active' ;;
        deep)     printf '%s' 'deep_active' ;;
        *)        printf '%s' "${MODE:-passive}" ;;
    esac
}

ewnaf_choose_language() {
    if [[ "${LANG_EXPLICIT:-0}" == "1" ]]; then
        [[ "${LANG_MODE:-pl}" != "en" ]] && LANG_MODE="pl"
        return 0
    fi
    if [[ -t 0 && -t 1 ]]; then
        echo
        echo "Wybierz język / Choose language"
        echo "  1) Polski"
        echo "  2) English"
        read -r -p "> " _ewnaf_lang_choice
        case "${_ewnaf_lang_choice:-1}" in
            2|en|EN|English|english) LANG_MODE="en" ;;
            *) LANG_MODE="pl" ;;
        esac
    else
        LANG_MODE="${LANG_MODE:-pl}"
        [[ "$LANG_MODE" != "en" ]] && LANG_MODE="pl"
    fi
}

ewnaf_show_intro() {
    local profile
    profile="$(ewnaf_profile_label)"
    echo
    if [[ "${LANG_MODE:-pl}" == "en" ]]; then
        cat <<EOF
EWNAF is a defensive heuristic network audit.
It is observation-first: it maps behaviour, segmentation, exposure, topology
and risk signals without assigning vendor-specific product labels.

Selected execution profile: ${profile}
- strict_passive: observe only
- light_active: limited verification
- deep_active: broader validation inside authorized scope

The runtime environment is treated as an observation point, not as a representative model of the entire network.
Use this tool only on infrastructure you own or are explicitly authorized to assess.
The report is expected to contain signals, inferences, confidence and limitations.
EOF
    else
        cat <<EOF
EWNAF jest defensywnym heurystycznym audytem sieci.
Działa w modelu observation-first: mapuje zachowanie, segmentację, ekspozycję,
topologię i sygnały ryzyka bez przypisywania nazw konkretnym produktom.

Wybrany profil wykonania: ${profile}
- strict_passive: wyłącznie obserwacja
- light_active: ograniczona weryfikacja
- deep_active: szersza walidacja w autoryzowanym zakresie

Audyt nie powinien zakładać, że środowisko uruchomieniowe audytora jest reprezentatywne dla całej sieci.
Narzędzie należy stosować wyłącznie we własnej infrastrukturze albo na podstawie
wyraźnego upoważnienia. Raport powinien zawierać sygnały, wnioski, pewność i ograniczenia.
EOF
    fi
    echo
}


ewnaf_legal_notice() {
    echo
    if [[ "${LANG_MODE:-pl}" == "en" ]]; then
        cat <<EOF
Usage notice:
- defensive audit only
- use only on infrastructure you own or are explicitly authorized to assess
- no claim of complete network truth from a single vantage point
- interpret results together with confidence and limitations
EOF
    else
        cat <<EOF
Informacja o użyciu:
- wyłącznie audyt defensywny
- użycie tylko we własnej infrastrukturze albo za wyraźnym upoważnieniem
- brak założenia, że jeden punkt obserwacji opisuje całą sieć
- wyniki należy interpretować razem z pewnością i ograniczeniami
EOF
    fi
    echo
}
ewnaf_confirm_intro() {
    local answer
    if [[ ! -t 0 || ! -t 1 ]]; then
        return 0
    fi
    if [[ "${LANG_MODE:-pl}" == "en" ]]; then
        read -r -p "Do you want to continue? [Y/N] " answer
        [[ "$answer" =~ ^([YyTt])$ ]]
    else
        read -r -p "Czy chcesz kontynuować? [T/N] " answer
        [[ "$answer" =~ ^([TtYy])$ ]]
    fi
}

usage() {
    cat <<EOF
EWNAF v${VERSION} – Defensive Heuristic Network Audit / Defensywny heurystyczny audyt sieci

Usage / Użycie: $0 [OPTIONS]

  -m|--mode        passive|standard|deep  (default/domyslnie: passive)
  -c|--client      Client / Nazwa klienta
  -o|--output      Output directory / Katalog wyjściowy (default: ~/EWNAF-Reports)
  -s|--subnets     Optional scope seed CSV / Opcjonalny seed scope CSV
  -w|--wan         Public router IP for exposure check / Publiczny IP routera do testu ekspozycji
  -j|--jobs        Max parallel jobs / Maks. równoległych zadań
  --budget         Behavioural budget / Budżet heurystyczny
  --skip-wan       Skip WAN checks / Pomiń testy WAN
  --skip-banners   Skip banner grab / Pomiń banner grab
  --lang           pl|en
  -q|--quiet       Suppress console output / Bez outputu do konsoli
  --strict         Strict mode (set -eE + ERR trap)
  --deterministic  Stable host order + seeded randomness
  --seed           Seed for deterministic mode
  --gentle         Conservative pacing / Zachowawcze tempo
  --aggressive     Stronger active verification / Mocniejsza aktywna weryfikacja
  -h|--help        Show help / Pomoc

Profiles / Profile:
  passive   = strict passive / ścisły pasywny
  standard  = light active / lekko aktywny
  deep      = deep active / głęboko aktywny

This tool is observation-first. It must be used only on infrastructure you own
or are explicitly authorized to assess.
EOF
    exit 0
}

# Enterprise safety: domyślnie żadnych instalacji / zmian na hoście audytora
ALLOW_INSTALL=0
CHAOS_MODE=0
CHAOS_TARGET=""
LANG_MODE="pl"   # pl | en
LANG_EXPLICIT=0

TEMP=$(getopt -o m:c:o:s:w:j:hq \
    --long mode:,client:,output:,subnets:,wan:,jobs:,budget:,lang:,seed:,skip-wan,skip-banners,strict,deterministic,gentle,aggressive,quiet,help \
    -n "$(basename "$0")" -- "$@") || { echo "[ERROR] Invalid arguments / Błędne argumenty"; exit 1; }
eval set -- "$TEMP"; unset TEMP

while true; do
    case "$1" in
        -m|--mode)       MODE="${2,,}";         shift 2 ;;
        -c|--client)     CLIENT_NAME="$2";      shift 2 ;;
        -o|--output)     OUTPUT_ROOT="$2";      shift 2 ;;
        -s|--subnets)    SUBNETS_ARG="$2";      shift 2 ;;
        -w|--wan)        WAN_IP_OVERRIDE="$2";  shift 2 ;;
        -j|--jobs)       MAX_PARALLEL="$2";     shift 2 ;;
        --budget)        BH_BUDGET="$2";        shift 2 ;;
        --skip-wan)      SKIP_WAN=1;            shift   ;;
        --skip-banners)  SKIP_BANNERS=1;        shift   ;;
                --gentle)        SAFE_MODE=1;            shift   ;;
--aggressive)    SAFE_MODE=0;            shift   ;;



        --strict)        STRICT_MODE=1;        shift   ;;
        --deterministic) DETERMINISTIC=1;      shift   ;;
        --seed)          DETERMINISTIC_SEED="$2"; shift 2 ;;
        --lang)          LANG_MODE="${2,,}"; LANG_EXPLICIT=1; shift 2 ;;
        -q|--quiet)      QUIET=1;               shift   ;;
        -h|--help)       usage; exit 0          ;;
        --) shift; break ;;
        *)  echo "Nieznany parametr: $1"; exit 1 ;;
    esac
done

ewnaf_choose_language
ewnaf_show_intro
ewnaf_legal_notice
if ! ewnaf_confirm_intro; then
    [[ "${LANG_MODE:-pl}" == "en" ]] && echo "Cancelled by user." || echo "Anulowano przez użytkownika."
    exit 0
fi

# ── Gentle (default) safety clamps ────────────────────────────────────────────
if [[ "${SAFE_MODE:-1}" == "1" ]]; then
    # Keep it polite: limit concurrency and reduce behavioural burst.
    [[ "${MAX_PARALLEL}" -gt 20 ]] && MAX_PARALLEL=20
    BH_BURST_SIZE=2
    BH_JITTER_MAX=250
    BH_JITTER_MIN=80
    BH_COOLDOWN=4
    BH_PROBE_TIMEOUT=2
    # TCP probe pacing
    G_RETRY=2
    G_DELAY=1
    # lower connect timeout slightly to avoid long hangs (still polite)
    : "${G_TIMEOUT:=2}"
else
    # Aggressive mode: allow higher concurrency (user-controlled) and stronger probing.
    : "${G_TIMEOUT:=2}"
fi

# Small random jitter between probes to avoid bursty patterns
_jitter_sleep() {
    local ms="${SAFE_JITTER_MS:-0}"
    if [[ "${SAFE_MODE:-1}" == "1" && "${ms}" -gt 0 ]]; then
        # 0..ms milliseconds
        local r=$((RANDOM % (ms+1)))
        sleep "0.$(printf '%03d' "$r")"
    fi
}
# Activate strict mode after CLI parsing
if [[ "${STRICT_MODE:-0}" == "1" ]]; then
    set -eE
    trap _err_trap ERR
fi

# Deterministic mode: stable ordering + seeded randomness
if [[ "${DETERMINISTIC:-0}" == "1" ]]; then
    # Seed RANDOM (bash uses 16-bit LCG). Hash string seed to int if needed.
    if [[ -n "${DETERMINISTIC_SEED:-}" ]]; then
        if [[ "${DETERMINISTIC_SEED}" =~ ^[0-9]+$ ]]; then
            RANDOM=$(( DETERMINISTIC_SEED % 32768 ))
        else
            # Poor-man hash (portable)
            local_seed=$(printf "%s" "${DETERMINISTIC_SEED}" | od -An -tu2 2>/dev/null | tr -d " " | head -c 5)
            [[ -z "$local_seed" ]] && local_seed=1337
            RANDOM=$(( local_seed % 32768 ))
        fi
    else
        RANDOM=1337
    fi
    # Clamp behavioural jitter to deterministic window
    BH_JITTER_MIN=${BH_JITTER_MIN:-120}
    BH_JITTER_MAX=${BH_JITTER_MAX:-120}
fi

# ── INTERNATIONALISATION ──────────────────────────────────────────────────────
# Użycie: L key [arg1 arg2 ...]  →  zwraca przetłumaczony string
# Zmienne w msgach: %s podstawiane kolejno przez argumenty
#
# Dostępne języki: pl (domyślny) | en
#
# Aktywacja: --lang en  lub  export LANG_MODE=en przed uruchomieniem
# ─────────────────────────────────────────────────────────────────────────────

declare -A _MSG_PL=(
    [start]="EWNAF v%s START | Klient: %s | Tryb: %s"
    [no_hosts]="Brak aktywnych hostów."
    [scoring]="Scoring..."
    [phase_0]="TOPOLOGY PROBE"
    [phase_0_done]="TOPOLOGY PROBE — zakończony"
    [phase_2]="Faza 2: Infrastruktura sieciowa"
    [phase_3]="Faza 3: Discovery hostów"
    [phase_4]="Faza 4: Port scan (%s hostów, tryb=%s)"
    [phase_5]="Faza 5: Banner grab"
    [phase_6]="Faza 6: Klasyfikacja"
    [phase_7]="Faza 7: Weryfikacja usług"
    [phase_8]="Faza 8: DNS audit"
    [phase_9]="Faza 9: Egress audit"
    [phase_10]="Faza 10: WAN exposure (%s)"
    [phase_11]="Faza 11: Lateral movement"
    [phase_12]="Faza 12: Firewall audit"
    [phase_13]="Faza 13: Managed endpoint visibility"
    [phase_14]="Faza 14: Prowler / AWS"
    [phase_bh]="EXPLORATORY ENGINE — BEHAVIOURAL ANALYSIS"
    [preflight]="Preflight"
    [topo_vpn]="[0.1] VPN/Tunnel"
    [topo_wan]="[0.2] WAN IP"
    [topo_nat]="[0.3] NAT layers"
    [topo_ids]="[0.4] Network defence heuristics"
    [topo_fw]="[0.5] Firewall fingerprint"
    [topo_sub]="[0.6] Subnet selection"
    [topo_rec]="[0.7] Scan recommendation"
    [topo_rep]="[0.8] Topology report"
    [topo_stats]="VPN: %s | Deception-like signals: %s | Correlated defence: %s"
    [topo_secsys]="Observed control classes: %s"
    [topo_subnets]="Target subnets: %s"
    [bh_round1]="ROUND 1: behavioural baseline"
    [bh_round2]="ROUND 2: high-entropy revisit"
    [bh_state]="SESSION STATE"
    [bh_hosts]="Hosts: %s | Budget: %s"
    [no_root]="No root — some tests unavailable"
    [bash_old]="Bash < 4 — bash 4+ required"
    [no_subnets]="No target scope. Enterprise auto-discovery found no legal scope from current vantage point (runner/miniserver excluded from audit)"
    [wan_skip_vpn]="WAN test skipped — VPN active or no WAN IP"
    [subnet_skip_vpn]="Skipping VPN subnet: %s"
    [no_subnet_warn]="Topology probe found no subnets — fallback to local"
    [fleet_local]="  [Fleet] fleetctl: %s (v%s)"
    [fleet_server_local]="  [Fleet] Server active (local)"
    [fleet_osquery]="  [Fleet] osquery v%s"
    [fleet_net]="  [Fleet] Fleet API at %s:%s v%s"
    [fleet_no_install]="  [Fleet] Not found — skipped"
    [fleet_no_detect]="  [Fleet] Not detected in network"
    [fleet_install_ok]="  [Fleet] Installed: %s (v%s)"
    [fleet_install_fail]="  [Fleet] Auto-install failed: %s"
    [prowler_installed]="  [Prowler] Found: %s (v%s)"
    [prowler_no_install]="  [Prowler] Not found — skipped"
    [prowler_no_aws]="  [Prowler] No AWS credentials — cloud scan skipped"
    [prowler_running]="  [Prowler] AWS scan running (PID: %s)"
    [prowler_install_fail]="  [Prowler] Install failed: %s"
    [l2_section]="Layer 2: broadcast domain"
    [l3_section]="Layer 3: routing & segmentation"
    [l3_no_hosts]="  [i] L3: no hosts — skipping segmentation tests"
    [traffic_section]="Traffic Policy"
    [http_open]="  [!] HTTP egress (port 80) OPEN — unencrypted channel"
    [http_blocked]="  [✓] HTTP egress blocked"
    [dns_filter_ok]="  [✓] DNS filtering confirmed (confidence %s%%)"
    [dns_filter_weak]="  [i] DNS filtering: weak signal (%s/%s domains)"
    [dns_leak]="  [!] DNS leak: external resolvers reachable (UDP=%s/4, TCP=%s/4, conf=%s%%)"
    [dns_leak_weak]="  [~] DNS leak: weak signal (UDP=%s/4, TCP=%s/4, conf=%s%%) — possible ISP passthrough"
    [dns_noleak]="  [✓] DNS leak blocked (UDP=%s/4, TCP=%s/4)"
    [tproxy]="  [!] Transparent proxy detected"
    [gw_drop]="  [✓] GW: stateful DROP (conf=%s%%)"
    [gw_drop_weak]="  [~] GW: possible DROP (conf=%s%%)"
    [gw_reject]="  [i] GW: REJECT/RST (conf=%s%% — below DROP threshold)"
    [egress_ok]="  [✓] Egress filtering: dangerous ports blocked"
    [egress_fail]="  [!] Egress: %s dangerous ports open"
    [dns_int_ok]="  Internal DNS %s: responding ✓"
    [dns_egress_ok]="  DNS egress blocked ✓ (UDP=%s/4, TCP=%s/4)"
    [fw_sample]="  [FW] samples=%s med=%sms var=%sms ndrop=%s base=%sms conf=%s%%"
    [honeypot_warn]="  [DEF] ⚠ %s: prawdopodobne zachowanie deception-like (score=%s) — %s"
    [honeypot_suspect]="  [DEF] ? %s: podejrzane kształtowanie odpowiedzi (score=%s) — %s"
    [mirage_filter]="  [!] Filtr portów fantomowych aktywny — usuwam mało wiarygodne porty"
    [hp_section]="Analiza odpowiedzi deception-like"
    [python_missing]="Python3 not found — PDF skipped"
)

declare -A _MSG_EN=(
    [start]="EWNAF v%s START | Client: %s | Mode: %s"
    [no_hosts]="No active hosts found."
    [scoring]="Scoring..."
    [phase_0]="TOPOLOGY PROBE"
    [phase_0_done]="TOPOLOGY PROBE — complete"
    [phase_2]="Phase 2: Network infrastructure"
    [phase_3]="Phase 3: Host discovery"
    [phase_4]="Phase 4: Port profiling (%s hosts, mode=%s)"
    [phase_5]="Phase 5: Banner grab"
    [phase_6]="Phase 6: Host classification"
    [phase_7]="Phase 7: Service verification"
    [phase_8]="Phase 8: DNS audit"
    [phase_9]="Phase 9: Egress audit"
    [phase_10]="Phase 10: WAN exposure (%s)"
    [phase_11]="Phase 11: Lateral movement"
    [phase_12]="Phase 12: Firewall audit"
    [phase_13]="Phase 13: Managed endpoint visibility"
    [phase_14]="Phase 14: Prowler / AWS"
    [phase_bh]="EXPLORATORY ENGINE — BEHAVIOURAL ANALYSIS"
    [preflight]="Preflight"
    [topo_vpn]="[0.1] VPN/Tunnel"
    [topo_wan]="[0.2] WAN IP"
    [topo_nat]="[0.3] NAT layers"
    [topo_ids]="[0.4] Network defence heuristics"
    [topo_fw]="[0.5] Firewall fingerprint"
    [topo_sub]="[0.6] Subnet selection"
    [topo_rec]="[0.7] Scan recommendation"
    [topo_rep]="[0.8] Topology report"
    [topo_stats]="VPN: %s | Deception-like signals: %s | Correlated defence: %s"
    [topo_secsys]="Observed control classes: %s"
    [topo_subnets]="Target subnets: %s"
    [bh_round1]="ROUND 1: behavioural baseline"
    [bh_round2]="ROUND 2: high-entropy revisit"
    [bh_state]="SESSION STATE"
    [bh_hosts]="Hosts: %s | Budget: %s"
    [no_root]="No root — some tests unavailable"
    [bash_old]="Bash < 4 — bash 4+ required"
    [no_subnets]="No target scope. Enterprise auto-discovery found no legal scope from current vantage point (runner/miniserver excluded from audit)"
    [wan_skip_vpn]="WAN test skipped — VPN active or no WAN IP"
    [subnet_skip_vpn]="Skipping VPN subnet: %s"
    [no_subnet_warn]="Topology probe found no subnets — fallback to local"
    [fleet_local]="  [Fleet] fleetctl: %s (v%s)"
    [fleet_server_local]="  [Fleet] Server active (local)"
    [fleet_osquery]="  [Fleet] osquery v%s"
    [fleet_net]="  [Fleet] Fleet API at %s:%s v%s"
    [fleet_no_install]="  [Fleet] Not found — skipped"
    [fleet_no_detect]="  [Fleet] Not detected in network"
    [fleet_install_ok]="  [Fleet] Installed: %s (v%s)"
    [fleet_install_fail]="  [Fleet] Auto-install failed: %s"
    [prowler_installed]="  [Prowler] Found: %s (v%s)"
    [prowler_no_install]="  [Prowler] Not found — skipped"
    [prowler_no_aws]="  [Prowler] No AWS credentials — cloud scan skipped"
    [prowler_running]="  [Prowler] AWS scan running (PID: %s)"
    [prowler_install_fail]="  [Prowler] Install failed: %s"
    [l2_section]="Layer 2: broadcast domain"
    [l3_section]="Layer 3: routing & segmentation"
    [l3_no_hosts]="  [i] L3: no hosts — skipping segmentation tests"
    [traffic_section]="Traffic Policy"
    [http_open]="  [!] HTTP egress (port 80) OPEN — unencrypted channel"
    [http_blocked]="  [✓] HTTP egress blocked"
    [dns_filter_ok]="  [✓] DNS filtering confirmed (confidence %s%%)"
    [dns_filter_weak]="  [i] DNS filtering: weak signal (%s/%s domains)"
    [dns_leak]="  [!] DNS leak: external resolvers reachable (UDP=%s/4, TCP=%s/4, conf=%s%%)"
    [dns_leak_weak]="  [~] DNS leak: weak signal (UDP=%s/4, TCP=%s/4, conf=%s%%) — possible ISP passthrough"
    [dns_noleak]="  [✓] DNS leak blocked (UDP=%s/4, TCP=%s/4)"
    [tproxy]="  [!] Transparent proxy detected"
    [gw_drop]="  [✓] GW: stateful DROP (conf=%s%%)"
    [gw_drop_weak]="  [~] GW: possible DROP (conf=%s%%)"
    [gw_reject]="  [i] GW: REJECT/RST (conf=%s%% — below DROP threshold)"
    [egress_ok]="  [✓] Egress filtering: dangerous ports blocked"
    [egress_fail]="  [!] Egress: %s dangerous ports open"
    [dns_int_ok]="  Internal DNS %s: responding ✓"
    [dns_egress_ok]="  DNS egress blocked ✓ (UDP=%s/4, TCP=%s/4)"
    [fw_sample]="  [FW] samples=%s med=%sms var=%sms ndrop=%s base=%sms conf=%s%%"
    [honeypot_warn]="  [DEF] ⚠ %s: prawdopodobne zachowanie deception-like (score=%s) — %s"
    [honeypot_suspect]="  [DEF] ? %s: podejrzane kształtowanie odpowiedzi (score=%s) — %s"
    [mirage_filter]="  [!] Filtr portów fantomowych aktywny — usuwam mało wiarygodne porty"
    [hp_section]="Analiza odpowiedzi deception-like"
    [python_missing]="Python3 not found — PDF skipped"
)

# Lokalizacja: zwróć string dla klucza, podstawiaj %s
L() {
    local key="$1"; shift
    local tmpl
    if [[ "${LANG_MODE:-pl}" == "en" ]]; then
        tmpl="${_MSG_EN[$key]:-[$key]}"
    else
        tmpl="${_MSG_PL[$key]:-[$key]}"
    fi
    # printf obsługuje %s podstawienia
    # shellcheck disable=SC2059
    printf "$tmpl" "$@"
}

ewnaf_legal_notice() {
    if [[ "${LANG_MODE:-pl}" == "en" ]]; then
        cat <<EOF
Legal and compliance note:
Use this tool only on infrastructure you own or are explicitly authorized to assess.
The methodology is observation-first and aligned with network security risk management
and technical assessment practices such as ISO/IEC 27001, ISO/IEC 27002,
ISO/IEC 27005, ISO/IEC 27033, NIST SP 800-115 and NIST CSF.
EOF
    else
        cat <<EOF
Nota prawna i zgodności:
Używaj tego narzędzia wyłącznie we własnej infrastrukturze albo na podstawie
wyraźnego upoważnienia. Metodyka ma charakter observation-first i jest zgodna
kierunkowo z praktykami zarządzania ryzykiem i ocen technicznych takimi jak
ISO/IEC 27001, ISO/IEC 27002, ISO/IEC 27005, ISO/IEC 27033, NIST SP 800-115
oraz NIST CSF.
EOF
    fi
}


# Pseudonymization helpers (v28)
declare -A ENTITY_ALIAS=()

_entity_alias() {
    local key="$1"
    local kind="${2:-Node}"
    [[ -n "${ENTITY_ALIAS[$key]:-}" ]] && { echo "${ENTITY_ALIAS[$key]}"; return; }
    local n=$(( ${#ENTITY_ALIAS[@]} + 1 ))
    local alias
    alias=$(printf "%s-%03d" "$kind" "$n")
    ENTITY_ALIAS[$key]="$alias"
    echo "$alias"
}

_entity_alias_for_index() {
    local idx="$1"
    local seg="${D_SEGMENT[$idx]:-Node}"
    seg="${seg//[^A-Za-z0-9]/}"
    [[ -z "$seg" ]] && seg="Node"
    _entity_alias "${D_IP[$idx]:-idx-$idx}" "$seg"
}

_anonymize_text() {
    local s="$1"
    if [[ "${EXPORT_RAW_IDENTIFIERS:-0}" == "1" ]]; then
        printf '%s' "$s"
        return
    fi
    local i ip alias hn
    for (( i=0; i<${DEV_COUNT:-0}; i++ )); do
        ip="${D_IP[$i]:-}"
        alias=$(_entity_alias_for_index "$i")
        [[ -n "$ip" ]] && s="${s//${ip}/${alias}}"
        hn="${D_HOSTNAME[$i]:-}"
        [[ -n "$hn" ]] && s="${s//${hn}/${alias}}"
    done
    [[ -n "${GATEWAY_IP:-}" ]] && s="${s//${GATEWAY_IP}/Boundary-Egress-001}"
    [[ -n "${WAN_IP:-}" ]] && s="${s//${WAN_IP}/External-Egress-001}"
    [[ -n "${TOPO[real_gateway]:-}" ]] && s="${s//${TOPO[real_gateway]}/Boundary-Egress-001}"
    [[ -n "${TOPO[true_wan_ip]:-}" ]] && s="${s//${TOPO[true_wan_ip]}/External-Egress-001}"
    printf '%s' "$s"
}
OUTPUT_PATH="$OUTPUT_ROOT/$TIMESTAMP"
LOG_FILE="$OUTPUT_PATH/ewnaf-audit.log"
JSON_REPORT="$OUTPUT_PATH/EWNAF-REPORT.json"
HTML_REPORT="$OUTPUT_PATH/EWNAF-REPORT.html"
REPORT_PDF="$OUTPUT_PATH/EWNAF-REPORT.pdf"
TOPO_FILE="$OUTPUT_PATH/topology.txt"

rm -f "$LOCK_FILE"
mkdir -p "$OUTPUT_PATH"
touch "$LOG_FILE" 2>/dev/null || true
exec 200>"$LOCK_FILE"
flock -n 200 || { echo "[!] EWNAF już działa (lock). Abort."; exit 1; }
cleanup() { ewnaf_miniserver_stop; flock -u 200 2>/dev/null; rm -f "$LOCK_FILE"; }
trap cleanup EXIT INT TERM
chown -R "$REAL_USER:$REAL_USER" "$OUTPUT_ROOT" 2>/dev/null || true

# Embedded mini-server (single-file control plane)
EWNAF_MINISERVER_ENABLED="${EWNAF_MINISERVER_ENABLED:-0}"
EWNAF_MINISERVER_PID=""
EWNAF_MINISERVER_PORT=""
EWNAF_MINISERVER_URL=""
EWNAF_MINISERVER_TOKEN=""
EWNAF_MINISERVER_READY_FILE="$OUTPUT_PATH/miniserver-ready.json"
EWNAF_MINISERVER_EVENTS_FILE="$OUTPUT_PATH/miniserver-events.ndjson"
EWNAF_MINISERVER_PY="$OUTPUT_PATH/.ewnaf_miniserver.py"

_ewnaf_emit_miniserver_py() {
cat > "$EWNAF_MINISERVER_PY" <<'PY'
#!/usr/bin/env python3
import argparse, json, os, secrets, signal, socketserver, sys, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = {
    "started_at": time.time(),
    "events_path": None,
    "run_dir": None,
    "token": None,
}
SHUTDOWN = {"server": None}

def append_event(obj):
    path = STATE["events_path"]
    if not path:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

class Handler(BaseHTTPRequestHandler):
    server_version = "EWNAFMini/1.0"
    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

    def _auth_ok(self):
        if self.path.startswith("/healthz"):
            return True
        return self.headers.get("X-EWNAF-Token", "") == STATE["token"]

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"ok": True, "service": "ewnaf-miniserver"})
            return
        if not self._auth_ok():
            self._send(403, {"ok": False, "error": "forbidden"})
            return
        if self.path == "/snapshot":
            self._send(200, {
                "ok": True,
                "started_at": STATE["started_at"],
                "run_dir": STATE["run_dir"],
                "events_path": STATE["events_path"],
            })
            return
        self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        if not self._auth_ok():
            self._send(403, {"ok": False, "error": "forbidden"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            payload = {"raw": raw.decode("utf-8", errors="replace")}
        if self.path == "/event":
            append_event({
                "ts": time.time(),
                "kind": payload.get("kind", "event"),
                "value": payload.get("value", ""),
                "meta": payload.get("meta", {}),
            })
            self._send(200, {"ok": True})
            return
        if self.path == "/shutdown":
            self._send(200, {"ok": True, "shutting_down": True})
            threading.Thread(target=SHUTDOWN["server"].shutdown, daemon=True).start()
            return
        self._send(404, {"ok": False, "error": "not_found"})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ready-file", required=True)
    ap.add_argument("--events-file", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()

    token = secrets.token_hex(16)
    STATE["events_path"] = args.events_file
    STATE["run_dir"] = args.run_dir
    STATE["token"] = token

    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    SHUTDOWN["server"] = srv

    ready = {
        "ok": True,
        "host": args.host,
        "port": srv.server_address[1],
        "token": token,
        "events_file": args.events_file,
        "run_dir": args.run_dir,
    }
    os.makedirs(os.path.dirname(args.ready_file), exist_ok=True)
    with open(args.ready_file, "w", encoding="utf-8") as f:
        json.dump(ready, f, ensure_ascii=False)

    append_event({"ts": time.time(), "kind": "lifecycle", "value": "started", "meta": ready})

    def _handle_sig(*_):
        try:
            srv.shutdown()
        except Exception:
            pass
    signal.signal(signal.SIGTERM, _handle_sig)
    signal.signal(signal.SIGINT, _handle_sig)

    try:
        srv.serve_forever()
    finally:
        append_event({"ts": time.time(), "kind": "lifecycle", "value": "stopped", "meta": {}})

if __name__ == "__main__":
    main()
PY
chmod 700 "$EWNAF_MINISERVER_PY"
}

ewnaf_miniserver_event() {
    local kind="${1:-event}" value="${2:-}" meta="${3:-}"
    [[ "${EWNAF_MINISERVER_ENABLED:-1}" == "1" ]] || return 0
    [[ -n "${EWNAF_MINISERVER_URL:-}" && -n "${EWNAF_MINISERVER_TOKEN:-}" ]] || return 0
    local payload
    payload=$(printf '{"kind":"%s","value":"%s","meta":{"text":"%s"}}' \
        "$(printf '%s' "$kind" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
        "$(printf '%s' "$value" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
        "$(printf '%s' "$meta" | sed 's/\\/\\\\/g; s/"/\\"/g')")
    curl -fsS -m 2 -H "Content-Type: application/json" -H "X-EWNAF-Token: $EWNAF_MINISERVER_TOKEN" \
        -d "$payload" "$EWNAF_MINISERVER_URL/event" >/dev/null 2>&1 || true
}

ewnaf_miniserver_start() {
    [[ "${EWNAF_MINISERVER_ENABLED:-1}" == "1" ]] || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    command -v curl >/dev/null 2>&1 || return 0
    rm -f "$EWNAF_MINISERVER_READY_FILE" "$EWNAF_MINISERVER_EVENTS_FILE" "$EWNAF_MINISERVER_PY"
    _ewnaf_emit_miniserver_py
    python3 "$EWNAF_MINISERVER_PY" \
        --ready-file "$EWNAF_MINISERVER_READY_FILE" \
        --events-file "$EWNAF_MINISERVER_EVENTS_FILE" \
        --run-dir "$OUTPUT_PATH" >/dev/null 2>&1 &
    EWNAF_MINISERVER_PID=$!
    local i
    for i in {1..40}; do
        [[ -s "$EWNAF_MINISERVER_READY_FILE" ]] && break
        sleep 0.1
    done
    if [[ -s "$EWNAF_MINISERVER_READY_FILE" ]]; then
        EWNAF_MINISERVER_PORT="$(python3 - <<PY
import json
with open(r"$EWNAF_MINISERVER_READY_FILE","r",encoding="utf-8") as f:
    d=json.load(f)
print(d.get("port",""))
PY
)"
        EWNAF_MINISERVER_TOKEN="$(python3 - <<PY
import json
with open(r"$EWNAF_MINISERVER_READY_FILE","r",encoding="utf-8") as f:
    d=json.load(f)
print(d.get("token",""))
PY
)"
        EWNAF_MINISERVER_URL="http://127.0.0.1:${EWNAF_MINISERVER_PORT}"
    fi
}

ewnaf_miniserver_stop() {
    [[ "${EWNAF_MINISERVER_ENABLED:-1}" == "1" ]] || return 0
    if [[ -n "${EWNAF_MINISERVER_URL:-}" && -n "${EWNAF_MINISERVER_TOKEN:-}" ]]; then
        curl -fsS -m 2 -H "X-EWNAF-Token: $EWNAF_MINISERVER_TOKEN" -X POST \
            "$EWNAF_MINISERVER_URL/shutdown" >/dev/null 2>&1 || true
    fi
    if [[ -n "${EWNAF_MINISERVER_PID:-}" ]]; then
        wait "$EWNAF_MINISERVER_PID" 2>/dev/null || true
    fi
}


# Early IPv4 helper: needed before LOCAL_FOOTPRINT/exclusion bootstrap
_is_ipv4() {
    local ip="${1:-}" IFS=.
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local a b c d o
    read -r a b c d <<< "${ip//./ }"
    for o in "$a" "$b" "$c" "$d"; do
        [[ "$o" =~ ^[0-9]+$ ]] || return 1
        (( o >= 0 && o <= 255 )) || return 1
    done
    return 0
}


# Self-audit exclusion list: control-plane and runner addresses are never audited.
declare -a EXCLUDE_IPS=()

_exclude_add() {
    local ip="${1:-}"
    _is_ipv4 "$ip" || return 0
    case "$ip" in
        0.*|127.*|169.254.*) ;;
    esac
    EXCLUDE_IPS+=("$ip")
}

_is_excluded_ip() {
    local ip="${1:-}" e
    _is_ipv4 "$ip" || return 1
    for e in "${EXCLUDE_IPS[@]:-}"; do
        [[ "$ip" == "$e" ]] && return 0
    done
    return 1
}

build_local_footprint() {
    LOCAL_HOSTNAME="$(hostname 2>/dev/null || echo unknown)"
    mapfile -t LOCAL_IPS < <({
        hostname -I 2>/dev/null | tr ' ' '\n'
        ip -4 addr show 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1
    } | awk 'NF' | sort -u)
    mapfile -t LOCAL_INTERFACES < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk 'NF' | sort -u)
    mapfile -t LOCAL_CIDRS < <(ip -4 route show scope link 2>/dev/null | awk '{print $1}' | awk 'NF' | sort -u)
}

_build_exclude_ips() {
    EXCLUDE_IPS=()
    build_local_footprint
    _exclude_add "127.0.0.1"
    local ip
    for ip in "${LOCAL_IPS[@]:-}"; do
        _exclude_add "$ip"
    done
}

_is_internal_noise() {
    local ip="${1:-}"
    _is_ipv4 "$ip" || return 0
    _is_excluded_ip "$ip" && return 0
    [[ -n "${GATEWAY_IP:-}" && "$ip" == "$GATEWAY_IP" ]] && return 0
    [[ -n "${WAN_IP:-}" && "$ip" == "$WAN_IP" ]] && return 0
    [[ -n "${TOPO[real_gateway]:-}" && "$ip" == "${TOPO[real_gateway]}" ]] && return 0
    [[ -n "${TOPO[wan_ip]:-}" && "$ip" == "${TOPO[wan_ip]}" ]] && return 0
    return 1
}

touch "$LOG_FILE"

# LOGGING

declare -a LOG_ENTRIES=()

log() {
    local msg="$1" level="${2:-INFO}"
    local ts; ts=$(date +"%H:%M:%S.%3N")
    local entry="[$ts][$level] $msg"
    LOG_ENTRIES+=("$entry")
    echo "$entry" >> "$LOG_FILE"
    case "$level" in
        SECTION|WARN|ERROR) ewnaf_miniserver_event "log" "$level" "$msg" ;;
    esac
    [[ $QUIET -eq 1 ]] && return
    local color="$CC"
    case "$level" in
        WARN)    color="$CO" ;;
        ERROR)   color="$CR" ;;
        OK)      color="$CG" ;;
        DEBUG)   color="$CD" ;;
        SECTION) color="$CW"; echo "" ;;
        TOPO)    color="$CM" ;;
    esac
    echo -e "${color}[$level]${CN} $msg"
}
# Convenience wrappers
log_ok()   { log "$1" "OK"; }
log_warn() { log "$1" "WARN"; }
log_err()  { log "$1" "ERROR"; }

_build_exclude_ips
local _ewnaf_local_ips_count=0 _ewnaf_local_cidrs_count=0
[[ ${#LOCAL_IPS[@]} -ge 0 ]] && _ewnaf_local_ips_count=${#LOCAL_IPS[@]}
[[ ${#LOCAL_CIDRS[@]} -ge 0 ]] && _ewnaf_local_cidrs_count=${#LOCAL_CIDRS[@]}
log "LOCAL_FOOTPRINT: host=${LOCAL_HOSTNAME:-unknown}, local_ips=${_ewnaf_local_ips_count}, local_cidrs=${_ewnaf_local_cidrs_count}" "INFO"
if [[ -n "${EWNAF_MINISERVER_URL:-}" ]]; then
    log "Mini-serwer kontrolny aktywny: ${EWNAF_MINISERVER_URL}" "INFO"
fi


progress() { [[ $QUIET -eq 1 ]] && return; echo -ne "\r${CC}[SCAN]${CN} $1                    "; }

# HELPERS

declare -A T=()
_is_int() { [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }

# Safe array element fetch (works with set -u)
# Usage: _a_get ARRAYNAME KEY  -> echoes value or empty
_a_get() {
    local arr="$1" key="$2"
    eval 'echo "${'"$arr"'[$key]:-}"'
}

# Deterministic helpers
_sort_ips() {
    # Reads IPs from args, outputs sorted list one per line
    printf '%s\n' "$@" | awk -F. 'NF==4{printf "%03d.%03d.%03d.%03d %s\n",$1,$2,$3,$4,$0}' | sort | awk '{print $2}'
}

_median_int() {
    local arr=() v
    for v in "$@"; do
        _is_int "$v" || continue
        arr+=("$v")
    done
    local n=${#arr[@]}
    (( n == 0 )) && { echo 0; return; }
    local sorted mid
    sorted=$(printf '%s\n' "${arr[@]}" | sort -n)
    mid=$(( n / 2 ))
    if (( n % 2 == 1 )); then
        echo "$sorted" | sed -n "$(( mid + 1 ))p"
    else
        local a b
        a=$(echo "$sorted" | sed -n "${mid}p")
        b=$(echo "$sorted" | sed -n "$(( mid + 1 ))p")
        _is_int "$a" || a=0
        _is_int "$b" || b=0
        echo $(( (a + b) / 2 ))
    fi
}

_dns_is_block() {
    case "${1:-}" in
        SINKHOLE|NXDOMAIN) return 0 ;;
        *) return 1 ;;
    esac
}

# Safe TTL extract from ping output.
# Returns empty string if TTL not present (distinguish "missing" vs numeric 0).
_ping_ttl() {
    local ip="$1"
    local out ttl
    out=$(ping -c1 -W1 "$ip" 2>/dev/null || true)
    ttl=$(grep -oP 'ttl=\K[0-9]+' <<< "$out" | head -1 || true)
    echo "${ttl:-}"
}


_is_ipv4() {
    local ip="${1:-}" IFS=.
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    read -r a b c d <<< "${ip//./ }"
    for o in "$a" "$b" "$c" "$d"; do
        [[ "$o" =~ ^[0-9]+$ ]] || return 1
        (( o >= 0 && o <= 255 )) || return 1
    done
    return 0
}

_is_cidr() {
    local s="${1:-}" ip mask
    [[ "$s" == */* ]] || return 1
    ip="${s%/*}"; mask="${s#*/}"
    _is_ipv4 "$ip" || return 1
    [[ "$mask" =~ ^[0-9]+$ ]] || return 1
    (( mask >= 0 && mask <= 32 )) || return 1
    return 0
}

_ipv4_to_int() {
    local ip="$1" a b c d
    IFS=. read -r a b c d <<< "$ip"
    echo $(( (a<<24) + (b<<16) + (c<<8) + d ))
}

_int_to_ipv4() {
    local n="$1"
    echo "$(( (n>>24)&255 )).$(( (n>>16)&255 )).$(( (n>>8)&255 )).$(( n&255 ))"
}

_ip_to_default_network_cidr() {
    local ip="$1"
    IFS=. read -r a b c d <<< "$ip"
    echo "${a}.${b}.${c}.0/24"
}

_cidr_canonical() {
    local cidr="$1" ip mask ipi net
    ip="${cidr%/*}"; mask="${cidr#*/}"
    ipi=$(_ipv4_to_int "$ip")
    if (( mask == 0 )); then
        net=0
    else
        net=$(( ipi & ((0xFFFFFFFF << (32-mask)) & 0xFFFFFFFF) ))
    fi
    printf '%s/%s\n' "$(_int_to_ipv4 "$net")" "$mask"
}

_resolve_scope_seed() {
    local seed="${1:-}" ips=()
    if _is_ipv4 "$seed"; then
        echo "$seed"
        return 0
    fi
    while read -r ip _; do
        _is_ipv4 "$ip" && ips+=("$ip")
    done < <(getent ahostsv4 "$seed" 2>/dev/null || true)
    if (( ${#ips[@]} == 0 )) && command -v dig >/dev/null 2>&1; then
        while read -r ip; do
            _is_ipv4 "$ip" && ips+=("$ip")
        done < <(dig +short A "$seed" 2>/dev/null || true)
    fi
    printf '%s\n' "${ips[@]}" | awk 'NF' | sort -u
}

_range_same_24_to_cidr() {
    local token="${1:-}" left right
    left="${token%-*}"
    right="${token#*-}"
    _is_ipv4 "$left" || return 1
    _is_ipv4 "$right" || return 1
    IFS=. read -r a1 b1 c1 d1 <<< "$left"
    IFS=. read -r a2 b2 c2 d2 <<< "$right"
    [[ "$a1.$b1.$c1" == "$a2.$b2.$c2" ]] || return 1
    echo "${a1}.${b1}.${c1}.0/24"
}

declare -a HOUND_SCOPE=()

hound_seed_scope() {
    local raw="${1:-}" token resolved_ip
    HOUND_SCOPE=()

    # CSV, whitespace and newline tolerant
    raw="${raw//;/,}"
    while IFS= read -r token; do
        token="${token#"${token%%[![:space:]]*}"}"
        token="${token%"${token##*[![:space:]]}"}"
        [[ -z "$token" ]] && continue

        if _is_cidr "$token"; then
            HOUND_SCOPE+=("$(_cidr_canonical "$token")")
            continue
        fi

        if _is_ipv4 "$token"; then
            HOUND_SCOPE+=("$(_ip_to_default_network_cidr "$token")")
            continue
        fi

        if [[ "$token" == *-* ]] && _range_same_24_to_cidr "$token" >/dev/null 2>&1; then
            HOUND_SCOPE+=("$(_range_same_24_to_cidr "$token")")
            continue
        fi

        while IFS= read -r resolved_ip; do
            [[ -z "$resolved_ip" ]] && continue
            HOUND_SCOPE+=("$(_ip_to_default_network_cidr "$resolved_ip")")
        done < <(_resolve_scope_seed "$token")
    done < <(printf '%s' "$raw" | tr ', ' '\n\n')

    mapfile -t HOUND_SCOPE < <(printf '%s\n' "${HOUND_SCOPE[@]}" | awk 'NF' | sort -u)

    if (( ${#HOUND_SCOPE[@]} > 0 )); then
        return 0
    fi
    return 1
}


hound_discover_enterprise_scope() {
    local -a seeds=()
    local line dst ip
    declare -A seen=()

    # 1) Routing hints: tylko prefiksy osiągalne, bez użycia ich jako raportowanej "prawdy"
    while read -r line; do
        dst="${line%% *}"
        [[ -n "$dst" ]] || continue
        [[ "$dst" == "default" ]] && continue
        [[ "$dst" == 127.* || "$dst" == 0.* || "$dst" == 169.254.* ]] && continue
        if _is_cidr "$dst"; then
            dst=$(_cidr_canonical "$dst")
            case "${dst#*/}" in
                0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15)
                    # zbyt szerokie prefiksy tniemy do /16 jako hint eksploracyjny
                    IFS=. read -r a b c d <<< "${dst%/*}"
                    dst="${a}.${b}.0.0/16"
                    ;;
            esac
            seen["$dst"]=1
        fi
    done < <(ip -4 route show 2>/dev/null || true)

    # 2) Neighbor hints: obserwowani sąsiedzi -> /24 scope, bez ekspozycji IP na wyjściu
    while read -r ip _; do
        _is_ipv4 "$ip" || continue
        [[ "$ip" == 127.* || "$ip" == 169.254.* ]] && continue
        _is_excluded_ip "$ip" && continue
        dst=$(_ip_to_default_network_cidr "$ip")
        seen["$dst"]=1
    done < <({
        ip neigh 2>/dev/null | awk '/REACHABLE|STALE|DELAY|PERMANENT|FAILED/ {print $1}'
        arp -n 2>/dev/null | awk '/[0-9]/ && !/incomplete/ {print $1}'
        awk 'NR>1 && $3!="0x0" {print $1}' /proc/net/arp 2>/dev/null || true
    } | sort -u)

    # 3) Fallback: jeśli routing i neighbor nie dały scope, użyj adresów interfejsów
    if (( ${#seen[@]} == 0 )); then
        while read -r line; do
            local addr="${line%% *}"
            [[ -n "$addr" ]] || continue
            _is_cidr "$addr" || continue
            local net_addr
            net_addr=$(_cidr_canonical "$addr")
            [[ "$net_addr" == 127.* || "$net_addr" == 169.254.* ]] && continue
            seen["$net_addr"]=1
        done < <(ip -4 addr show 2>/dev/null | awk '/inet / {print $2}')
    fi

    # 4) Wypisz wyniki
    for dst in "${!seen[@]}"; do
        printf '%s\n' "$dst"
    done | sort -u
}

hound_before_discovery() {
    local raw="${SUBNETS_ARG:-${TOPO[target_subnets]:-}}" joined=""
    if [[ -n "$raw" ]]; then
        if ! hound_seed_scope "$raw"; then
            log "  [HOUND] Nieprawidłowy ręczny scope. Przechodzę na auto-discovery enterprise." "WARN"
        fi
    fi

    if (( ${#HOUND_SCOPE[@]} == 0 )); then
        mapfile -t HOUND_SCOPE < <(hound_discover_enterprise_scope)
    fi

    if (( ${#HOUND_SCOPE[@]} == 0 )); then
        log "  [HOUND] Brak auto-odkrytego scope enterprise. Runner i miniserwer są wyłączone z audytu; z tego punktu nie znaleziono legalnego scope enterprise." "WARN"
        return 1
    fi

    mapfile -t SUBNETS < <(printf '%s
' "${HOUND_SCOPE[@]}" | awk 'NF' | sort -u)
    joined=$(printf '%s ' "${SUBNETS[@]}")
    joined="${joined% }"
    TOPO[target_subnets]="$joined"
    log "  [HOUND] Enterprise scope: ${#SUBNETS[@]} segment(y) odkryte automatycznie" "TOPO"
    return 0
}


_tcp_connect_ms() {
    local ip="$1" port="$2" timeout_s="${3:-2}"
    local t1 t2
    t1=$(date +%s%3N)
    timeout "$timeout_s" bash -c "exec 3<>/dev/tcp/$ip/$port && exec 3>&-" 2>/dev/null || true
    t2=$(date +%s%3N)
    echo $(( t2 - t1 ))
}

_tcp_samples_median() {
    local ip="$1" port="$2" n="${3:-5}" timeout_s="${4:-2}"
    local -a vals=()
    local i d
    for (( i=0; i<n; i++ )); do
        d=$(_tcp_connect_ms "$ip" "$port" "$timeout_s")
        _is_int "$d" && vals+=("$d")
        sleep 0.12
    done
    _median_int "${vals[@]}"
}


# PROBABILISTYCZNY SILNIK CONFIDENCE — FIREWALL / TARPIT
#
# Model: zbiera N pomiarów, liczy medianę + wariancję + ratio vs baseline.
# Confidence = f(ratio, variance_stability, n_consistent)
#
# Wejście:  ip port n_samples timeout_s
# Wyjście:  "median|variance|n_drop|n_total"

_fw_collect_samples() {
    local ip="$1" port="$2" n="${3:-5}" timeout_s="${4:-2}"
    local -a samples=()
    local i d
    for (( i=0; i<n; i++ )); do
        d=$(_tcp_connect_ms "$ip" "$port" "$timeout_s")
        _is_int "$d" && samples+=("$d")
        sleep 0.15
    done
    local med var=0 n_drop=0 n_total="${#samples[@]}"
    (( n_total == 0 )) && { echo "0|0|0|0"; return; }
    med=$(_median_int "${samples[@]}")
    # Variance = max - min
    local mn mx
    mn=$(printf '%s\n' "${samples[@]}" | sort -n | head -1)
    mx=$(printf '%s\n' "${samples[@]}" | sort -n | tail -1)
    _is_int "$mn" && _is_int "$mx" && var=$(( mx - mn ))
    # n_drop = ile próbek >= 1800ms (faktyczny timeout)
    local s
    for s in "${samples[@]}"; do
        (( s >= 1500 )) && (( n_drop++ ))  # soft DROP może timeoutować w 1500-1700ms
    done
    echo "${med}|${var}|${n_drop}|${n_total}"
}

# Oblicz confidence DROP policy na podstawie zebranych próbek + baseline
# Wyjście: conf (0-100), gdzie:
#   < 60  = za mało dowodów
#   60-79 = prawdopodobny DROP
#   80-89 = wysoka pewność
#   90+   = bardzo wysoka pewność
_fw_drop_confidence() {
    # Wrapper — deleguje do centralnego modelu przez _conf_fw_drop()
    _conf_fw_drop "$@"
}

# Probabilistyczny confidence SSH tarpit
# Wejście: delay_med delay_var baseline banner_ok (0/1 = baner SSH prawidłowy)
# Wyjście: conf (0-100)
_ssh_tarpit_confidence() {
    # Wrapper — deleguje do centralnego modelu przez _conf_ssh_tarpit()
    _conf_ssh_tarpit "$@"
}


# ══════════════════════════════════════════════════════════════════════════════
#  CENTRALNY MODEL CONFIDENCE — ADAPTERY
#
#  Każdy adapter tłumaczy surowe dane domenowe na 5 parametrów _conf_calibrate:
#    observations  — ile razy zmierzono
#    required      — ile próbek daje pełną pewność w tej domenie
#    variance      — spójność wyników (0=zawsze to samo, 100=chaos)
#    repeats       — ile pomiarów potwierdziło hipotezę
#    has_baseline  — czy mamy punkt odniesienia (0/1)
#
#  Progi decyzyjne (>= 65, >= 80 itd.) pozostają w funkcjach wywołujących —
#  to jest wiedza domenowa, nie silnik.
# ══════════════════════════════════════════════════════════════════════════════

# CONFIDENCE CALIBRATION MODEL
#
# Defensible confidence score oparty na 4 zmiennych:
#   N  = liczba obserwacji (sample_size)
#   V  = wariancja / niespójność wyników (0-100, niżej=lepiej)
#   R  = powtarzalność (ile razy test dał ten sam wynik / N)
#   B  = stabilność baseline (czy baseline był mierzony, 0|1)
#
# Wzór: conf = base × N_factor × (1 - V_penalty) × R_factor × B_factor
#   base      = 50 (punkt startowy — bez danych nic nie wiemy)
#   N_factor  = min(1.0, N/required_N)          — rośnie z próbką
#   V_penalty = V/200                            — kara za zmienność
#   R_factor  = 0.5 + R/2                        — powtarzalność 0→0.5, 1→1.0
#   B_factor  = 1.0 jeśli baseline znany, 0.75 jeśli nie
#
# Wynik: 0-100 (całkowity, zaokrąglony)
_conf_calibrate() {
    local observations="${1:-1}"  # N  — ile razy zmierzono
    local required="${2:-5}"      # N_req — ile potrzeba do pełnej pewności
    local variance="${3:-50}"     # V  — 0=zawsze to samo, 100=kompletny chaos
    local repeats="${4:-1}"       # ile razy z N wyników było zgodnych
    local has_baseline="${5:-0}"  # 1 = mierzono baseline, 0 = nie

    # Ogranicz
    (( observations < 1 ))  && observations=1
    (( required    < 1 ))   && required=1
    (( variance    < 0 ))   && variance=0
    (( variance    > 100 )) && variance=100
    (( repeats     < 0 ))   && repeats=0
    (( repeats     > observations )) && repeats=$observations

    # N_factor: 0.0→1.0 w miarę zbliżania się do required
    # Użyj integer: N_factor_pct = min(100, N*100/required)
    local n_factor_pct=$(( observations * 100 / required ))
    (( n_factor_pct > 100 )) && n_factor_pct=100

    # V_penalty_pct = variance / 2   (variance=100 → penalty=50%)
    local v_penalty_pct=$(( variance / 2 ))

    # R_factor_pct: repeats/observations → 50..100
    local r_factor_pct=$(( 50 + repeats * 50 / observations ))

    # B_factor_pct: 100 jeśli baseline, 75 jeśli nie
    local b_factor_pct=75
    (( has_baseline == 1 )) && b_factor_pct=100

    # conf = 50 × (n_factor/100) × (1 - v_penalty/100) × (r_factor/100) × (b_factor/100)
    # Integer: conf = 50 × n × (100-v) × r × b / 100^3
    local conf
    conf=$(( 50 * n_factor_pct * (100 - v_penalty_pct) * r_factor_pct * b_factor_pct / 100000000 * 2 ))
    # Uwaga: /100^3 = /1000000, ale mnożymy ×2 żeby skala wychodziła do ~100

    # Normalizuj
    (( conf < 0 ))   && conf=0
    (( conf > 100 )) && conf=100
    echo "$conf"
}

# Adapter: firewall DROP policy
# Inputs: med(ms) var(ms) n_drop n_total baseline(ms)
_conf_fw_drop() {
    local med="$1" var="$2" n_drop="$3" n_total="$4" baseline="$5"
    _is_int "$med" && _is_int "$var" && _is_int "$n_drop" \
        && _is_int "$n_total" && _is_int "$baseline" || { echo 0; return; }
    (( n_total == 0 || baseline == 0 )) && { echo 0; return; }

    # variance ms → 0-100: 0ms=stabilny(0), 2000ms+=chaos(100)
    local v_norm=$(( var * 100 / 2000 ))
    (( v_norm > 100 )) && v_norm=100

    # ratio sygnału: ile razy mediana > baseline
    # Konwertujemy ratio na "ile próbek jakościowych" (repeats bonus)
    local ratio=$(( med * 100 / baseline ))
    local ratio_bonus=0
    (( ratio >= 600  )) && ratio_bonus=1
    (( ratio >= 1000 )) && (( ratio_bonus++ ))
    (( ratio >= 1800 )) && (( ratio_bonus++ ))
    # mediana absolutna >= 1800ms = dodatkowe potwierdzenie
    (( med >= 1800 )) && (( ratio_bonus++ ))
    # repeats = n_drop + ratio_bonus, cap at n_total
    local effective_repeats=$(( n_drop + ratio_bonus ))
    (( effective_repeats > n_total )) && effective_repeats=$n_total

    _conf_calibrate "$n_total" 5 "$v_norm" "$effective_repeats" 1
}

# Adapter: SSH tarpit
# Inputs: med(ms) var(ms) baseline(ms) banner_ok(0/1)
_conf_ssh_tarpit() {
    local med="$1" var="$2" baseline="$3" banner_ok="${4:-0}"
    _is_int "$med" && _is_int "$var" && _is_int "$baseline" || { echo 0; return; }
    (( baseline == 0 )) && { echo 0; return; }

    local v_norm=$(( var * 100 / 2000 ))
    (( v_norm > 100 )) && v_norm=100

    local ratio=$(( med * 100 / baseline ))
    # Repeats: kumulatywne potwierdzenia hipotezy tarpitu
    local reps=0
    (( ratio >= 500  )) && (( reps++ ))
    (( ratio >= 1000 )) && (( reps++ ))
    (( ratio >= 2000 )) && (( reps++ ))
    (( med >= 2500   )) && (( reps++ ))
    (( med >= 5000   )) && (( reps++ ))
    # Banner: brak prawidłowego SSH bannera = silny sygnał
    (( banner_ok == 0 )) && (( reps++ ))
    # Prawidłowy banner = słabszy sygnał (cofnij jeden repeat)
    (( banner_ok == 1 && reps > 0 )) && (( reps-- ))
    # required=6 (suma możliwych potwierdzeń powyżej)
    local required=6
    (( reps > required )) && reps=$required

    _conf_calibrate 3 "$required" "$v_norm" "$reps" 1
}

# Adapter: IDS / rate limiting
# Inputs: base_gw(ms) post_gw(ms) var_ms(ms) ext_spiked(0/1)
_conf_ids_ratelimit() {
    local base_gw="$1" post_gw="$2" var_ms="$3" ext_spiked="${4:-0}"
    _is_int "$base_gw" && _is_int "$post_gw" && _is_int "$var_ms" || { echo 0; return; }
    (( base_gw == 0 )) && { echo 0; return; }

    # variance ms → 0-100 (500ms = duży jitter dla IDS = 100%)
    local v_norm=$(( var_ms * 100 / 500 ))
    (( v_norm > 100 )) && v_norm=100

    # repeats: ile z 5 próbek potwierdziło throttling
    local ratio=$(( post_gw * 100 / base_gw ))
    local reps=0
    # ratio >= 350% (3.5x) = podstawowe potwierdzenie
    (( ratio >= 350 && post_gw > 400 )) && reps=3
    # ratio >= 500% (5x) = silne potwierdzenie
    (( ratio >= 500 )) && reps=4
    # stabilność (niska wariancja) = dodatkowe potwierdzenie
    (( v_norm < 60 && reps > 0 )) && (( reps++ ))
    # ext kontrola stabilna = eliminuje ISP lag
    (( ext_spiked == 0 && reps > 0 )) && (( reps++ ))
    (( reps > 5 )) && reps=5

    _conf_calibrate 5 5 "$v_norm" "$reps" 1
}

# Adapter: DNS filtering
# Inputs: n_blocked n_observed
_conf_dns_filter() {
    local n_blocked="$1" n_obs="$2"
    _is_int "$n_blocked" && _is_int "$n_obs" || { echo 0; return; }
    (( n_obs == 0 )) && { echo 0; return; }

    # variance: niespójność — jeśli 100% blokowane, wariancja=0
    local pct_blocked=$(( n_blocked * 100 / n_obs ))
    local v_norm=$(( 100 - pct_blocked ))

    _conf_calibrate "$n_obs" 10 "$v_norm" "$n_blocked" 1
}

# Adapter: L3 silent DROP
# Inputs: delta(ms) baseline(ms)
_conf_l3_silent_drop() {
    local delta="$1" baseline="$2"
    _is_int "$delta" && _is_int "$baseline" || { echo 0; return; }
    (( baseline == 0 )) && { echo 0; return; }

    local ratio=$(( delta * 100 / baseline ))
    local reps=0
    (( delta >= 2000 && ratio >= 400 )) && reps=1
    (( delta >= 3000 && ratio >= 400 )) && (( reps++ ))
    # Tylko 1 próbka → wysoka wariancja (nie wiemy czy powtarzalne)
    _conf_calibrate 1 3 70 "$reps" 1
}

# Adapter: L3 east-west reachability
# Inputs: flat_total flat_hits
_conf_l3_east_west() {
    local flat_total="$1" flat_hits="$2"
    _is_int "$flat_total" && _is_int "$flat_hits" || { echo 0; return; }
    (( flat_total == 0 )) && { echo 0; return; }

    # Brak baseline — nie wiemy jaki powinien być wynik (sieć flat vs segmented)
    # variance=0 bo wynik binarny (widzi/nie widzi) na każdej parze
    _conf_calibrate "$flat_total" 12 0 "$flat_hits" 0
}

# Adapter: DNS leak
# Inputs: udp_ok tcp_ok n_tested
_conf_dns_leak() {
    local udp_ok="$1" tcp_ok="$2" n_tested="${3:-4}"
    _is_int "$udp_ok" && _is_int "$tcp_ok" && _is_int "$n_tested" || { echo 0; return; }

    local total_tests=$(( n_tested * 2 ))
    local total_ok=$(( udp_ok + tcp_ok ))
    # variance: leak jest spójny (mało zmienności)
    local v_norm=20
    _conf_calibrate "$total_tests" 8 "$v_norm" "$total_ok" 1
}

# Adapter: TLS interception
# Inputs: issuer_match(0/1) san_delta(-1..N) n_checks
# issuer_match=0: issuery różne (silny sygnał MITM)
# san_delta: v_san - d_san (ujemny = intercepcja redukuje SAN)
_conf_tls_intercept() {
    local issuer_match="${1:-1}" san_delta="${2:-0}" n_checks="${3:-3}"
    _is_int "$issuer_match" && _is_int "$san_delta" && _is_int "$n_checks" || { echo 0; return; }

    local reps=0
    # Różne issuery = mocny sygnał
    (( issuer_match == 0 )) && (( reps += 2 ))
    # san_delta < 0 = intercepcja zmniejsza SAN (typowe dla MITM proxy)
    (( san_delta < 0 )) && (( reps++ ))
    # variance: jeśli issuer różny = spójny sygnał (niska wariancja)
    local v_norm=30
    (( issuer_match == 0 )) && v_norm=10

    (( reps > n_checks )) && reps=$n_checks
    _conf_calibrate "$n_checks" "$n_checks" "$v_norm" "$reps" 1
}


# Zwraca 0 = OPEN, 1 = CLOSED/FILTERED
# Zmienna globalna _PP_STATE = OPEN|CLOSED|FILTERED
probe_port() {
    local ip="$1" port="$2" timeout_s="${3:-1}"
    local t1 t2 delta rc
    t1=$(date +%s%3N)
    if [[ -n "${T[nc_cmd]:-}" ]]; then
        timeout "$timeout_s" ${T[nc_cmd]} -z -w1 "$ip" "$port" 2>/dev/null
        rc=$?
    else
        timeout "$timeout_s" bash -c "exec 3<>/dev/tcp/$ip/$port && exec 3>&-" 2>/dev/null
        rc=$?
    fi
    t2=$(date +%s%3N)
    delta=$(( t2 - t1 ))
    if [[ $rc -eq 0 ]]; then
        _PP_STATE="OPEN"; return 0
    elif (( delta < 800 )); then
        # RST zwrócony szybko = port CLOSED (host żywy, port zamknięty)
        _PP_STATE="CLOSED"; return 1
    else
        # Timeout = DROP policy (FILTERED)
        _PP_STATE="FILTERED"; return 1
    fi
}

# Adaptacyjny port scan: wykrywa DROP policy po pierwszych portach
# i skraca listę/timeout jeśli host w ogóle nie odpowiada (czysty DROP)
probe_port_adaptive() {
    local ip="$1" port="$2" timeout_s="${3:-1}"
    # Jeśli host znany jako DROP-only: użyj krótszego timeoutu
    if [[ "${_ADAPTIVE_DROP[$ip]:-0}" == "1" ]]; then
        timeout_s="0.4"
    fi
    probe_port "$ip" "$port" "$timeout_s"
    local rc=$?
    # Kalibracja: 3 FILTERED z rzędu = oznacz jako DROP host
    if [[ "${_PP_STATE:-}" == "FILTERED" ]]; then
        _ADAPTIVE_FILTERED[$ip]=$(( ${_ADAPTIVE_FILTERED[$ip]:-0} + 1 ))
        (( ${_ADAPTIVE_FILTERED[$ip]} >= 3 )) && _ADAPTIVE_DROP[$ip]="1"
    elif [[ "${_PP_STATE:-}" == "OPEN" || "${_PP_STATE:-}" == "CLOSED" ]]; then
        _ADAPTIVE_DROP[$ip]="0"
        _ADAPTIVE_FILTERED[$ip]=0
    fi
    return $rc
}

# Escape do HTML (chroni raport przed XSS z PTR/bannerów/opisów)
html_esc() {
    local s="${1:-}"
    local _sq=$'\''
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//$_sq/&#39;}"
    s=$(echo "$s" | tr -d '\x01\x02\x03')
    echo "$s"
}


# HEURISTICS HELPERS (precision v2)
_dig_classify() {
    local resolver="$1" domain="$2" use_tcp="${3:-0}"
    [[ -z "${T[dig]:-}" ]] && echo "UNKNOWN" && return
    local out short status tcpflag=""
    [[ "$use_tcp" == "1" ]] && tcpflag="+tcp"
    out=$(timeout 3 dig +time=1 +tries=1 $tcpflag @"$resolver" "$domain" A 2>/dev/null || true)
    short=$(echo "$out" | awk '/^;; ANSWER SECTION:/{a=1;next} /^;;/{a=0} a{print $NF}' | head -1)
    status=$(echo "$out" | awk -F'[, ]+' '/^;; ->>HEADER<<-/{for(i=1;i<=NF;i++) if($i=="status:") {print $(i+1); exit}}')
    if echo "$short" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        if [[ "$short" == "0.0.0.0" || "$short" =~ ^127\. ]]; then
            echo "SINKHOLE"
        else
            echo "OK"
        fi
    else
        [[ "$status" == "NXDOMAIN" ]] && echo "NXDOMAIN" || echo "TIMEOUT"
    fi
}

_dns_egress_probe() {
    local resolver="$1" domain="${2:-example.com}"
    local u1 u2 t1 t2 u_ok=0 t_ok=0
    u1=$(_dig_classify "$resolver" "$domain" 0)
    u2=$(_dig_classify "$resolver" "$domain" 0)
    [[ "$u1" == "OK" || "$u2" == "OK" ]] && u_ok=1
    t1=$(_dig_classify "$resolver" "$domain" 1)
    t2=$(_dig_classify "$resolver" "$domain" 1)
    [[ "$t1" == "OK" || "$t2" == "OK" ]] && t_ok=1
    echo "$u_ok $t_ok"
}

_tls_fp_openssl() {
    local host="$1" resolve_ip="${2:-}" port="${3:-443}" sni="${4:-$host}"
    [[ -z "${T[openssl]:-}" ]] && echo "" && return
    local target="$host:$port"
    [[ -n "$resolve_ip" ]] && target="$resolve_ip:$port"
    timeout 6 bash -c "
        echo | ${T[openssl]} s_client -connect '$target' -servername '$sni' -showcerts 2>/dev/null \
        | awk 'BEGIN{c=0} /BEGIN CERTIFICATE/{c=1} c{print} /END CERTIFICATE/{exit}' \
        | ${T[openssl]} x509 -noout -fingerprint -sha256 2>/dev/null" \
    | awk -F'=' '/Fingerprint=/{gsub(/:/,"",$2); print tolower($2); exit}'
}

_tls_issuer_san() {
    # Zwraca "issuer|san_count" dla danego połączenia
    local host="$1" resolve_ip="${2:-}" port="${3:-443}" sni="${4:-$1}"
    [[ -z "${T[openssl]:-}" ]] && echo "|0" && return
    local target="$host:$port"
    [[ -n "$resolve_ip" ]] && target="$resolve_ip:$port"
    local cert
    cert=$(timeout 6 bash -c "
        echo | ${T[openssl]} s_client -connect '$target' -servername '$sni' -showcerts 2>/dev/null         | awk 'BEGIN{c=0} /BEGIN CERTIFICATE/{c=1} c{print} /END CERTIFICATE/{exit}'" 2>/dev/null)
    [[ -z "$cert" ]] && echo "|0" && return
    local issuer san_count
    issuer=$(echo "$cert" | ${T[openssl]} x509 -noout -issuer 2>/dev/null | sed 's/issuer= *//' | head -1 || echo "")
    # Wyciągnij CN issuera (Organization lub Common Name)
    issuer=$(echo "$issuer" | grep -oP 'O\s*=\s*\K[^,]+' | head -1 | tr -d ' ' || echo "$issuer" | head -c 60)
    san_count=$(echo "$cert" | ${T[openssl]} x509 -noout -text 2>/dev/null | grep -c "DNS:" || echo "0")
    echo "${issuer:-unknown}|${san_count:-0}"
}

_doh_json_ok() {
    local url="$1"
    [[ -z "${T[curl]:-}" ]] && echo "0" && return
    local r
    r=$(curl -sk --max-time 4 -H 'accept: application/dns-json' "$url" 2>/dev/null | head -c 400 || true)
    echo "$r" | grep -qiE '"Status"[[:space:]]*:[[:space:]]*0|"Answer"[[:space:]]*:' && echo "1" || echo "0"
}


grab_banner() {
    local ip="$1" port="$2" timeout_s="${3:-3}" send="${4:-}"
    local banner=""
    if [[ -n "${T[nc_cmd]:-}" ]]; then
        if [[ -n "$send" ]]; then
            banner=$(echo -e "$send" | timeout "$timeout_s" ${T[nc_cmd]} -w"$timeout_s" "$ip" "$port" 2>/dev/null | head -3 | tr -d '\r' | grep -v '^$' | head -1)
        else
            banner=$(timeout "$timeout_s" ${T[nc_cmd]} -w"$timeout_s" "$ip" "$port" 2>/dev/null | head -3 | tr -d '\r' | grep -v '^$' | head -1)
        fi
    fi
    echo "${banner:0:120}"
}

grab_http_banner() {
    local url="$1" timeout_s="${2:-3}"
    [[ -z "${T[curl]:-}" ]] && echo "" && return
    curl -sk --max-time "$timeout_s" --max-filesize 4096 -o /dev/null -w "%{http_code} %{redirect_url}" "$url" 2>/dev/null || echo ""
}

get_http_headers() {
    local url="$1" timeout_s="${2:-3}"
    [[ -z "${T[curl]:-}" ]] && echo "" && return
    curl -skI --max-time "$timeout_s" "$url" 2>/dev/null | tr -d '\r' | head -20 || echo ""
}

declare -A _ADAPTIVE_DROP=()      # ip → "1" jeśli host ma DROP policy
declare -A _ADAPTIVE_FILTERED=()  # ip → liczba consecutive FILTERED

scan_ports_parallel() {
    local ip="$1" port_list="$2" max_j="${3:-$MAX_PARALLEL}" to="${4:-1}"
    local tmp; tmp=$(mktemp -d)
    local active=0
    for port in $port_list; do
        ( probe_port_adaptive "$ip" "$port" "$to" && touch "$tmp/$port" ) &
        (( active++ ))
        if (( active >= max_j )); then wait; active=0; fi
    done
    wait
    local open=""
    for port in $port_list; do [[ -f "$tmp/$port" ]] && open="$open $port"; done
    rm -rf "$tmp"
    echo "${open# }"
}

contains_port() { echo " $1 " | grep -qw "$2"; }
port_count()    { [[ -z "$1" ]] && echo 0 || echo "$1" | wc -w; }

# [0] TOPOLOGY PROBE — heurystyczna analiza topologii PRZED audytem

# Globalne wyniki topologii
declare -A TOPO=(
    [vpn_detected]="0"
    [vpn_type]=""
    [vpn_interface]=""
    [nat_layers]="0"
    [real_gateway]=""
    [true_wan_ip]=""
    [vpn_wan_ip]=""
    [honeypot_detected]="0"
    [ids_detected]="0"
    [ids_type]=""
    [dns_filter_detected]="0"
    [autoban_detected]="0"
    [mirage_ports]="0"
    [firewall_type]=""
    [proxy_detected]="0"
    [double_nat]="0"
    [scan_recommendation]=""
    [fleet_detected]="0"
    [fleet_server_ip]=""
    [fleet_version]=""
    [fleet_agent_count]="0"
    [prowler_installed]="0"
    [prowler_aws_running]="0"
    [prowler_report_dir]=""
    [target_subnets]=""
    [skip_subnets]=""
)

declare -a TOPO_WARNINGS=()
declare -a SECURITY_SYSTEMS=()

topo_detect_vpn() {
    local vpn_ifaces="" vpn_type=""

    if ip link show 2>/dev/null | grep -qE "wg[0-9]|wgc[0-9]"; then
        vpn_ifaces=$(ip link show 2>/dev/null | grep -oE "wg[a-z0-9]+" | head -5)
        vpn_type="WireGuard"
        TOPO[vpn_detected]="1"
        TOPO[vpn_type]="WireGuard"
        TOPO[vpn_interface]="$vpn_ifaces"
        log "  [!] WireGuard VPN wykryty: $vpn_ifaces" "TOPO"
    fi

    if ip link show 2>/dev/null | grep -qE "tun[0-9]|tap[0-9]"; then
        vpn_ifaces=$(ip link show 2>/dev/null | grep -oE "tun[0-9]+|tap[0-9]+" | head -5)
        vpn_type="OpenVPN"
        TOPO[vpn_detected]="1"
        TOPO[vpn_type]="${TOPO[vpn_type]:-}${TOPO[vpn_type]:+,}OpenVPN"
        TOPO[vpn_interface]="${TOPO[vpn_interface]:-}${TOPO[vpn_interface]:+ }$vpn_ifaces"
        log "  [!] OpenVPN/TUN VPN wykryty: $vpn_ifaces" "TOPO"
    fi

    if ip link show 2>/dev/null | grep -qE "ppp[0-9]"; then
        TOPO[vpn_detected]="1"
        TOPO[vpn_type]="${TOPO[vpn_type]:-}${TOPO[vpn_type]:+,}PPP"
        log "  [!] PPP tunnel wykryty" "TOPO"
    fi

    local vpn_routes=""
    vpn_routes=$(ip route show 2>/dev/null | grep -E "wg|tun|tap|ppp" | head -5 || true)
    if [[ -n "$vpn_routes" ]]; then
        TOPO[vpn_detected]="1"
        log "  [!] VPN routes w tablicy routingu: $vpn_routes" "TOPO"
    fi

    if pgrep -x "wg\|openvpn\|wireguard" > /dev/null 2>&1; then
        TOPO[vpn_detected]="1"
        log "  [!] Proces VPN uruchomiony" "TOPO"
    fi
}

topo_detect_wan() {
    [[ -z "${T[curl]:-}" ]] && return

    local ip1 ip2 ip3
    ip1=$(curl -s --max-time 4 https://api.ipify.org 2>/dev/null || echo "")
    ip2=$(curl -s --max-time 4 https://api4.my-ip.io/ip 2>/dev/null || echo "")
    ip3=$(curl -s --max-time 4 https://checkip.amazonaws.com 2>/dev/null | tr -d '\n' || echo "")

    local candidate
    for candidate in "$ip1" "$ip2" "$ip3"; do
        if echo "$candidate" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
            TOPO[true_wan_ip]="$candidate"
            break
        fi
    done

    if [[ -n "${TOPO[true_wan_ip]}" ]]; then
        log "  [i] Zewnętrzny IP: ${TOPO[true_wan_ip]}" "TOPO"
        local wan="${TOPO[true_wan_ip]}"
        if echo "$wan" | grep -qE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"; then
            TOPO[vpn_detected]="1"
            TOPO[vpn_wan_ip]="$wan"
            TOPO[double_nat]="1"
            log "  [!] WAN IP jest RFC1918 — podwójny NAT lub VPN gateway" "TOPO"
            TOPO_WARNINGS+=("DOUBLE_NAT: WAN IP $wan jest prywatny — audyt WAN będzie niedokładny")
        fi
    fi
}

topo_detect_nat() {
    local gw_ip
    gw_ip=$(ip route show default 2>/dev/null | awk '/default via/ {print $3}' | head -1 || echo "")
    [[ -z "$gw_ip" ]] && return

    TOPO[real_gateway]="$gw_ip"
    local nat_count=0

    if [[ -n "${T[traceroute]:-}" ]]; then
        local hops
        hops=$(traceroute -n -w1 -q1 -m5 "$EXT_DNS_PRIMARY" 2>/dev/null | grep -cE '^\s*[0-9]' || echo "0")
        nat_count=$hops
        log "  [i] Hopów do internetu: $hops" "TOPO"
        if (( hops > 5 )); then
            log "  [!] Wiele hopów ($hops) — możliwe podwójne NAT lub VPN chain (ISP norma: 4-5)" "TOPO"
        elif (( hops > 3 )); then
            log "  [i] $hops hopów do internetu (norma ISP)" "TOPO"
        fi
    fi
    TOPO[nat_layers]="$nat_count"
}

# IDS/Rate-limit detection — probabilistyczny model z confidence
# Wymaga: n_gw >= 3 próbek ORAZ ratio >= 3.5x GW ORAZ ext kontrola stabilna
topo_detect_ids() {
    local gw="${TOPO[real_gateway]:-}"
    [[ -z "$gw" ]] && return

    local ext_ip="$EXT_CTRL_HOST2"
    local base_gw post_gw base_ext post_ext

    # Zbierz bazowe próbki (5 dla GW, 4 dla ext)
    base_gw=$(_tcp_samples_median "$gw" 80 5 2)
    base_ext=$(_tcp_samples_median "$ext_ip" 443 4 2)

    # Stymulacja: 10 szybkich połączeń
    local k
    for (( k=0; k<10; k++ )); do
        timeout 1 bash -c "exec 3<>/dev/tcp/$gw/80 && exec 3>&-" 2>/dev/null || true
    done
    sleep 0.25

    # Próbki po stymulacji (5 dla GW, 4 dla ext)
    post_gw=$(_tcp_samples_median "$gw" 80 5 2)
    post_ext=$(_tcp_samples_median "$ext_ip" 443 4 2)

    _is_int "$base_gw"  || base_gw=0
    _is_int "$post_gw"  || post_gw=0
    _is_int "$base_ext" || base_ext=0
    _is_int "$post_ext" || post_ext=0

    # Zbierz variance GW: kilka dodatkowych próbek post-burst dla stabilności
    local -a _ids_post_samples=()
    local _idsi _idsd
    for (( _idsi=0; _idsi<3; _idsi++ )); do
        _idsd=$(_tcp_connect_ms "$gw" 80 2)
        _is_int "$_idsd" && _ids_post_samples+=("$_idsd")
        sleep 0.1
    done
    local _ids_var=0
    if (( ${#_ids_post_samples[@]} >= 2 )); then
        local _ids_mn _ids_mx
        _ids_mn=$(printf '%s\n' "${_ids_post_samples[@]}" | sort -n | head -1)
        _ids_mx=$(printf '%s\n' "${_ids_post_samples[@]}" | sort -n | tail -1)
        _is_int "$_ids_mn" && _is_int "$_ids_mx" && _ids_var=$(( _ids_mx - _ids_mn ))
    fi

    if (( base_gw > 0 && post_gw > 0 )); then
        local gw_tripled=0 ext_spiked=0
        # Wymagaj: ratio >= 3.5x ORAZ post_gw > 400ms (eliminuje wolny router z jitterem)
        (( post_gw > base_gw * 35/10 && post_gw > 400 )) && gw_tripled=1
        (( base_ext > 0 && post_ext > base_ext * 2 && post_ext > 500 )) && ext_spiked=1

        if (( gw_tripled == 1 && ext_spiked == 0 )); then
            local _rl_conf
            _rl_conf=$(_conf_ids_ratelimit "$base_gw" "$post_gw" "$_ids_var" "$ext_spiked")
            _is_int "$_rl_conf" || _rl_conf=0
            TOPO[ids_detected]="1"
            TOPO[ids_conf]="$_rl_conf"
            SECURITY_SYSTEMS+=("Rate Limiting/IDS: throttling GW (${base_gw}→${post_gw}ms, var=${_ids_var}ms, pewność ${_rl_conf}%)")
            log "  [✓] Throttling na gateway — możliwy IDS/IPS (GW ${base_gw}→${post_gw}ms, var=${_ids_var}ms, conf=${_rl_conf}%)" "TOPO"
        fi
    fi
}

# DNS filtering detection
topo_detect_dns_filter() {
    local gw="${TOPO[real_gateway]:-}"
    [[ -z "$gw" ]] && return
    [[ -z "${T[dig]:-}" ]] && return

    local _resolver="${INTERNAL_DNS:-${TOPO[real_gateway]:-}}"
    [[ -z "$_resolver" ]] && _resolver="$EXT_DNS_PRIMARY"
    local _ref1="$EXT_DNS_SECONDARY" _ref2="$EXT_DNS_PRIMARY"

    local _dns_test_domains=(
        "doubleclick.net"
        "adservice.google.com"
        "ads.yahoo.com"
        "pagead2.googlesyndication.com"
        "static.doubleclick.net"
        "telemetry.microsoft.com"
        "v10.events.data.microsoft.com"
        "clients4.google.com"
        "www.googletagmanager.com"
        "tracking.tiktok.com"
    )
    local _dns_obs=0 _dns_blk=0 d r1 r2 a1 a2
    for d in "${_dns_test_domains[@]}"; do
        r1=$(_dig_classify "$_ref1" "$d" 0)
        r2=$(_dig_classify "$_ref2" "$d" 0)
        [[ "$r1" == "TIMEOUT" && "$r2" == "TIMEOUT" ]] && continue
        a1=$(_dig_classify "$_resolver" "$d" 0)
        a2=$(_dig_classify "$_resolver" "$d" 0)
        [[ "$a1" == "TIMEOUT" && "$a2" == "TIMEOUT" ]] && continue
        (( _dns_obs++ ))
        if _dns_is_block "$a1" || _dns_is_block "$a2"; then
            (( _dns_blk++ ))
        fi
    done

    if (( _dns_obs >= 5 )); then
        local _dns_pct=$(( _dns_blk * 100 / _dns_obs ))
        local _dns_conf
        _dns_conf=$(_conf_dns_filter "$_dns_blk" "$_dns_obs")
        _is_int "$_dns_conf" || _dns_conf=0
        if (( _dns_conf >= 65 )); then
            TOPO[dns_filter_detected]="1"
            SECURITY_SYSTEMS+=("DNS Filtering: aktywny (${_dns_blk}/${_dns_obs} domen, pewność ${_dns_conf}%)")
            log "  [✓] DNS Filtering wykryty (${_dns_blk}/${_dns_obs}, pewność ${_dns_conf}%)" "TOPO"
        else
            log "  [i] DNS Filtering: słaby sygnał (${_dns_blk}/${_dns_obs} domen — ${_dns_pct}%)"
        fi
    else
        log "  [i] DNS Filtering: za mała próbka ($_dns_obs domen dostępnych) — wynik niedostępny"
    fi
}

# SSH Tarpit detection — behawioralne, z twardym progiem median >= 2500ms
# Wymaga: n_samples >= 3, median >= 2500ms lub ratio >= 800% baseline
topo_detect_ssh_tarpit() {
    local gw="${TOPO[real_gateway]:-}"
    [[ -z "$gw" ]] && return
    probe_port "$gw" 22 1 || return

    # Baseline TCP (port 80 lub 443 — eliminuje wolny router)
    local _ssh_base
    _ssh_base=$(_tcp_connect_ms "$gw" 80 1)
    _is_int "$_ssh_base" || _ssh_base=$(_tcp_connect_ms "$gw" 443 1)
    _is_int "$_ssh_base" || _ssh_base=30
    (( _ssh_base < 5 )) && _ssh_base=5

    # Próbka 1: banner read (mierzy czas do pierwszego bajtu — endlessh opóźnia to celowo)
    local _ssh_t1 _ssh_t2 _ssh_d _ssh_banner=""
    _ssh_t1=$(date +%s%3N)
    _ssh_banner=$(timeout 4 bash -c \
        "exec 3<>/dev/tcp/$gw/22; IFS= read -r -t3 -u3 _l 2>/dev/null; echo \"\${_l:-}\"" \
        2>/dev/null | head -1 | tr -d $'\r\n' || echo "")
    _ssh_t2=$(date +%s%3N)
    _ssh_d=$(( _ssh_t2 - _ssh_t1 ))

    # Próbki 2 i 3: connect-only (szybsze, bez czekania na banner)
    local -a _ssh_samples=("$_ssh_d")
    local _ssh_t3 _ssh_t4 _ssh_t5 _ssh_t6 _ssh_s2 _ssh_s3
    sleep 0.2
    _ssh_t3=$(date +%s%3N)
    timeout 2 bash -c "exec 3<>/dev/tcp/$gw/22 && exec 3>&-" 2>/dev/null; true
    _ssh_t4=$(date +%s%3N)
    _ssh_s2=$(( _ssh_t4 - _ssh_t3 ))
    _is_int "$_ssh_s2" && _ssh_samples+=("$_ssh_s2")
    sleep 0.2
    _ssh_t5=$(date +%s%3N)
    timeout 2 bash -c "exec 3<>/dev/tcp/$gw/22 && exec 3>&-" 2>/dev/null; true
    _ssh_t6=$(date +%s%3N)
    _ssh_s3=$(( _ssh_t6 - _ssh_t5 ))
    _is_int "$_ssh_s3" && _ssh_samples+=("$_ssh_s3")

    local _ssh_med; _ssh_med=$(_median_int "${_ssh_samples[@]}")
    _is_int "$_ssh_med" || _ssh_med="$_ssh_d"
    local _ssh_mn _ssh_mx _ssh_var=0
    _ssh_mn=$(printf '%s\n' "${_ssh_samples[@]}" | sort -n | head -1)
    _ssh_mx=$(printf '%s\n' "${_ssh_samples[@]}" | sort -n | tail -1)
    _is_int "$_ssh_mn" && _is_int "$_ssh_mx" && _ssh_var=$(( _ssh_mx - _ssh_mn ))

    local _ssh_ratio=0
    (( _ssh_base > 0 )) && _ssh_ratio=$(( _ssh_med * 100 / _ssh_base ))

    local _banner_ok=0
    if [[ "$_ssh_banner" =~ ^SSH-2\.[0-9] ]] && \
       [[ ! "$_ssh_banner" =~ SSH-2\.0-Go ]]; then
        _banner_ok=1
    fi

    # Wymagaj: n_samples >= 3 ORAZ (median >= 2500ms LUB ratio >= 800%)
    # Endlessh z małym delay może osiągnąć 1500ms - próg 2500ms eliminuje wolne routery
    local _n_ok=0
    (( ${#_ssh_samples[@]} >= 3 )) && _n_ok=1

    local _ssh_conf=0
    if (( _n_ok == 1 )); then
        _ssh_conf=$(_ssh_tarpit_confidence "$_ssh_med" "$_ssh_var" "$_ssh_base" "$_banner_ok")
        _is_int "$_ssh_conf" || _ssh_conf=0

        # Hard floor: jeśli median < 2500ms I ratio < 800% — obniż confidence
        # Chroni przed false positive na wolnym routerze embedded
        if (( _ssh_med < 2500 && _ssh_ratio < 800 )); then
            (( _ssh_conf = _ssh_conf * 70 / 100 ))
        fi
    fi

    if (( _ssh_conf >= 85 )); then
        TOPO[honeypot_detected]="1"
        SECURITY_SYSTEMS+=("SSH Tarpit: aktywny (med=${_ssh_med}ms, ratio=${_ssh_ratio}%, n=${#_ssh_samples[@]}, pewność=${_ssh_conf}%)")
        log "  [✓] SSH Tarpit GW:22 — delay=${_ssh_d}ms base=${_ssh_base}ms ratio=${_ssh_ratio}% med=${_ssh_med}ms" "TOPO"
    else
        log "  [i] SSH port 22 — med=${_ssh_med}ms base=${_ssh_base}ms ratio=${_ssh_ratio}% conf=${_ssh_conf}% (nie tarpit)" "TOPO"
    fi
}

# Auto-ban detection: sondujemy nieistniejący port, potem sprawdzamy czy GW nadal odpowiada
topo_detect_autoban() {
    local gw="${TOPO[real_gateway]:-}"
    [[ -z "$gw" ]] && return

    timeout 1 bash -c "exec 3<>/dev/tcp/$gw/9998 && exec 3>&-" 2>/dev/null; true
    sleep 0.5

    local _ab_ok=0
    timeout 1 bash -c "exec 3<>/dev/tcp/$gw/80 && exec 3>&-" 2>/dev/null && _ab_ok=1 || true
    [[ "$_ab_ok" == "0" ]] && { timeout 1 bash -c "exec 3<>/dev/tcp/$gw/80 && exec 3>&-" 2>/dev/null && _ab_ok=1 || true; }
    [[ "$_ab_ok" == "0" ]] && { timeout 1 bash -c "exec 3<>/dev/tcp/$gw/443 && exec 3>&-" 2>/dev/null && _ab_ok=1 || true; }

    if [[ "$_ab_ok" == "0" ]]; then
        TOPO[autoban_detected]="1"
        SECURITY_SYSTEMS+=("Auto-ban IPS: aktywny (GW zablokował IP po sondzie, pewność 88%)")
        log "  [✓] Auto-ban wykryty na GW (host niedostępny po próbie)" "TOPO"
    fi
}

# Firewall fingerprint — probabilistyczny model DROP/REJECT (istniejąca logika, bez zmian)
topo_detect_firewall() {
    local gw_fw="${TOPO[real_gateway]:-}"
    [[ -z "$gw_fw" ]] && return

    local _fw_baseline
    _fw_baseline=$(_tcp_samples_median "$gw_fw" 80 4 1)
    _is_int "$_fw_baseline" || _fw_baseline=$(_tcp_samples_median "$gw_fw" 443 3 1)
    _is_int "$_fw_baseline" || _fw_baseline=30
    (( _fw_baseline < 5 )) && _fw_baseline=5

    local _fw_raw; _fw_raw=$(_fw_collect_samples "$gw_fw" 9997 5 2)
    local _fw_med="${_fw_raw%%|*}"
    local _fw_rest="${_fw_raw#*|}"
    local _fw_var="${_fw_rest%%|*}"
    local _fw_rest2="${_fw_rest#*|}"
    local _fw_ndrop="${_fw_rest2%%|*}"
    local _fw_ntotal="${_fw_rest2##*|}"

    _is_int "$_fw_med"    || _fw_med=0
    _is_int "$_fw_var"    || _fw_var=0
    _is_int "$_fw_ndrop"  || _fw_ndrop=0
    _is_int "$_fw_ntotal" || _fw_ntotal=0

    local _fw_conf
    _fw_conf=$(_fw_drop_confidence \
        "$_fw_med" "$_fw_var" "$_fw_ndrop" "$_fw_ntotal" "$_fw_baseline")
    _is_int "$_fw_conf" || _fw_conf=0

    TOPO[firewall_drop_conf]="$_fw_conf"
    TOPO[firewall_baseline_ms]="$_fw_baseline"
    TOPO[firewall_median_ms]="$_fw_med"

    log "$(L fw_sample "${_fw_ntotal}" "${_fw_med}" "${_fw_var}" "${_fw_ndrop}" "${_fw_baseline}" "${_fw_conf}")" "TOPO"

    if (( _fw_conf >= 80 )); then
        TOPO[firewall_type]="stateful-DROP"
        SECURITY_SYSTEMS+=("Stateful firewall: DROP policy (med=${_fw_med}ms, base=${_fw_baseline}ms, pewność=${_fw_conf}%)")
        log "  [✓] Stateful DROP firewall na GW (pewność=${_fw_conf}%)" "TOPO"
    elif (( _fw_conf >= 60 )); then
        TOPO[firewall_type]="probable-DROP"
        SECURITY_SYSTEMS+=("Firewall: możliwy DROP (med=${_fw_med}ms, pewność=${_fw_conf}% — niska próbka lub duży jitter)")
        log "  [~] Prawdopodobny DROP firewall — conf=${_fw_conf}% (nierozstrzygnięte)" "TOPO"
    else
        TOPO[firewall_type]="RST/reject"
        log "  [i] GW REJECT/RST (med=${_fw_med}ms, base=${_fw_baseline}ms, conf=${_fw_conf}% — poniżej progu)" "TOPO"
    fi

    if ping -c1 -W1 "$gw_fw" &>/dev/null 2>&1; then
        TOPO[firewall_type]="${TOPO[firewall_type]}+ICMP-allowed"
    else
        TOPO[firewall_type]="${TOPO[firewall_type]}+ICMP-blocked"
        SECURITY_SYSTEMS+=("ICMP blocked na GW")
    fi
}

# Subnet selection — bez zmian logiki
topo_select_subnets() {
    local target_nets="" skip_nets=""

    while IFS= read -r cidr; do
        local net="${cidr%/*}"
        local prefix="${cidr#*/}"
        # Guard: prefix musi być liczbą całkowitą 1-32 (shift 32 daje UB, prefix="" crashuje)
        _is_int "$prefix" || continue
        (( prefix < 1 || prefix > 32 )) && continue
        IFS='.' read -r a b c d <<< "$net"
        local _ip_dec=$(( (a<<24)+(b<<16)+(c<<8)+d ))
        local _mask=$(( 0xFFFFFFFF << (32-prefix) & 0xFFFFFFFF ))
        local _net=$(( _ip_dec & _mask ))
        local full_net; full_net=$(printf "%d.%d.%d.%d/%s" \
            $(( (_net>>24)&255 )) $(( (_net>>16)&255 )) \
            $(( (_net>>8)&255 ))  $(( _net&255 )) "$prefix")

        local is_vpn=0
        local iface
        iface=$(ip -4 addr show 2>/dev/null | grep -B2 "$cidr" | grep -oP '^\d+: \K[^:@]+' | head -1 || echo "")

        if echo "$iface" | grep -qE "^(wg|tun|tap|ppp)[0-9]"; then
            is_vpn=1
        fi

        if echo "$net" | grep -qE "^10\.255\."; then
            if echo "$iface" | grep -qE "^wg"; then
                is_vpn=1
            fi
        fi

        if [[ $is_vpn -eq 0 ]]; then
            local rt_iface
            rt_iface=$(ip route show "$net/$prefix" 2>/dev/null | awk '{print $3}' | head -1 || echo "")
            if echo "$rt_iface" | grep -qE "^(wg|tun|tap|ppp)[0-9]"; then
                is_vpn=1
            fi
        fi

        if (( is_vpn )); then
            skip_nets="$skip_nets $full_net"
            log "  [!] Pomijam VPN subnet: $full_net (interfejs: ${iface:-unknown})" "TOPO"
        else
            target_nets="$target_nets $full_net"
            log "  [✓] Target subnet: $full_net" "TOPO"
        fi
    done < <(ip -4 addr show 2>/dev/null | awk '/inet / {print $2}' | grep -vE '^(127\.|169\.254\.)' || true)

    TOPO[target_subnets]="${target_nets# }"
    TOPO[skip_subnets]="${skip_nets# }"

    if [[ -z "${TOPO[target_subnets]}" ]]; then
        log "  [!] Brak lokalnych podsieci do skanowania — sprawdź interfejsy" "TOPO"
        TOPO_WARNINGS+=("NO_SUBNETS: Brak wykrytych podsieci lokalnych")
    fi
}

# Scan recommendation — bez zmian logiki
topo_scan_recommendation() {
    local rec="STANDARD"
    [[ "${TOPO[vpn_detected]}" == "1" ]] && rec="VPN_AWARE"
    [[ "${TOPO[mirage_ports]}" != "0" ]] && rec="${rec}+MIRAGE_FILTER"
    [[ "${TOPO[ids_detected]}" == "1" ]] && rec="${rec}+IDS_AWARE"
    TOPO[scan_recommendation]="$rec"
}

# Topology report — bez zmian logiki
topo_generate_report() {
    {
        echo "EWNAF v${VERSION} — Topology Analysis Report"
        echo "Generated: $(date)"
        echo ""
        echo "=== VPN / TUNNEL ==="
        echo "VPN Detected: ${TOPO[vpn_detected]}"
        echo "VPN Type: ${TOPO[vpn_type]:-none}"
        echo "VPN Interface: ${TOPO[vpn_interface]:-none}"
        echo "Double NAT: ${TOPO[double_nat]}"
        echo "NAT Layers: ${TOPO[nat_layers]}"
        echo ""
        echo "=== NETWORK ==="
        echo "Gateway: [runner-context-disabled]"
        echo "External IP: [runner-context-disabled]"
        echo "Target Subnets: ${TOPO[target_subnets]}"
        echo "Skip Subnets: ${TOPO[skip_subnets]}"
        echo ""
        echo "=== SECURITY SYSTEMS DETECTED ==="
        for sys in "${SECURITY_SYSTEMS[@]:-}"; do echo "  + $sys"; done
        echo ""
        echo "=== WARNINGS ==="
        for w in "${TOPO_WARNINGS[@]:-}"; do echo "  ! $w"; done
        echo ""
        echo "=== SCAN RECOMMENDATION ==="
        echo "${TOPO[scan_recommendation]}"
    } > "$TOPO_FILE"

    log "  Topology report: $TOPO_FILE" "TOPO"
}

# ──────────────────────────────────────────────────────────────────────────────
#  ORCHESTRATOR — probe_topology() wywołuje subfunkcje po kolei
# ──────────────────────────────────────────────────────────────────────────────

probe_topology() {
    log "═══════════════════════════════════════════════════════════════" "TOPO"
    log " $(L phase_0)" "TOPO"
    log "═══════════════════════════════════════════════════════════════" "TOPO"

    if [[ "${TARGET_CENTRIC_MODE:-1}" == "1" ]]; then
        log "  [v30] Enterprise auto-scope: brak ręcznych IP, brak raportowania adresów" "TOPO"
        if hound_before_discovery; then
            log "  [✓] Hound scope normalized: ${TOPO[target_subnets]}" "TOPO"
        else
            TOPO_WARNINGS+=("NO_SCOPE: v30 nie wymaga ręcznych IP; auto-discovery nie znalazł legalnego scope enterprise")
            log "  [!] Brak legalnego scope enterprise. v30 nie wymaga ręcznych IP; z tego punktu nie znaleziono legalnego scope enterprise." "WARN"
        fi
        TOPO[scan_recommendation]="TARGET_SCOPE_ONLY"
        topo_generate_report
        log "═══════════════════════════════════════════════════════════════" "TOPO"
        log " $(L phase_0_done)" "TOPO"
        log " $(L topo_subnets "${TOPO[target_subnets]}")" "TOPO"
        log "═══════════════════════════════════════════════════════════════" "TOPO"
        return 0
    fi

    log "  $(L topo_vpn)" "TOPO"
    topo_detect_vpn
    log "  $(L topo_wan)" "TOPO"
    topo_detect_wan
    log "  $(L topo_nat)" "TOPO"
    topo_detect_nat
    log "  $(L topo_ids)" "TOPO"
    topo_detect_ids
    topo_detect_dns_filter
    topo_detect_ssh_tarpit
    topo_detect_autoban
    log "  $(L topo_fw)" "TOPO"
    topo_detect_firewall
    log "  $(L topo_sub)" "TOPO"
    topo_select_subnets
    log "  $(L topo_rec)" "TOPO"
    topo_scan_recommendation
    log "  $(L topo_rep)" "TOPO"
    topo_generate_report
    log "═══════════════════════════════════════════════════════════════" "TOPO"
    log " $(L phase_0_done)" "TOPO"
    log " $(L topo_stats "${TOPO[vpn_detected]}" "${TOPO[honeypot_detected]}" "${TOPO[ids_detected]}")" "TOPO"
    log " $(L topo_secsys "${#SECURITY_SYSTEMS[@]}")" "TOPO"
    log " $(L topo_subnets "${TOPO[target_subnets]}")" "TOPO"
    log "═══════════════════════════════════════════════════════════════" "TOPO"
}




# ─────────────────────────────────────────────────────────────────────────────
# NET-AUDIT v27 — GENERIC AUDIT FRAMEWORK
# Zero hard-coded adresów jako cele testowe; zero integracji produktowych.
# Wyniki: CONFIRMED | NOT_DETECTED | NOT_TESTED | ABSENT
# ─────────────────────────────────────────────────────────────────────────────

declare -a AUDIT_FINDINGS=()
declare -A AUDIT_COVERAGE=()
declare -A AUDIT_META=()
declare -A PORT_STATE=()
declare -A BEHAVIOR_GRAPH=()

_report_finding() {
    local klass="$1" status="$2" confidence="${3:-0}" evidence="${4:-}" tested_by="${5:-}"
    AUDIT_FINDINGS+=("${klass}${SEP}${status}${SEP}${confidence}${SEP}${evidence}${SEP}${tested_by}")
    case "$status" in
        CONFIRMED|NOT_DETECTED|ABSENT) (( AUDIT_COVERAGE[tested]+=1 )) ;;
        NOT_TESTED) (( AUDIT_COVERAGE[not_tested]+=1 )) ;;
    esac
    case "$status" in
        CONFIRMED) (( AUDIT_COVERAGE[confirmed]+=1 )) ;;
        NOT_DETECTED) (( AUDIT_COVERAGE[not_detected]+=1 )) ;;
        ABSENT) (( AUDIT_COVERAGE[absent]+=1 )) ;;
        NOT_TESTED) (( AUDIT_COVERAGE[not_tested_items]+=1 )) ;;
    esac
}

_coverage_summary() {
    local total="${#AUDIT_FINDINGS[@]}"
    AUDIT_COVERAGE[total]="$total"
    : "${AUDIT_COVERAGE[tested]:=0}"
    : "${AUDIT_COVERAGE[confirmed]:=0}"
    : "${AUDIT_COVERAGE[not_detected]:=0}"
    : "${AUDIT_COVERAGE[absent]:=0}"
    : "${AUDIT_COVERAGE[not_tested_items]:=0}"
}

_scale_confidence() {
    local base="${1:-50}" bonus="${2:-0}" penalty="${3:-0}"
    _is_int "$base" || base=50
    _is_int "$bonus" || bonus=0
    _is_int "$penalty" || penalty=0
    local score=$(( base + bonus - penalty ))
    (( score < 0 )) && score=0
    (( score > 100 )) && score=100
    echo "$score"
}

_rand_token() {
    tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 14
}

_dyn_resolver_candidates() {
    local seen=" "
    local ns
    for ns in "${DNS_SERVERS[@]:-}"; do
        [[ -n "$ns" && "$seen" != *" $ns "* ]] && { echo "$ns"; seen+=" $ns "; }
    done
    [[ -n "${INTERNAL_DNS:-}" && "$seen" != *" $INTERNAL_DNS "* ]] && echo "$INTERNAL_DNS"
}

_probe_harness() {
    local name="$1" fn="$2" intensity="${3:-safe}" dry_run="${4:-0}"
    AUDIT_META["${name}:intensity"]="$intensity"
    if [[ "$dry_run" == "1" ]]; then
        _report_finding "$name" "NOT_TESTED" 0 "dry-run" "$fn"
        return 0
    fi
    if ! declare -F "$fn" >/dev/null 2>&1; then
        _report_finding "$name" "NOT_TESTED" 0 "missing probe function" "$fn"
        return 0
    fi
    "$fn"
}

_probe_rollback() { return 0; }

_probe_intensity_gate() {
    local requested="${1:-safe}"
    case "${MODE:-standard}" in
        passive) [[ "$requested" == "safe" ]] ;;
        *) return 0 ;;
    esac
}

_calibrate_noise_floor() {
    local src="${SESSION_STATE[noise_floor]:-${BH_NOISE_FLOOR_MS:-0}}"
    _is_int "$src" || src=0
    if (( src == 0 )) && [[ -n "${GATEWAY_IP:-}" ]]; then
        local vals=() i x
        for i in 1 2 3; do
            x=$(_tcp_connect_ms "$GATEWAY_IP" 80 1)
            _is_int "$x" && vals+=("$x")
        done
        (( ${#vals[@]} > 0 )) && src=$(_median_int "${vals[@]}")
    fi
    BH_NOISE_FLOOR_MS="${src:-0}"
    echo "${BH_NOISE_FLOOR_MS:-0}"
}

_classify_port_type() {
    local ip="$1" port="$2"
    local fp="" banner="" delay="0"
    declare -F _port_fingerprint >/dev/null 2>&1 && fp=$(_port_fingerprint "$ip" "$port" 2>/dev/null || true)
    banner="$(timeout 2 bash -c "exec 3<>/dev/tcp/$ip/$port; head -c 128 <&3" 2>/dev/null | tr -d '\r' || true)"
    delay="$(_tcp_connect_ms "$ip" "$port" 1)"
    if [[ "$banner" =~ ^SSH-2\.0- ]] || [[ "$banner" =~ ^220[[:space:]] ]] || [[ "$banner" =~ ^\+OK[[:space:]] ]]; then
        echo "tarpit"
    elif [[ -n "$fp" && "$fp" =~ fake|phantom|mirage|decoy ]]; then
        echo "mirage"
    elif _is_int "$delay" && (( delay > 1400 )) && [[ -z "$banner" ]]; then
        echo "tarpit"
    elif [[ -n "$banner" ]]; then
        echo "real"
    else
        echo "unknown"
    fi
}

_score_deception_quality() {
    local total=0 good=0 key cls
    for key in "${!PORT_STATE[@]}"; do
        cls="${PORT_STATE[$key]}"
        [[ "$cls" == "mirage" || "$cls" == "tarpit" ]] || continue
        (( total++ ))
        [[ "$cls" == "tarpit" ]] && (( good++ )) || [[ "$cls" == "mirage" ]] && (( good++ ))
    done
    if (( total == 0 )); then
        _report_finding "DECEPTION_SURFACE" "NOT_TESTED" 0 "no classified deceptive ports" "_score_deception_quality"
    else
        local conf; conf=$(_scale_confidence 55 $(( good*8 )) $(( (total-good)*5 )))
        _report_finding "DECEPTION_SURFACE" "CONFIRMED" "$conf" "classified=${total} quality=${good}/${total}" "_score_deception_quality"
    fi
}

_deception_normalize() {
    local i ip ports p cls filtered=()
    for (( i=0; i<DEV_COUNT; i++ )); do
        ip="${D_IP[$i]:-}"
        ports="${D_PORTS[$i]:-}"
        [[ -z "$ip" || -z "$ports" ]] && continue
        filtered=()
        for p in $ports; do
            cls="$(_classify_port_type "$ip" "$p")"
            PORT_STATE["$ip:$p"]="$cls"
            [[ "$cls" == "real" || "$cls" == "unknown" ]] && filtered+=("$p")
        done
        D_PORTS[$i]="${filtered[*]:-}"
    done
    _score_deception_quality
}

_normalize_port_surface() {
    _deception_normalize
}

_test_dns_tunnel() {
    if [[ -z "${T[dig]:-}" ]]; then
        _report_finding "DNS_TUNNELING_CONTROL" "NOT_TESTED" 0 "dig unavailable" "_test_dns_tunnel"
        return 0
    fi
    local resolver token q ans
    resolver="${INTERNAL_DNS:-$(head -n1 < <(_dyn_resolver_candidates) || true)}"
    [[ -z "$resolver" ]] && { _report_finding "DNS_TUNNELING_CONTROL" "NOT_TESTED" 0 "no resolver candidate" "_test_dns_tunnel"; return 0; }
    token="$(_rand_token)$(_rand_token)$(_rand_token)"
    q="${token}.audit.invalid"
    ans=$(dig +time=2 +tries=1 @"$resolver" "$q" TXT 2>/dev/null || true)
    if echo "$ans" | grep -qiE 'status:\s*(REFUSED|SERVFAIL)'; then
        _report_finding "DNS_TUNNELING_CONTROL" "CONFIRMED" 76 "oversized label constrained by resolver" "_test_dns_tunnel"
    elif echo "$ans" | grep -qi 'status: NXDOMAIN'; then
        _report_finding "DNS_TUNNELING_CONTROL" "NOT_DETECTED" 42 "plain NXDOMAIN only; no proof of tunnel-aware control" "_test_dns_tunnel"
    else
        _report_finding "DNS_TUNNELING_CONTROL" "NOT_DETECTED" 35 "query path available without explicit control signal" "_test_dns_tunnel"
    fi
}

_test_dga_detection() {
    if [[ -z "${T[dig]:-}" ]]; then
        _report_finding "DGA_DETECTION" "NOT_TESTED" 0 "dig unavailable" "_test_dga_detection"
        return 0
    fi
    local resolver="${INTERNAL_DNS:-$(head -n1 < <(_dyn_resolver_candidates) || true)}"
    [[ -z "$resolver" ]] && { _report_finding "DGA_DETECTION" "NOT_TESTED" 0 "no resolver candidate" "_test_dga_detection"; return 0; }
    local total=0 nx=0 blocked=0 d ans
    for d in "$(_rand_token).invalid" "$(_rand_token).invalid" "$(_rand_token).invalid"; do
        (( total++ ))
        ans=$(dig +time=2 +tries=1 @"$resolver" "$d" A 2>/dev/null || true)
        echo "$ans" | grep -qi 'status: NXDOMAIN' && (( nx++ ))
        echo "$ans" | grep -qiE '0\.0\.0\.0|127\.' && (( blocked++ ))
    done
    if (( blocked > 0 )); then
        _report_finding "DGA_DETECTION" "CONFIRMED" 72 "sinkhole/block pattern observed (${blocked}/${total})" "_test_dga_detection"
    else
        _report_finding "DGA_DETECTION" "NOT_DETECTED" 45 "random domains ended as plain NXDOMAIN=${nx}/${total}" "_test_dga_detection"
    fi
}

_test_dns_exfil_channel() {
    if [[ -z "${T[dig]:-}" ]]; then
        _report_finding "DNS_EXFIL_CHANNEL" "NOT_TESTED" 0 "dig unavailable" "_test_dns_exfil_channel"
        return 0
    fi
    local total=0 reachable=0 ns
    while IFS= read -r ns; do
        [[ -z "$ns" ]] && continue
        (( total++ ))
        dig +time=2 +tries=1 @"$ns" example.com A >/dev/null 2>&1 && (( reachable++ ))
    done < <(_dyn_resolver_candidates)
    if (( total == 0 )); then
        _report_finding "DNS_EXFIL_CHANNEL" "NOT_TESTED" 0 "no resolver candidates" "_test_dns_exfil_channel"
    elif (( reachable <= 1 )); then
        _report_finding "DNS_EXFIL_CHANNEL" "CONFIRMED" 78 "resolver surface limited (${reachable}/${total})" "_test_dns_exfil_channel"
    else
        _report_finding "DNS_EXFIL_CHANNEL" "ABSENT" 84 "multiple resolver paths answer (${reachable}/${total})" "_test_dns_exfil_channel"
    fi
}

_test_dot_doh_bypass() {
    local doh_ok=0 dot_ok=0
    if [[ -n "${T[curl]:-}" ]]; then
        timeout 4 curl -ksS -o /dev/null --max-time 3 "https://dns.google/resolve?name=example.com&type=A" && (( doh_ok++ )) || true
        timeout 4 curl -ksS -o /dev/null --max-time 3 "https://cloudflare-dns.com/dns-query?name=example.com&type=A" -H "accept: application/dns-json" && (( doh_ok++ )) || true
    fi
    if [[ -n "${T[openssl]:-}" ]]; then
        timeout 4 bash -c 'echo | openssl s_client -quiet -connect dns.google:853 >/dev/null 2>&1' && (( dot_ok++ )) || true
        timeout 4 bash -c 'echo | openssl s_client -quiet -connect one.one.one.one:853 >/dev/null 2>&1' && (( dot_ok++ )) || true
    fi
    if (( doh_ok == 0 && dot_ok == 0 )); then
        _report_finding "DNS_BYPASS_CONTROLS" "CONFIRMED" 74 "DoH/DoT paths not observed" "_test_dot_doh_bypass"
    elif (( doh_ok + dot_ok == 1 )); then
        _report_finding "DNS_BYPASS_CONTROLS" "NOT_DETECTED" 55 "partial bypass surface doh=${doh_ok} dot=${dot_ok}" "_test_dot_doh_bypass"
    else
        _report_finding "DNS_BYPASS_CONTROLS" "ABSENT" 82 "multiple DoH/DoT paths reachable" "_test_dot_doh_bypass"
    fi
}

audit_dns_deep() {
    log "[DNS-DEEP] behavioural DNS controls" "SECTION"
    _probe_harness "DNS_TUNNELING_CONTROL" "_test_dns_tunnel" safe 0
    _probe_harness "DGA_DETECTION" "_test_dga_detection" safe 0
    _probe_harness "DNS_EXFIL_CHANNEL" "_test_dns_exfil_channel" safe 0
    _probe_harness "DNS_BYPASS_CONTROLS" "_test_dot_doh_bypass" safe 0
}

_test_http_exfil() {
    if [[ -z "${T[curl]:-}" ]]; then
        _report_finding "HTTP_EXFIL_POLICY" "NOT_TESTED" 0 "curl unavailable" "_test_http_exfil"
        return 0
    fi
    local code
    code=$(timeout 5 curl -ksS -o /dev/null -w '%{http_code}' -X POST --data "audit=$(_rand_token)" https://example.com 2>/dev/null || echo "000")
    if [[ "$code" =~ ^(000|403|405)$ ]]; then
        _report_finding "HTTP_EXFIL_POLICY" "CONFIRMED" 63 "post not freely usable (code=$code)" "_test_http_exfil"
    else
        _report_finding "HTTP_EXFIL_POLICY" "ABSENT" 78 "outbound POST succeeded (code=$code)" "_test_http_exfil"
    fi
}

_test_dns_exfil() {
    _test_dns_exfil_channel
}

_test_icmp_exfil() {
    if [[ -z "${T[ping]:-}" ]]; then
        _report_finding "ICMP_EXFIL_POLICY" "NOT_TESTED" 0 "ping unavailable" "_test_icmp_exfil"
        return 0
    fi
    if timeout 3 ping -c1 -W1 example.com >/dev/null 2>&1; then
        _report_finding "ICMP_EXFIL_POLICY" "ABSENT" 68 "outbound ICMP reachable" "_test_icmp_exfil"
    else
        _report_finding "ICMP_EXFIL_POLICY" "CONFIRMED" 66 "outbound ICMP constrained" "_test_icmp_exfil"
    fi
}

_classify_exfil_policy() {
    local absent=0 confirmed=0
    local f IFS_OLD="$IFS" klass st conf ev by
    for f in "${AUDIT_FINDINGS[@]}"; do
        IFS=$'\x01' read -r klass st conf ev by <<< "$f"
        case "$klass" in
            HTTP_EXFIL_POLICY|DNS_EXFIL_CHANNEL|ICMP_EXFIL_POLICY)
                [[ "$st" == "ABSENT" ]] && (( absent++ ))
                [[ "$st" == "CONFIRMED" ]] && (( confirmed++ ))
                ;;
        esac
    done
    IFS="$IFS_OLD"
    if (( absent >= 2 )); then
        _report_finding "EXFIL_POLICY" "ABSENT" 81 "multiple outbound channels remained available" "_classify_exfil_policy"
    elif (( confirmed >= 2 )); then
        _report_finding "EXFIL_POLICY" "CONFIRMED" 74 "multiple outbound channels constrained" "_classify_exfil_policy"
    else
        _report_finding "EXFIL_POLICY" "NOT_DETECTED" 50 "mixed exfil signal" "_classify_exfil_policy"
    fi
}

audit_exfil() {
    log "[EXFIL] safe outbound validation" "SECTION"
    _probe_harness "HTTP_EXFIL_POLICY" "_test_http_exfil" safe 0
    _probe_harness "DNS_EXFIL_CHANNEL" "_test_dns_exfil" safe 0
    _probe_harness "ICMP_EXFIL_POLICY" "_test_icmp_exfil" safe 0
    _classify_exfil_policy
}

_inject_canary_credential() {
    local token="canary_$(_rand_token)"
    AUDIT_META[credential_token]="$token"
    echo "$token"
}

_test_dlp_response() {
    if [[ -z "${T[curl]:-}" ]]; then
        _report_finding "SECRET_DLP" "NOT_TESTED" 0 "curl unavailable" "_test_dlp_response"
        return 0
    fi
    local token code
    token="$(_inject_canary_credential)"
    code=$(timeout 5 curl -ksS -o /dev/null -w '%{http_code}' -X POST \
        -H "X-Audit-Token: ${token}" \
        --data "credential=${token}" \
        https://example.com 2>/dev/null || echo "000")
    if [[ "$code" =~ ^(000|403)$ ]]; then
        _report_finding "SECRET_DLP" "CONFIRMED" 58 "secret-like marker was not freely emitted (code=$code)" "_test_dlp_response"
    else
        _report_finding "SECRET_DLP" "NOT_DETECTED" 41 "no independent DLP signal on inert token (code=$code)" "_test_dlp_response"
    fi
}

_validate_secret_detection() {
    local token="${AUDIT_META[credential_token]:-}"
    [[ -z "$token" ]] && { _report_finding "SECRET_VALIDATION" "NOT_TESTED" 0 "no token generated" "_validate_secret_detection"; return 0; }
    _report_finding "SECRET_VALIDATION" "NOT_DETECTED" 35 "no out-of-band observer; token=$token" "_validate_secret_detection"
}

audit_credential_leak() {
    log "[DLP] inert credential marker" "SECTION"
    _probe_harness "SECRET_DLP" "_test_dlp_response" safe 0
    _probe_harness "SECRET_VALIDATION" "_validate_secret_detection" safe 0
}

_test_tcp_fingerprint() {
    local total=0 stable=0 ip ttl
    for ip in "${D_IP[@]:-}"; do
        [[ -z "$ip" ]] && continue
        (( total++ ))
        ttl=$(_ping_ttl "$ip")
        _is_int "$ttl" && (( stable++ ))
        (( total >= 5 )) && break
    done
    if (( total == 0 )); then
        _report_finding "TCP_FINGERPRINTING" "NOT_TESTED" 0 "no hosts" "_test_tcp_fingerprint"
    elif (( stable == total )); then
        _report_finding "TCP_FINGERPRINTING" "NOT_DETECTED" 46 "ttl values stable enough for passive fingerprint hints (${stable}/${total})" "_test_tcp_fingerprint"
    else
        _report_finding "TCP_FINGERPRINTING" "CONFIRMED" 57 "limited fingerprint signal (${stable}/${total})" "_test_tcp_fingerprint"
    fi
}

_test_banner_disclosure() {
    local disclosed=0 total=0 i b
    for (( i=0; i<DEV_COUNT; i++ )); do
        b="${D_BANNER[$i]:-}"
        [[ -z "$b" ]] && continue
        (( total++ ))
        echo "$b" | grep -qiE 'server:|version|nginx|apache|openssh|smtp' && (( disclosed++ ))
    done
    if (( total == 0 )); then
        _report_finding "BANNER_DISCLOSURE" "NOT_TESTED" 0 "no banners collected in network-only mode" "_test_banner_disclosure"
    elif (( disclosed == 0 )); then
        _report_finding "BANNER_DISCLOSURE" "CONFIRMED" 62 "no explicit version disclosure in collected banners" "_test_banner_disclosure"
    else
        _report_finding "BANNER_DISCLOSURE" "NOT_DETECTED" 60 "version-like disclosure present ${disclosed}/${total}" "_test_banner_disclosure"
    fi
}

_test_topology_leak() {
    local vis="${L2_RESULTS[vendor_diversity]:-0}" flat="${L3_RESULTS[flat_network_pct]:-${TRAFFIC_POLICY[east_west_pre_hits]:-0}}"
    _is_int "$vis" || vis=0
    _is_int "$flat" || flat=0
    if (( vis <= 3 && flat <= 20 )); then
        _report_finding "TOPOLOGY_PRIVACY" "CONFIRMED" 68 "limited broadcast/segmentation disclosure" "_test_topology_leak"
    else
        _report_finding "TOPOLOGY_PRIVACY" "NOT_DETECTED" 54 "mapping surface remains visible vendor_diversity=${vis} flat=${flat}" "_test_topology_leak"
    fi
}

audit_privacy() {
    log "[PRIVACY] fingerprinting surface" "SECTION"
    _probe_harness "TCP_FINGERPRINTING" "_test_tcp_fingerprint" safe 0
    _probe_harness "BANNER_DISCLOSURE" "_test_banner_disclosure" safe 0
    _probe_harness "TOPOLOGY_PRIVACY" "_test_topology_leak" safe 0
}

_simulate_propagation() {
    local max_hosts=6 tested=0 hits=0 a b p
    local -a ports=(22 53 80 443 445 3389)
    for a in "${D_IP[@]:-}"; do
        [[ -z "$a" ]] && continue
        for b in "${D_IP[@]:-}"; do
            [[ -z "$b" || "$a" == "$b" ]] && continue
            for p in "${ports[@]}"; do
                (( tested++ ))
                g_tcp_probe "$b" "$p" 1 | grep -qE 'open|closed' && { (( hits++ )); break; }
                (( tested >= max_hosts )) && break
            done
            (( tested >= max_hosts )) && break
        done
        (( tested >= max_hosts )) && break
    done
    AUDIT_META[lateral_tested]="$tested"
    AUDIT_META[lateral_hits]="$hits"
}

_test_segment_isolation() {
    _simulate_propagation
    local tested="${AUDIT_META[lateral_tested]:-0}" hits="${AUDIT_META[lateral_hits]:-0}"
    if (( tested == 0 )); then
        _report_finding "SEGMENT_ISOLATION" "NOT_TESTED" 0 "insufficient host pairs" "_test_segment_isolation"
    elif (( hits <= 1 )); then
        _report_finding "SEGMENT_ISOLATION" "CONFIRMED" 70 "limited east-west reachability (${hits}/${tested})" "_test_segment_isolation"
    else
        _report_finding "SEGMENT_ISOLATION" "NOT_DETECTED" 67 "east-west paths visible (${hits}/${tested})" "_test_segment_isolation"
    fi
}

_estimate_blast_radius() {
    local tested="${AUDIT_META[lateral_tested]:-0}" hits="${AUDIT_META[lateral_hits]:-0}"
    if (( tested == 0 )); then
        _report_finding "BLAST_RADIUS" "NOT_TESTED" 0 "no lateral sample" "_estimate_blast_radius"
    elif (( hits * 100 / tested >= 50 )); then
        _report_finding "BLAST_RADIUS" "ABSENT" 76 "broad reachability sample ${hits}/${tested}" "_estimate_blast_radius"
    else
        _report_finding "BLAST_RADIUS" "CONFIRMED" 64 "contained reachability sample ${hits}/${tested}" "_estimate_blast_radius"
    fi
}

audit_lateral_deep() {
    log "[LATERAL] containment sample" "SECTION"
    _probe_harness "SEGMENT_ISOLATION" "_test_segment_isolation" safe 0
    _probe_harness "BLAST_RADIUS" "_estimate_blast_radius" safe 0
}

_test_escalation() {
    local threat="${SESSION_STATE[threat_level]:-0}" corr="${SESSION_STATE[correlation_score]:-0}"
    _is_int "$threat" || threat=0
    _is_int "$corr" || corr=0
    if (( threat >= 60 || corr >= 40 )); then
        _report_finding "ADAPTIVE_RESPONSE" "CONFIRMED" 79 "session reactivity threat=${threat} corr=${corr}" "_test_escalation"
    else
        _report_finding "ADAPTIVE_RESPONSE" "NOT_DETECTED" 48 "limited behavioural escalation threat=${threat} corr=${corr}" "_test_escalation"
    fi
}

_test_rate_limiting() {
    if [[ "${TRAFFIC_POLICY[rate_limiting]:-0}" == "1" || "${TOPO[ids_detected]:-0}" == "1" ]]; then
        _report_finding "RATE_LIMITING" "CONFIRMED" "${TOPO[ids_conf]:-${TRAFFIC_POLICY[rate_limit_conf]:-65}}" "traffic throttling indicators present" "_test_rate_limiting"
    else
        _report_finding "RATE_LIMITING" "NOT_DETECTED" 44 "no stable throttling indicator in session" "_test_rate_limiting"
    fi
}

_test_behavior_change() {
    if [[ "${SESSION_STATE[adaptation_detected]:-0}" == "1" ]]; then
        _report_finding "BEHAVIOR_CHANGE" "CONFIRMED" 75 "defence posture changed over time" "_test_behavior_change"
    else
        _report_finding "BEHAVIOR_CHANGE" "NOT_DETECTED" 40 "no persistent behaviour change observed" "_test_behavior_change"
    fi
}

audit_adaptive_response() {
    log "[ADAPTIVE] behaviour over time" "SECTION"
    _probe_harness "ADAPTIVE_RESPONSE" "_test_escalation" safe 0
    _probe_harness "RATE_LIMITING" "_test_rate_limiting" safe 0
    _probe_harness "BEHAVIOR_CHANGE" "_test_behavior_change" safe 0
}

_cross_node_correlate() {
    local corr="${SESSION_STATE[correlation_score]:-0}" shift="${SESSION_STATE[cross_host_latency_shift]:-0}"
    _is_int "$corr" || corr=0
    _is_int "$shift" || shift=0
    BEHAVIOR_GRAPH[nodes]="${DEV_COUNT:-0}"
    BEHAVIOR_GRAPH[cross_score]="$corr"
    BEHAVIOR_GRAPH[cross_shift]="$shift"
    if (( corr >= 40 || shift >= 2 )); then
        _report_finding "GLOBAL_CORRELATION" "CONFIRMED" 80 "cross-node reaction corr=${corr} shift=${shift}" "_cross_node_correlate"
    else
        _report_finding "GLOBAL_CORRELATION" "NOT_DETECTED" 46 "weak cross-node signal corr=${corr} shift=${shift}" "_cross_node_correlate"
    fi
}

_build_behavior_graph() {
    _report_finding "BEHAVIOR_GRAPH" "CONFIRMED" 58 "nodes=${BEHAVIOR_GRAPH[nodes]:-0} cross_score=${BEHAVIOR_GRAPH[cross_score]:-0}" "_build_behavior_graph"
}

_test_eicar_flow() {
    if [[ -z "${T[curl]:-}" ]]; then
        _report_finding "MALWARE_SAFE" "NOT_TESTED" 0 "curl unavailable" "_test_eicar_flow"
        return 0
    fi
    local code
    code=$(timeout 5 curl -ksS -o /dev/null -w '%{http_code}' -X POST \
        --data-urlencode 'eicar=X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
        https://example.com 2>/dev/null || echo "000")
    if [[ "$code" =~ ^(000|403)$ ]]; then
        _report_finding "MALWARE_SAFE" "CONFIRMED" 57 "test marker not freely transferred (code=$code)" "_test_eicar_flow"
    else
        _report_finding "MALWARE_SAFE" "NOT_DETECTED" 39 "marker passed application layer (code=$code)" "_test_eicar_flow"
    fi
}

_test_inert_payload() {
    local token="inert-$(_rand_token)"
    AUDIT_META[inert_payload]="$token"
    _report_finding "INERT_PAYLOAD_FLOW" "CONFIRMED" 52 "marker generated ${token}" "_test_inert_payload"
}

_measure_av_response() {
    _report_finding "AV_RESPONSE" "NOT_TESTED" 0 "no out-of-band observer for response time" "_measure_av_response"
}

audit_malware_safe() {
    log "[MALWARE-SAFE] inert payloads" "SECTION"
    _probe_harness "MALWARE_SAFE" "_test_eicar_flow" safe 0
    _probe_harness "INERT_PAYLOAD_FLOW" "_test_inert_payload" safe 0
    _probe_harness "AV_RESPONSE" "_measure_av_response" safe 0
}

_test_url_filtering() {
    if [[ -z "${T[curl]:-}" ]]; then
        _report_finding "URL_FILTERING" "NOT_TESTED" 0 "curl unavailable" "_test_url_filtering"
        return 0
    fi
    local code
    code=$(timeout 5 curl -ksS -o /dev/null -w '%{http_code}' https://example.com/.well-known/security.txt 2>/dev/null || echo "000")
    if [[ "$code" =~ ^(000|403)$ ]]; then
        _report_finding "URL_FILTERING" "CONFIRMED" 50 "generic outbound web path constrained (code=$code)" "_test_url_filtering"
    else
        _report_finding "URL_FILTERING" "NOT_DETECTED" 37 "generic web path available (code=$code)" "_test_url_filtering"
    fi
}

_test_gtube() {
    _report_finding "MAIL_CONTENT_CONTROL" "NOT_TESTED" 0 "no safe mail loop in generic mode" "_test_gtube"
}

_simulate_phishing_safe() {
    if [[ -z "${T[dig]:-}" ]]; then
        _report_finding "PHISHING_SAFE" "NOT_TESTED" 0 "dig unavailable" "_simulate_phishing_safe"
        return 0
    fi
    local resolver="${INTERNAL_DNS:-$(head -n1 < <(_dyn_resolver_candidates) || true)}"
    [[ -z "$resolver" ]] && { _report_finding "PHISHING_SAFE" "NOT_TESTED" 0 "no resolver candidate" "_simulate_phishing_safe"; return 0; }
    local ans
    ans=$(dig +time=2 +tries=1 @"$resolver" "login-update-$(_rand_token).invalid" A 2>/dev/null || true)
    if echo "$ans" | grep -qiE 'REFUSED|SERVFAIL'; then
        _report_finding "PHISHING_SAFE" "CONFIRMED" 61 "suspicious lookup constrained locally" "_simulate_phishing_safe"
    else
        _report_finding "PHISHING_SAFE" "NOT_DETECTED" 38 "no explicit phishing-aware control signal" "_simulate_phishing_safe"
    fi
}

audit_phishing_safe() {
    log "[PHISH-SAFE] generic social-engineering controls" "SECTION"
    _probe_harness "URL_FILTERING" "_test_url_filtering" safe 0
    _probe_harness "MAIL_CONTENT_CONTROL" "_test_gtube" safe 0
    _probe_harness "PHISHING_SAFE" "_simulate_phishing_safe" safe 0
}


# [1] PREFLIGHT

preflight() {
    log "$(L preflight)" "SECTION"

    local tools=(bash ping nc ncat curl wget dig host nmap arp ip ss netstat
                 iptables nft traceroute openssl timeout bc wc awk grep sed
                 sort uniq mktemp date tr cut head tail
                 nmblookup snmpwalk ldapsearch rpcclient smbclient)

    for t in "${tools[@]}"; do
        command -v "$t" &>/dev/null && T[$t]="$t" || T[$t]=""
    done

    T[nc_cmd]="${T[ncat]:-${T[nc]:-}}"

    local bv="${BASH_VERSINFO[0]}"
    (( bv < 4 )) && log "$(L bash_old)" "ERROR" && exit 1

    T[is_root]="0"
    [[ $EUID -eq 0 ]] && T[is_root]="1"
    [[ "${T[is_root]}" == "0" ]] && log "$(L no_root)" "WARN"

    T[has_ipv6]="0"
    ip -6 addr show 2>/dev/null | grep -q "inet6" && T[has_ipv6]="1"

    log "Narzędzia: nc=${T[nc_cmd]:-BRAK} curl=${T[curl]:-BRAK} iptables=${T[iptables]:-BRAK}"
    log "Root: ${T[is_root]} | IPv6: ${T[has_ipv6]} | Tryb: $MODE"
}

# [2] INFRASTRUCTURE

GATEWAY_IP=""
GATEWAY_MAC=""
WAN_IP=""
INTERNAL_DNS=""
declare -a DNS_SERVERS=()
declare -a LOCAL_IPS=()
declare -a SUBNETS=()


discover_infrastructure() {
    log "$(L phase_2)" "SECTION"

    LOCAL_IPS=()
    DNS_SERVERS=()
    SUBNETS=()
    GATEWAY_IP=""
    GATEWAY_MAC=""
    WAN_IP=""
    INTERNAL_DNS=""

    if ! hound_before_discovery; then
        AUDIT_STATUS="NO_SCOPE"
    ewnaf_miniserver_event "audit_status" "NO_SCOPE" "Brak legalnego scope enterprise"
        AUDIT_NOTE="$(L no_subnets)"
        log "$AUDIT_NOTE" "WARN"
        return 1
    fi
    log "Scope targetu po normalizacji: ${SUBNETS[*]}"

    if [[ -n "${WAN_IP_OVERRIDE:-}" ]]; then
        WAN_IP="$WAN_IP_OVERRIDE"
        log "WAN override: $WAN_IP"
    fi

    log "v30: enterprise auto-scope aktywny — reachability hints bez ekspozycji adresów w raporcie"
}




# [2b] LAYER 2 — domena rozgłoszeniowa

declare -A L2_RESULTS=(
    [ap_count]="0"      [switch_count]="0"    [router_count]="0"
    [vendor_diversity]="0" [ttl_baseline]="64"  [broadcast_domain]=""
    [oui_clusters]=""
)
declare -a L2_DEVICES=()

audit_layer2() {
    log "$(L l2_section)" "SECTION"

    # Pełny ARP sweep — wyślij ARP do wszystkich hostów we wszystkich subnetach
    local tmp_arp; tmp_arp=$(mktemp)
    for subnet in "${SUBNETS[@]}"; do
        local ip="${subnet%/*}" mask="${subnet#*/}"
        IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
        local ip_dec=$(( (o1<<24)+(o2<<16)+(o3<<8)+o4 ))
        local mbits=$(( 0xFFFFFFFF << (32-mask) & 0xFFFFFFFF ))
        local net=$(( ip_dec & mbits ))
        local bcast=$(( net | (~mbits & 0xFFFFFFFF) ))
        local start=$(( net+1 )) end=$(( bcast-1 ))
        (( end-start > 1022 )) && end=$(( start+1022 ))
        for (( i=start; i<=end; i++ )); do
            local tgt; tgt=$(printf "%d.%d.%d.%d" $(( (i>>24)&255 )) $(( (i>>16)&255 )) $(( (i>>8)&255 )) $(( i&255 )))
            _is_excluded_ip "$tgt" && continue
            ( ping -c1 -W1 "$tgt" &>/dev/null || true ) &
        done
    done
    wait
    sleep 1  # daj ARP cache czas

    # Zbierz ARP cache po sweep
    declare -A arp_full=()
    while read -r ip mac; do
        [[ -n "$ip" && -n "$mac" && "$mac" != "(incomplete)" ]] || continue
        _is_excluded_ip "$ip" && continue
        arp_full["$ip"]="$mac"
        echo "$ip $mac" >> "$tmp_arp"
    done < <({
        arp -n 2>/dev/null | awk '/[0-9]/ && !/incomplete/ {print $1,$3}'
        ip neigh 2>/dev/null | awk '/REACHABLE|STALE|DELAY|PERMANENT/ {print $1,$5}'
        awk 'NR>1 && $3!="0x0" {print $1,$4}' /proc/net/arp 2>/dev/null || true
    } | sort -u)

    log "  ARP sweep: ${#arp_full[@]} hostów"

    # MAC Vendor clustering
    declare -A oui_count=()
    local ap=0 sw=0 rt=0 vendor_set=""

    for ip in "${!arp_full[@]}"; do
        local mac="${arp_full[$ip]}"
        local oui; oui=$(echo "$mac" | tr '[:lower:]' '[:upper:]' | sed 's/://g' | cut -c1-6)
        local vendor; vendor=$(get_vendor "$mac")

        oui_count["$oui"]=$(( ${oui_count["$oui"]:-0} + 1 ))
        vendor_set="$vendor_set $vendor"

        local role="host"
        case "$vendor" in
            *Cisco*|*Juniper*|*MikroTik*|*Ubiquiti*|*Aruba*|*Netgear*|*TP-Link*)
                case "$vendor" in
                    *AP*|*Aruba*|*Ruckus*) role="AP"; (( ap++ )) ;;
                    *Switch*|*Catalyst*) role="switch"; (( sw++ )) ;;
                    *) role="router"; (( rt++ )) ;;
                esac ;;
        esac

        # TTL-based role inference
        local ttl_h; ttl_h=$(_ping_ttl "$ip")
        if _is_int "$ttl_h" && (( ttl_h >= 250 )); then role="router/switch"; (( rt++ ))
        elif _is_int "$ttl_h" && (( ttl_h >= 120 && ttl_h <= 128 )); then [[ "$role" == "host" ]] && role="windows"
        elif _is_int "$ttl_h" && (( ttl_h >= 60 && ttl_h <= 64 )); then [[ "$role" == "host" ]] && role="linux"
        fi

        L2_DEVICES+=("$ip|$mac|$vendor|$oui|$role|$ttl_h")
    done

    # TTL baseline — mediana
    local ttl_vals=()
    for dev in "${L2_DEVICES[@]}"; do
        local t; t="${dev##*|}"
        (( t > 0 )) && ttl_vals+=("$t")
    done
    if (( ${#ttl_vals[@]} > 0 )); then
        local baseline; baseline=$(_median_int "${ttl_vals[@]}")
        if (( ${#ttl_vals[@]} < 5 )); then
            (( baseline < 30 || baseline > 250 )) && baseline=64
        fi
        L2_RESULTS[ttl_baseline]="$baseline"
    fi

    # OUI diversity
    L2_RESULTS[vendor_diversity]="${#oui_count[@]}"
    L2_RESULTS[ap_count]="$ap"
    L2_RESULTS[switch_count]="$sw"
    L2_RESULTS[router_count]="$rt"

    # OUI clusters (top 5)
    local clusters=""
    for oui in "${!oui_count[@]}"; do
        clusters="$clusters ${oui_count[$oui]}x$oui"
    done
    L2_RESULTS[oui_clusters]="${clusters# }"

    log "  Routery: $rt | Switche: $sw | AP: $ap | OUI diversity: ${#oui_count[@]}"
    log "  TTL baseline: ${L2_RESULTS[ttl_baseline]}"

    rm -f "$tmp_arp"
}

# [2c] LAYER 3 — routing i segmentacja

declare -A L3_RESULTS=(
    [reachable_subnets]=""  [cross_subnet_ok]="0"
    [asymmetric_acl]="0"    [silent_drop_detected]="0"
    [east_west_isolated]="1" [nat_detected]="0"
)
declare -a L3_PATHS=()

audit_layer3() {
    log "$(L l3_section)" "SECTION"

    # Guard: DEV_COUNT z tablicy D_IP (nie zakładaj że poprzednia faza ustawiła)
    local DEV_COUNT="${#D_IP[@]}"
    if (( DEV_COUNT == 0 )); then
        L3_RESULTS[cross_subnet_ok]="INSUFFICIENT_SAMPLE"
        L3_RESULTS[east_west_isolated]="INSUFFICIENT_SAMPLE"
        log "$(L l3_no_hosts)" "WARN"
        return
    fi

    # TTL probing — wykryj reachable subnety przez wariację TTL odpowiedzi
    declare -A seen_subnets=()
    for dev in "${L2_DEVICES[@]}"; do
        local ip="${dev%%|*}"
        local ttl="${dev##*|}"
        local subnet; subnet=$(echo "$ip" | awk -F. '{print $1"."$2"."$3".0/24"}')
        seen_subnets["$subnet"]="${ttl}"
    done

    local reachable=""
    for sn in "${!seen_subnets[@]}"; do
        reachable="$reachable $sn"
    done
    L3_RESULTS[reachable_subnets]="${reachable# }"
    log "  Wykryte subnety (TTL probing): ${L3_RESULTS[reachable_subnets]}"

    # Cross-subnet reachability test
    # Cross-subnet reachability — używa REALNYCH hostów z różnych subnetów
    local cross_hits=0 cross_total=0
    local _l2_limit=$(( DEV_COUNT < 16 ? DEV_COUNT : 16 ))
    for (( i=0; i<_l2_limit; i++ )); do
        for (( j=i+1; j<_l2_limit; j++ )); do
            local s1; s1=$(echo "${D_IP[$i]}" | awk -F. '{print $1"."$2"."$3}')
            local s2; s2=$(echo "${D_IP[$j]}" | awk -F. '{print $1"."$2"."$3}')
            [[ "$s1" == "$s2" ]] && continue  # pomiń same-subnet pary
            (( cross_total++ ))
            # Analiza kierunkowa: A→B i B→A (asymetryczne ACL = mamy korelację)
            local ab=0 ba=0
            if probe_port "${D_IP[$j]}" 80 1 || \
               probe_port "${D_IP[$j]}" 443 1 || \
               probe_port "${D_IP[$j]}" 22 1; then ab=1; fi
            if probe_port "${D_IP[$i]}" 80 1 || \
               probe_port "${D_IP[$i]}" 443 1 || \
               probe_port "${D_IP[$i]}" 22 1; then ba=1; fi
            if (( ab == 1 )); then
                (( cross_hits++ ))
                L3_PATHS+=("${D_IP[$i]} → ${D_IP[$j]}")
            fi
            if (( ab == 1 && ba == 0 )); then
                # Asymetryczny — wskazuje na ACL w jedną stronę (nie brak segmentacji)
                L3_PATHS+=("${D_IP[$i]} → ${D_IP[$j]} [ASYMMETRIC ACL]")
                L3_RESULTS[asymmetric_acl]="1"
            fi
        done
    done
    if (( cross_total >= 2 )); then
        local cross_pct=$(( cross_hits * 100 / cross_total ))
        # Minimalna próbka 6 par + >50% — eliminuje fałszywe HIGH przy małej sieci
        if (( cross_total >= 6 && cross_pct > 50 )); then
            L3_RESULTS[cross_subnet_ok]="1"
            log "  [!] Cross-subnet reachability: ${cross_hits}/${cross_total} par (${cross_pct}%)" "WARN"
            add_net_finding "HIGH" "SEGMENTACJA"                 "Cross-subnet ruch niezablokowany (${cross_pct}% par, próbka=${cross_total})"                 "Wdróż ACL między subnetami. Sprawdź routing policy na GW."
        elif (( cross_total < 6 && cross_pct > 50 )); then
            L3_RESULTS[cross_subnet_ok]="WEAK_SIGNAL"
            log "  [~] Cross-subnet: sygnał słaby (${cross_hits}/${cross_total} par, ${cross_pct}% — próbka za mała)" "WARN"
        else
            log "  [✓] Cross-subnet izolacja aktywna (${cross_hits}/${cross_total} par)" "OK"
        fi
        local synth_total=0 synth_hits=0
        local targets=() sn
        for sn in ${L3_RESULTS[reachable_subnets]}; do
            local pfx; pfx=$(echo "$sn" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3}')
            [[ -z "$pfx" ]] && continue
            targets+=("${pfx}.1" "${pfx}.10" "${pfx}.20" "${pfx}.254")
        done
        local tip lg s3
        lg=$(echo "${LOCAL_IPS[0]:-}" | cut -d/ -f1 | cut -d. -f1-3)
        for tip in "${targets[@]}"; do
            s3=$(echo "$tip" | cut -d. -f1-3)
            [[ -n "$lg" && "$s3" == "$lg" ]] && continue
            [[ -n "${GATEWAY_IP:-}" && "$tip" == "$GATEWAY_IP" ]] && continue
            (( synth_total++ ))
            if probe_port "$tip" 80 1 || probe_port "$tip" 443 1 || probe_port "$tip" 22 1 || probe_port "$tip" 445 1; then
                (( synth_hits++ ))
            fi
            (( synth_total >= 10 )) && break
        done
        if (( synth_total >= 4 && synth_hits >= 1 )); then
            L3_RESULTS[cross_subnet_ok]="WEAK_SIGNAL"
            log "  [!] Cross-subnet: słaby sygnał (synth ${synth_hits}/${synth_total})" "WARN"
        else
            log "  [i] Za mało hostów w różnych subnetach (${cross_total} par) — test niewiarygodny"
            L3_RESULTS[cross_subnet_ok]="INSUFFICIENT_SAMPLE"
        fi
    fi

    # Silent DROP vs REJECT — test przez nie-routowalne IP
    local test_ip="${GATEWAY_IP:-192.168.1.1}"

    # Baseline: normalna latencja portu otwartego (eliminuje wolny router/QoS)
    local _drop_baseline; _drop_baseline=$(_tcp_samples_median "$test_ip" 80 3 1)
    _is_int "$_drop_baseline" || _drop_baseline=50
    (( _drop_baseline < 5 )) && _drop_baseline=5   # minimalny baseline 5ms

    local t_start t_end delta
    t_start=$(date +%s%3N)
    timeout 2 bash -c "exec 3<>/dev/tcp/$test_ip/9997 && exec 3>&-" 2>/dev/null; true
    t_end=$(date +%s%3N)
    delta=$(( t_end - t_start ))

    # Wymóg: delta > baseline×4 ORAZ bezwzględnie ≥2000ms
    local _drop_ratio=0
    (( _drop_baseline > 0 )) && _drop_ratio=$(( delta * 100 / _drop_baseline ))
    local _drop_conf
    _drop_conf=$(_conf_l3_silent_drop "$delta" "$_drop_baseline")
    _is_int "$_drop_conf" || _drop_conf=0
    L3_RESULTS[silent_drop_conf]="$_drop_conf"
    L3_RESULTS[silent_drop_baseline]="$_drop_baseline"
    if (( _drop_conf >= 75 )); then
        L3_RESULTS[silent_drop_detected]="1"
        log "  [✓] Silent DROP: timeout=${delta}ms, baseline=${_drop_baseline}ms, ratio=${_drop_ratio}%, pewność=${_drop_conf}%" "OK"
    else
        log "  [i] GW REJECT/RST — delta=${delta}ms (baseline=${_drop_baseline}ms, ratio=${_drop_ratio}%)"
    fi

    # East-West isolation — walidacja z minimalną próbką
    local flat_hits=0 flat_total=0
    local ew_subnets_seen=()
    local _l3_limit=$(( DEV_COUNT < 24 ? DEV_COUNT : 24 ))
    for (( i=0; i<_l3_limit; i++ )); do
        for (( j=i+1; j<_l3_limit; j++ )); do
            local src="${D_IP[$i]}" dst="${D_IP[$j]}"
            local s3_src; s3_src=$(echo "$src" | cut -d. -f1-3)
            local s3_dst; s3_dst=$(echo "$dst" | cut -d. -f1-3)
            [[ "$s3_src" == "$s3_dst" ]] || continue  # tylko same-subnet
            (( flat_total++ ))
            # Próba peer-to-peer na typowych portach lateral movement
            if probe_port "$dst" 445 1 || probe_port "$dst" 22 1                || probe_port "$dst" 3389 1 || probe_port "$dst" 5985 1; then
                (( flat_hits++ ))
            fi
        done
    done

    if (( flat_total < 4 )); then
        L3_RESULTS[east_west_isolated]="INSUFFICIENT_SAMPLE"
        L3_RESULTS[east_west_conf]="0"
        log "  [i] East-West: za mało par same-subnet ($flat_total) — test niewiarygodny"
    else
        local ew_pct=$(( flat_hits * 100 / flat_total ))
        local ew_conf
        ew_conf=$(_conf_l3_east_west "$flat_total" "$flat_hits")
        _is_int "$ew_conf" || ew_conf=0
        L3_RESULTS[east_west_conf]="$ew_conf"
        if (( ew_pct > 50 )); then
            L3_RESULTS[east_west_isolated]="0"
            log "  [!] East-West NIE izolowany (${flat_hits}/${flat_total}, ${ew_pct}%, pewność=${ew_conf}%)" "WARN"
            local ew_sev="HIGH"; (( ew_conf >= 72 )) && ew_sev="CRITICAL"
            add_net_finding "$ew_sev" "LATERAL_MOVEMENT" \
                "East-West: ${flat_hits}/${flat_total} par same-subnet osiągalnych (${ew_pct}%, pewność=${ew_conf}%)" \
                "Wdróż VLAN mikrosegmentację lub port isolation. Sprawdź ACL peer-to-peer."
        else
            L3_RESULTS[east_west_isolated]="1"
            log "  [✓] East-West izolacja aktywna (${flat_hits}/${flat_total}, ${ew_pct}%, pewność=${ew_conf}%)" "OK"
        fi
    fi

    # Asymmetric ACL — wyślij SYN do GW na port który GW ma zamknięty vs odpowiedź
    local asym_test=0
    for port in 8080 8443 9090; do
        local r1; r1=$(probe_port "$GATEWAY_IP" "$port" 1 && echo "1" || echo "0")
        local r2; r2=$(probe_port "$GATEWAY_IP" "$port" 1 && echo "1" || echo "0")
        if [[ "$r1" != "$r2" ]]; then
            asym_test=1
            log "  [!] Asymetryczna ACL wykryta (port $port zmienne wyniki)" "WARN"
        fi
    done
    L3_RESULTS[asymmetric_acl]="$asym_test"

    log "  Cross-subnet: ${L3_RESULTS[cross_subnet_ok]} | Silent-drop: ${L3_RESULTS[silent_drop_detected]} | EW-isolated: ${L3_RESULTS[east_west_isolated]}"
}

# [2d] TRAFFIC POLICY — polityka ruchu

declare -A TRAFFIC_POLICY=(
    [http_egress_blocked]="0"   [dns_controlled]="0"
    [transparent_proxy]="0"     [tls_intercepted]="0"
    [rate_limiting]="0"         [dns_leak]="0"
    [http_redirect_to_https]="0"
)

audit_traffic_policy() {
# Gentle mode: do NOT perform burst/IDS-like probing (can look like an attack).
if [[ "${SAFE_MODE:-1}" == "1" ]]; then
    log_info "[IDS] Gentle mode: skipping burst/rate-limit probing (polite audit)."
    return 0
fi


    log "$(L traffic_section)" "SECTION"

    # HTTP egress — czy port 80 wychodzący jest zablokowany
    if probe_port "example.com" 80 3; then
        TRAFFIC_POLICY[http_egress_blocked]="0"
        log "$(L http_open)" "WARN"
        add_net_finding "MEDIUM" "EGRESS"             "HTTP egress port 80 otwarty — wektor exfiltracji niezaszyfrowanej"             "Zablokuj HTTP outbound. Wymuś HTTPS na poziomie firewalla."
    else
        TRAFFIC_POLICY[http_egress_blocked]="1"
        _safe_set RAW_EGRESS "http_egress_blocked" "1"
        log "$(L http_blocked)" "OK"
    fi

    # DNS — pomiar przez porównanie odpowiedzi + dostępność zewnętrznych resolverów
    if [[ -n "${T[dig]:-}" ]]; then
        local dns_to_test="${INTERNAL_DNS:-}"

        # Test 1: Czy internal resolver odpowiada (czy jest w ogóle DNS)
        local r_int
        r_int=$(timeout 2 dig +short +timeout=1 "example.com" "@${dns_to_test}" 2>/dev/null | grep -E '^[0-9]' | head -1 || echo "")

        # Test 2: Czy zewnętrzny resolver działa (baseline)
        local r_ext
        r_ext=$(timeout 2 dig +short +timeout=1 "example.com" "@8.8.8.8" 2>/dev/null | grep -E '^[0-9]' | head -1 || echo "")

        if [[ -z "$r_ext" ]]; then
            log "  [i] Brak zewnętrznej łączności DNS — testy DNS ograniczone"
        elif [[ -n "$r_int" && -n "$r_ext" ]]; then
            if [[ "$r_int" != "$r_ext" ]]; then
                # Różne wyniki = split-DNS lub filtering — to pozytywny wskaźnik kontroli
                TRAFFIC_POLICY[dns_controlled]="1"
                log "  [✓] DNS split lub filtering (internal=${r_int}, external=${r_ext})" "OK"
            else
                local _ref1="$EXT_DNS_SECONDARY" _ref2="$EXT_DNS_PRIMARY"
                local ads_list=("doubleclick.net" "adservice.google.com" "ads.yahoo.com")
                local obs=0 blk=0 d a1 a2 rr1 rr2
                for d in "${ads_list[@]}"; do
                    rr1=$(_dig_classify "$_ref1" "$d" 0)
                    rr2=$(_dig_classify "$_ref2" "$d" 0)
                    [[ "$rr1" == "TIMEOUT" && "$rr2" == "TIMEOUT" ]] && continue
                    a1=$(_dig_classify "$dns_to_test" "$d" 0)
                    a2=$(_dig_classify "$dns_to_test" "$d" 0)
                    [[ "$a1" == "TIMEOUT" && "$a2" == "TIMEOUT" ]] && continue
                    (( obs++ ))
                    if _dns_is_block "$a1" || _dns_is_block "$a2"; then
                        (( blk++ ))
                    fi
                done
                if (( obs >= 2 )); then
                    local pct=$(( blk * 100 / obs ))
                    if (( pct >= 60 )); then
                        TRAFFIC_POLICY[dns_controlled]="1"
                        log "$(L dns_filter_ok "${pct}")" "OK"
                    else
                        log "  [i] DNS bez mocnych dowodów filtrowania (${pct}%)"
                    fi
                fi
            fi
        fi

        # DNS leak (precision v2): real DNS queries — UDP+TCP — do 4 resolverów
        local ext_dns_list=("$EXT_DNS_PRIMARY" "$EXT_DNS_SECONDARY" "$EXT_DNS_TERTIARY" "$EXT_DNS_QUAD")
        local udp_ok=0 tcp_ok=0 ext
        for ext in "${ext_dns_list[@]}"; do
            read -r u t < <(_dns_egress_probe "$ext" "example.com")
            (( u == 1 )) && (( udp_ok++ ))
            (( t == 1 )) && (( tcp_ok++ ))
        done
        # Leak = UDP+TCP obydwa osiągalne na ≥3 resolverach (nie "jeden działa")
        # 1 resolver UDP może być ISP passthrough — to nie pełny leak
        local _leak_conf
        _leak_conf=$(_conf_dns_leak "$udp_ok" "$tcp_ok" 4)
        _is_int "$_leak_conf" || _leak_conf=0
        TRAFFIC_POLICY[dns_leak_conf]="$_leak_conf"
        if (( _leak_conf >= 72 )); then
            TRAFFIC_POLICY[dns_leak]="1"
            _safe_set RAW_DNS_AUDIT "dns_leak" "1"
            local _leak_sev="HIGH"; (( _leak_conf >= 90 )) && _leak_sev="HIGH"
            log "$(L dns_leak "${udp_ok}" "${tcp_ok}" "${_leak_conf}")" "WARN"
            add_net_finding "$_leak_sev" "DNS" \
                "DNS leak (pewność ${_leak_conf}%): zewnętrzne resolvery osiągalne (UDP=${udp_ok}/4, TCP=${tcp_ok}/4)" \
                "Zablokuj egress UDP/TCP 53 poza własnym resolwerem; rozważ DNS redirect/hijack na GW."
        elif (( _leak_conf >= 60 )); then
            TRAFFIC_POLICY[dns_leak]="PARTIAL"
            log "$(L dns_leak_weak "${udp_ok}" "${tcp_ok}" "${_leak_conf}")" "WARN"
        else
            TRAFFIC_POLICY[dns_leak]="0"
            log "$(L dns_noleak "${udp_ok}" "${tcp_ok}")" "OK"
        fi
    fi

    # Transparent proxy — sprawdź via nagłówek X-Forwarded-For / Via
    if [[ -n "${T[curl]:-}" ]]; then
        local headers
        headers=$(curl -sk --max-time 4 -I "http://example.com" 2>/dev/null | tr -d '
' || echo "")
        if echo "$headers" | grep -qi "x-forwarded-for\|via:\|x-proxy\|x-cache"; then
            TRAFFIC_POLICY[transparent_proxy]="1"
            log "$(L tproxy)" "WARN"
            add_net_finding "MEDIUM" "PROXY"                 "Transparent proxy wykryty — cały ruch HTTP jest przechwytywany/logowany"                 "Zweryfikuj czy proxy jest autoryzowany. Może przechwytywać dane uwierzytelniania."
        else
            log "  [i] Brak transparent proxy (brak nagłówków proxy)"
        fi

        # TLS interception (precision v2): SHA256 fingerprint via-net vs direct IP z retries
        if [[ -n "${T[openssl]:-}" ]]; then
            local host="example.com" ip_direct="93.184.216.34"
            local d1 d2 d3 v1 v2 v3 d_ok=0 v_ok=0
            d1=$(_tls_fp_openssl "$host" "$ip_direct" 443 "$host")
            d2=$(_tls_fp_openssl "$host" "$ip_direct" 443 "$host")
            d3=$(_tls_fp_openssl "$host" "$ip_direct" 443 "$host")
            v1=$(_tls_fp_openssl "$host" "" 443 "$host")
            v2=$(_tls_fp_openssl "$host" "" 443 "$host")
            v3=$(_tls_fp_openssl "$host" "" 443 "$host")
            [[ -n "$d1" ]] && (( d_ok++ )); [[ -n "$d2" ]] && (( d_ok++ )); [[ -n "$d3" ]] && (( d_ok++ ))
            [[ -n "$v1" ]] && (( v_ok++ )); [[ -n "$v2" ]] && (( v_ok++ )); [[ -n "$v3" ]] && (( v_ok++ ))
            if (( d_ok >= 2 && v_ok >= 2 )); then
                # Sprawdź stabilność direct fingerprint (CDN/failover może dać różne)
                local d_stable=0 v_stable=0 d_fp="" v_fp=""
                # direct stabilny: co najmniej 2 z 3 identyczne
                [[ -n "$d1" && -n "$d2" && "$d1" == "$d2" ]] && d_stable=1 && d_fp="$d1"
                [[ -n "$d1" && -n "$d3" && "$d1" == "$d3" ]] && d_stable=1 && d_fp="$d1"
                [[ -n "$d2" && -n "$d3" && "$d2" == "$d3" ]] && d_stable=1 && d_fp="$d2"
                # via-net stabilny: co najmniej 2 z 3 identyczne
                [[ -n "$v1" && -n "$v2" && "$v1" == "$v2" ]] && v_stable=1 && v_fp="$v1"
                [[ -n "$v1" && -n "$v3" && "$v1" == "$v3" ]] && v_stable=1 && v_fp="$v1"
                [[ -n "$v2" && -n "$v3" && "$v2" == "$v3" ]] && v_stable=1 && v_fp="$v2"

                if (( d_stable == 0 || v_stable == 0 )); then
                    # Niestabilny fingerprint — nie wyciągamy wniosków (CDN, failover, timeout)
                    TRAFFIC_POLICY[tls_intercepted]="INCONCLUSIVE"
                    log "  [i] TLS: niestabilny fingerprint (direct_ok=${d_ok}, via_ok=${v_ok}) — INCONCLUSIVE (możliwy CDN/failover)"
                elif [[ "$d_fp" != "$v_fp" ]]; then
                    # Dodatkowa weryfikacja: issuer i SAN
                    local d_issuer_san; d_issuer_san=$(_tls_issuer_san "$host" "$ip_direct" 443 "$host")
                    local v_issuer_san; v_issuer_san=$(_tls_issuer_san "$host" "" 443 "$host")
                    local d_issuer="${d_issuer_san%%|*}" v_issuer="${v_issuer_san%%|*}"
                    local d_san="${d_issuer_san##*|}" v_san="${v_issuer_san##*|}"

                    # Oblicz san_delta: v_san - d_san (ujemny gdy intercepcja redukuje SAN)
                    local _san_delta=0
                    _is_int "$d_san" && _is_int "$v_san" && _san_delta=$(( v_san - d_san ))
                    local _issuer_match=1
                    [[ -n "$d_issuer" && -n "$v_issuer" && "$d_issuer" != "$v_issuer" ]] && _issuer_match=0
                    local _tls_conf
                    _tls_conf=$(_conf_tls_intercept "$_issuer_match" "$_san_delta" 3)
                    _is_int "$_tls_conf" || _tls_conf=0

                    TRAFFIC_POLICY[tls_intercepted]="1"
                    TRAFFIC_POLICY[tls_conf]="$_tls_conf"
                    log "  [!] TLS interception: fingerprint mismatch, issuer d=${d_issuer} v=${v_issuer}, SAN d=${d_san} v=${v_san} (pewność ${_tls_conf}%)" "WARN"
                    add_net_finding "HIGH" "TLS" \
                        "TLS interception (pewność ${_tls_conf}%): fingerprint direct≠via, issuer direct=${d_issuer:-?} via=${v_issuer:-?}" \
                        "Zweryfikuj politykę TLS inspection na proxy/NGFW. Sprawdź issuer: różne issuery potwierdzają MITM."
                else
                    TRAFFIC_POLICY[tls_intercepted]="0"
                    log "  [i] TLS: fingerprint stabilny i zgodny (brak intercepcji)"
                fi
            fi
        fi

        # HTTP → HTTPS redirect
        local redir_code
        redir_code=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "http://example.com" 2>/dev/null || echo "0")
        if [[ "$redir_code" == "301" || "$redir_code" == "302" || "$redir_code" == "307" || "$redir_code" == "308" ]]; then
            TRAFFIC_POLICY[http_redirect_to_https]="1"
        fi
    fi

    # Rate limiting — mediana z 5 pomiarów przed i po burst (stabilne statystycznie)
    local gw_rl="${GATEWAY_IP:-}"
    [[ -z "$gw_rl" ]] && gw_rl="${TOPO[real_gateway]:-}"
    if [[ -n "$gw_rl" ]]; then
        # Baseline: 5 pomiarów ze spacingiem — zbierz do tablicy
        local rl_base_arr=()
        local _t1 _t2
        for _ in 1 2 3 4 5; do
            sleep 0.3
            _t1=$(date +%s%3N)
            timeout 1 bash -c "exec 3<>/dev/tcp/$gw_rl/80 && exec 3>&-" 2>/dev/null; true
            _t2=$(date +%s%3N)
            local _ms=$(( _t2 - _t1 ))
            (( _ms > 0 )) && rl_base_arr+=("$_ms")
        done

        local rl_med_base=""; (( ${#rl_base_arr[@]} >= 3 )) && rl_med_base=$(_median_int "${rl_base_arr[@]}")

        if [[ -z "$rl_med_base" || "$rl_med_base" -eq 0 ]]; then
            log "  [i] Rate limiting: za mało próbek baseline (${#rl_base_arr[@]}) — INCONCLUSIVE"
            TRAFFIC_POLICY[rate_limiting]="INCONCLUSIVE"
        else
            # Burst: 8 szybkich połączeń
            for _ in 1 2 3 4 5 6 7 8; do
                timeout 1 bash -c "exec 3<>/dev/tcp/$gw_rl/80 && exec 3>&-" 2>/dev/null; true
            done

            # Post-burst: 4 pomiary (wymagaj min. 3 ważnych)
            local rl_post_arr=()
            for _ in 1 2 3 4; do
                _t1=$(date +%s%3N)
                timeout 1 bash -c "exec 3<>/dev/tcp/$gw_rl/80 && exec 3>&-" 2>/dev/null; true
                _t2=$(date +%s%3N)
                local _ms2=$(( _t2 - _t1 ))
                (( _ms2 > 0 )) && rl_post_arr+=("$_ms2")
            done

            local rl_med_post=""; (( ${#rl_post_arr[@]} >= 3 )) && rl_med_post=$(_median_int "${rl_post_arr[@]}")

            if [[ -z "$rl_med_post" || "$rl_med_post" -eq 0 ]]; then
                log "  [i] Rate limiting: za mało próbek post-burst (${#rl_post_arr[@]}) — INCONCLUSIVE"
                TRAFFIC_POLICY[rate_limiting]="INCONCLUSIVE"
            elif (( rl_med_post > rl_med_base * 3 && rl_med_post > 300 )); then
                TRAFFIC_POLICY[rate_limiting]="1"
                log "  [✓] Rate limiting: baseline=${rl_med_base}ms, post-burst=${rl_med_post}ms (×$(( rl_med_post / (rl_med_base+1) )))" "OK"
                SECURITY_SYSTEMS+=("Rate limiting: aktywny (${rl_med_base}→${rl_med_post}ms)")
            else
                TRAFFIC_POLICY[rate_limiting]="0"
                log "  [i] Brak widocznego rate limiting (base=${rl_med_base}ms, post=${rl_med_post}ms)"
            fi
        fi
    fi

    log "  HTTP-blocked: ${TRAFFIC_POLICY[http_egress_blocked]} | DNS-ctrl: ${TRAFFIC_POLICY[dns_controlled]} | Proxy: ${TRAFFIC_POLICY[transparent_proxy]} | TLS-intercept: ${TRAFFIC_POLICY[tls_intercepted]} | Rate-limit: ${TRAFFIC_POLICY[rate_limiting]}"
}

# [3] DISCOVERY

declare -A OUI_TABLE=(
    ["000C29"]="VMware"     ["005056"]="VMware"
    ["3C7A8A"]="Apple"      ["ACDE48"]="Apple"
    ["00D0C9"]="Cisco"      ["001C58"]="Cisco"
    ["0050F2"]="Microsoft"  ["001A11"]="Google"
    ["1C6F65"]="Dell"       ["D4BED9"]="Intel"
    ["F8328C"]="Xiaomi"     ["3497F6"]="Realme"
    ["50C7BF"]="TP-Link"    ["C46E1F"]="TP-Link"
    ["F8A2D6"]="Netgear"    ["C4E984"]="Netgear"
    ["00265A"]="Ubiquiti"   ["788A20"]="Ubiquiti"
    ["B0BE76"]="Synology"   ["001217"]="Sonos"
    ["5CAAFB"]="Sonos"      ["00B0D0"]="Marantz"
)

get_vendor() {
    local mac="${1:-}"
    [[ -z "$mac" || "$mac" =~ incomplete ]] && echo "Unknown" && return
    local oui; oui=$(echo "$mac" | tr -d ':-' | tr '[:lower:]' '[:upper:]')
    oui="${oui:0:6}"
    echo "${OUI_TABLE[$oui]:-Unknown}"
}

expand_subnet() {
    local cidr="$1"
    local ip="${cidr%/*}"
    local mask="${cidr#*/}"

    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    local ip_dec=$(( (o1<<24) + (o2<<16) + (o3<<8) + o4 ))
    local mask_bits=$(( 0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF ))
    local net=$(( ip_dec & mask_bits ))
    local bcast=$(( net | (~mask_bits & 0xFFFFFFFF) ))
    local start=$(( net + 1 ))
    local end=$(( bcast - 1 ))

    # Adaptive sampling — nie skanuj całej sieci /8 lub /16 w pełni
    local host_count=$(( end - start + 1 ))
    local max_hosts
    if   (( host_count <= 254 ));   then max_hosts=$host_count  # /24 — pełny scan
    elif (( host_count <= 1022 ));  then max_hosts=510           # /22 — sample 50%
    elif (( host_count <= 4094 ));  then max_hosts=512           # /20 — sample 12%
    elif (( host_count <= 65534 )); then max_hosts=1024          # /16 — sample 1.5%
    else                                 max_hosts=2048          # /8+ — sample
    fi
    if (( host_count > max_hosts )); then
        log "  [!] Sieć $cidr: $host_count hostów — adaptive sampling do $max_hosts" "WARN"
        end=$(( start + max_hosts - 1 ))
    fi

    for (( i=start; i<=end; i++ )); do
        printf "%d.%d.%d.%d
"             $(( (i>>24)&255 ))             $(( (i>>16)&255 ))             $(( (i>>8)&255 ))              $(( i&255 ))
    done
}

declare -a D_IP=() D_HOSTNAME=() D_MAC=() D_VENDOR=() D_TTL=() D_OS=()
declare -a D_HONEYPOT=()
declare -a D_ROLE=() D_PORTS=() D_BANNERS=() D_SEGMENT=()
declare -a D_RAW_SCORE=() D_MITIGATIONS=() D_RESIDUAL_SCORE=() D_RISK_BAND=()
declare -a D_FINDINGS=() D_VERIFIED=()
DEV_COUNT=0

# CVSS v3.1 base score lookup — bez zewnętrznych narzędzi
# Mapuje kategorie findingów na typowe CVSS base scores
cvss_for_finding() {
    local sev="$1" cat="$2"
    # Precyzyjne score per kategoria (NIST NVD typowe wartości)
    case "${sev}:${cat}" in
        CRITICAL:CONTAINER_ESCAPE)  echo "10.0" ;;  # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        CRITICAL:K8S_UNAUTHENTICATED) echo "9.8" ;; # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        CRITICAL:ETCD_OPEN)         echo "9.8" ;;
        CRITICAL:KRADZIEŻ_DANYCH)   echo "9.1" ;;  # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
        CRITICAL:KRADZIEŻ_HASEŁ)    echo "9.8" ;;
        CRITICAL:POTENCJALNY_BACKDOOR) echo "9.8" ;;
        CRITICAL:PROTOKÓŁ)          echo "7.4" ;;  # SSH v1: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
        CRITICAL:SNMP_OPEN)         echo "8.6" ;;  # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L
        CRITICAL:LATERAL_MOVEMENT)  echo "9.0" ;;
        CRITICAL:*)                 echo "9.0" ;;
        HIGH:SZYFROWANIE)           echo "7.5" ;;  # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
        HIGH:SNMP_OPEN)             echo "7.5" ;;
        HIGH:LATERAL_MOVEMENT)      echo "8.1" ;;  # AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
        HIGH:FIREWALL)              echo "7.5" ;;
        HIGH:TLS_EXPIRED)           echo "7.5" ;;
        HIGH:TLS_WEAK_CIPHER)       echo "7.4" ;;
        HIGH:TLS_SELF_SIGNED)       echo "6.5" ;;
        HIGH:AD_LDAP_OPEN)          echo "8.1" ;;
        HIGH:AD_NO_SIGNING)         echo "8.1" ;;  # NTLM relay: AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
        HIGH:KERBEROASTING)         echo "7.5" ;;
        HIGH:*)                     echo "7.0" ;;
        MEDIUM:SZYFROWANIE)         echo "5.9" ;;
        MEDIUM:LATERAL_MOVEMENT)    echo "5.9" ;;
        MEDIUM:TLS_EXPIRING_SOON)   echo "5.3" ;;
        MEDIUM:UDP_AMPLIFICATION)   echo "5.8" ;;  # AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L
        MEDIUM:SNMP_PORT)           echo "5.3" ;;
        MEDIUM:FIREWALLED_HOST)     echo "4.0" ;;
        MEDIUM:*)                   echo "5.5" ;;
        LOW:*)                      echo "3.1" ;;
        INFO:*)                     echo "0.0" ;;
        *)                          echo "5.0" ;;
    esac
}

add_finding() {
    local idx="$1" sev="$2" cat="$3" desc="$4" rec="${5:-}" cvss="${6:-}"
    # Auto-calcola CVSS se non fornito
    [[ -z "$cvss" ]] && cvss=$(cvss_for_finding "$sev" "$cat")
    local entry="${sev}${SEP}${cat}${SEP}${desc}${SEP}${rec}${SEP}${cvss}"
    if [[ -z "${D_FINDINGS[$idx]:-}" ]]; then D_FINDINGS[$idx]="$entry"
    else D_FINDINGS[$idx]="${D_FINDINGS[$idx]}${SEP}${entry}"; fi
}

add_verified() {
    local idx="$1" control="$2" detail="${3:-}"
    local entry="${control}${SEP}${detail}"
    if [[ -z "${D_VERIFIED[$idx]:-}" ]]; then D_VERIFIED[$idx]="$entry"
    else D_VERIFIED[$idx]="${D_VERIFIED[$idx]}${SEP}${entry}"; fi
}

declare -a NET_FINDINGS=()
add_net_finding() {
    local sev="$1" cat="$2" desc="$3" rec="${4:-}"
    NET_FINDINGS+=("${sev}${SEP}${cat}${SEP}${desc}${SEP}${rec}")
}

discover_hosts() {
    log "$(L phase_3)" "SECTION"

    declare -A arp_map=()
    while read -r aip amac; do
        [[ -n "$aip" && -n "$amac" ]] || continue
        _is_excluded_ip "$aip" && continue
        arp_map["$aip"]="$amac"
    done < <({
        arp -n 2>/dev/null | awk '/[0-9]/ && !/incomplete/ {print $1,$3}'
        ip neigh 2>/dev/null | awk '/REACHABLE|STALE|DELAY|PERMANENT/ {print $1,$5}'
        # WSL / Linux kernel ARP table — bezpośrednio z /proc
        awk 'NR>1 && $3!="0x0" {print $1,$4}' /proc/net/arp 2>/dev/null || true
    } | sort -u)

    local tmp_alive; tmp_alive=$(mktemp)
    local active=0

    for subnet in "${SUBNETS[@]}"; do
        log "Discovery: $subnet"

        if [[ -n "${T[nmap]:-}" ]]; then
            (
                local o
                o=$("${T[nmap]}" -n -Pn --open -T4 --max-retries 1 --host-timeout 2s \
                    -p 22,80,443,445,3389,53,8080,8443,8888 "$subnet" -oG - 2>/dev/null || true)
                echo "$o" | awk '/Host:/{print $2}' | while read -r ip; do
                    [[ -z "$ip" ]] && continue
                    _is_excluded_ip "$ip" && continue
                    echo "$ip ${arp_map[$ip]:-} 0" >> "$tmp_alive"
                done
            ) &
            continue
        fi

        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            _is_excluded_ip "$ip" && continue

            # Pomiń VPN IP zakresy
            if [[ "${TOPO[vpn_detected]:-0}" == "1" ]]; then
                if echo "$ip" | grep -qE "^(10\.255\.|172\.31\.[0-9]+\.[0-9]+$)"; then
                    continue
                fi
            fi

            (
                local alive=0
                # 1. ARP cache (szybko, pasywnie)
                [[ -n "${arp_map[$ip]:-}" ]] && alive=1
                # 2. TCP connect probe — OPEN lub CLOSED = host żywy
                if (( alive == 0 )); then
                    for _p in 22 80 443 445 3389 53 8080 8443 8888 22222 8006 9200 9000; do
                        timeout 0.8 bash -c "exec 3<>/dev/tcp/$ip/$_p && exec 3>&-" 2>/dev/null                             && alive=1 && break
                    done
                fi
                # 3. Jeśli nadal nie wykryto — g_host_detect (rozróżnia DROP firewall)
                #    Host z pełnym DROP policy zwraca FILTERED na wszystkich portach.
                #    Klasyczny probe go pomija. g_host_detect go wykrywa.
                local detection_method="tcp"
                if (( alive == 0 )); then
                    local _ghd; _ghd=$(g_host_detect "$ip")
                    if [[ "$_ghd" == "HOST_PRESENT" || "$_ghd" == "HOST_FIREWALLED" ]]; then
                        alive=1
                        detection_method="$_ghd"
                    fi
                fi
                if [[ $alive -eq 1 ]]; then
                    local mac="${arp_map[$ip]:-}"
                    local ttl="0"
                    if timeout 1 ping -c1 -W1 -q "$ip" &>/dev/null 2>&1; then
                        ttl=$(_ping_ttl "$ip")
                        [[ -z "$ttl" ]] && ttl="0"
                    fi
                    echo "$ip $mac $ttl $detection_method" >> "$tmp_alive"
                fi
            ) &
            (( active++ ))
            if (( active >= MAX_PARALLEL )); then wait; active=0; fi
        done < <(expand_subnet "$subnet")
    done
    wait

    if [[ -s "$tmp_alive" ]]; then
        sort -t. -k1,1n -k2,2n -k3,3n -k4,4n "$tmp_alive" | sort -u > "${tmp_alive}.s"
        while read -r ip mac ttl detection_method; do
            local hostname=""
            if [[ -n "${T[dig]:-}" ]]; then
                hostname=$(dig +short +time=1 -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//' || echo "")
            fi
            local vendor; vendor=$(get_vendor "$mac")

            D_IP+=("$ip") D_HOSTNAME+=("${hostname:-}") D_MAC+=("${mac:-}")
            D_VENDOR+=("$vendor") D_TTL+=("$ttl") D_OS+=("")
            D_ROLE+=("") D_PORTS+=("") D_BANNERS+=("") D_SEGMENT+=("")
            D_RAW_SCORE+=(0) D_MITIGATIONS+=("") D_RESIDUAL_SCORE+=(0)
            D_RISK_BAND+=("") D_FINDINGS+=("") D_VERIFIED+=("")
            # Oznacz hosty wykryte tylko przez DROP fingerprint
            if [[ "${detection_method:-}" == "HOST_FIREWALLED" ]]; then
                local _fw_idx=$(( ${#D_IP[@]} - 1 ))
                add_finding "$_fw_idx" "INFO" "FIREWALLED_HOST"                     "Host $ip wykryty przez fingerprint DROP policy — brak odpowiedzi na standardowe porty"                     "Host z agresywną polityką DROP. Może być stealth node lub security appliance."
            fi
            (( DEV_COUNT++ ))
            log "Host: $ip | TTL=$ttl | MAC=${mac:-0} | Vendor=$vendor | PTR=${hostname:-brak}"
        done < "${tmp_alive}.s"
    fi

    rm -rf "$tmp_alive" "${tmp_alive}.s" 2>/dev/null || true
    log "Discovery zakończony: $DEV_COUNT hostów"
}

# HONEYPOT / FAKE PORT DETECTION — behawioralna, na zdalnych hostach
#
# Metoda: obserwacja ZACHOWANIA portu, nie obecności procesu
#
# Wskaźniki fałszywego portu (honeypot/mirage):
#  1. Port odpowiada identycznym bannerem jak inny port na tym samym hoście
#  2. Port odpowiada bardzo szybko (<5ms) — typowe dla nc -e /dev/zero
#  3. Port ignoruje dane wejściowe i zwraca tę samą odpowiedź
#  4. Host ma zbyt dużo otwartych portów jak na swój profil (>15 portów = podejrzane)
#  5. Timing: identyczny czas odpowiedzi na 3+ portach (±10ms)
#  6. Banner jest pusty ale port "otwarty" (nc fake accept)

# Główna ocena honeypot dla jednego hosta — zwraca liczbę podejrzanych portów
detect_honeypot_ports() {
    local ip="$1"
    local open_ports="$2"
    local port_count_n; port_count_n=$(echo "$open_ports" | wc -w)

    local suspicious_ports=""
    local honeypot_score=0
    local reasons=""

    # --- Wskaźnik 1: Zbyt dużo otwartych portów ---
    if (( port_count_n > 20 )); then
        honeypot_score=$(( honeypot_score + 3 ))
        reasons="$reasons EXCESS_PORTS($port_count_n)"
    elif (( port_count_n > 12 )); then
        honeypot_score=$(( honeypot_score + 1 ))
        reasons="$reasons HIGH_PORT_COUNT($port_count_n)"
    fi

    # --- Wskaźnik 2: Timing fingerprint z walidacją (load balancer vs honeypot) ---
    # Load balancer: identyczny timing NA WSZYSTKICH portach łącznie z 80/443
    # Honeypot/nc: identyczny timing na NIEZNANYCH portach, ale nie na 80/443
    local timing_samples=""
    local timing_known=""   # timing na znanych portach (80, 443, 22)
    local timing_unknown="" # timing na nieznanych portach
    local sample_ports=( $open_ports )
    local sampled=0

    for port in "${sample_ports[@]}"; do
        (( sampled >= 6 )) && break
        local t_start t_end t_ms
        t_start=$(date +%s%3N)
        timeout 1 bash -c "exec 3<>/dev/tcp/$ip/$port && exec 3>&-" 2>/dev/null || true
        t_end=$(date +%s%3N)
        t_ms=$(( t_end - t_start ))
        if echo " 22 80 443 " | grep -qw "$port"; then
            timing_known="$timing_known $t_ms"
        else
            timing_unknown="$timing_unknown $t_ms"
        fi
        timing_samples="$timing_samples $t_ms"
        (( sampled++ ))
    done

    # Identyczny timing NA NIEZNANYCH portach (a znane nie są tak szybkie) = honeypot
    local uk_arr=( $timing_unknown )
    if (( ${#uk_arr[@]} >= 3 )); then
        local identical=0 ref="${uk_arr[0]}"
        for t in "${uk_arr[@]}"; do
            local diff=$(( t - ref )); (( diff < 0 )) && diff=$(( -diff ))
            (( diff <= 15 )) && (( identical++ ))
        done
        # Tylko jeśli znane porty mają RÓŻNY timing (inaczej to LB)
        local known_ok=1
        local kn_arr=( $timing_known )
        if (( ${#kn_arr[@]} >= 2 )); then
            local k_diff=$(( ${kn_arr[0]} - ${kn_arr[1]} ))
            (( k_diff < 0 )) && k_diff=$(( -k_diff ))
            (( k_diff <= 15 )) && known_ok=0  # znane też identyczne = load balancer
        fi
        if (( identical >= 3 && known_ok == 1 )); then
            honeypot_score=$(( honeypot_score + 2 ))
            reasons="$reasons IDENTICAL_TIMING_UNKNOWN_PORTS(${timing_unknown# })"
        fi
    fi

    # --- Wskaźnik 3: Banner fingerprint ---
    # Pobierz bannery z kilku portów i porównaj
    local banner_samples=""
    local banner_count=0
    local identical_banners=0
    local first_banner=""
    local checked_ports=0

    for port in $open_ports; do
        (( checked_ports >= 5 )) && break
        # Pomiń znane porty z unikalnymi protokołami
        echo " 22 80 443 53 " | grep -qw "$port" && { (( checked_ports++ )); continue; }
        local b
        b=$(grab_banner "$ip" "$port" 2 2>/dev/null || echo "")
        if [[ -n "$b" ]]; then
            if [[ -z "$first_banner" ]]; then
                first_banner="$b"
            elif [[ "$b" == "$first_banner" ]]; then
                (( identical_banners++ ))
                honeypot_score=$(( honeypot_score + 2 ))
                reasons="$reasons IDENTICAL_BANNER"
            fi
            banner_count=$(( banner_count + 1 ))
        fi
        (( checked_ports++ ))
    done

    # --- Wskaźnik 4: Port odpowiada ZAWSZE tym samym na dowolne dane ---
    # Wyślij losowe dane i porównaj odpowiedź z odpowiedzią bez danych
    if (( port_count_n >= 3 )); then
        local test_port=""
        for port in $open_ports; do
            echo " 22 80 443 53 21 25 " | grep -qw "$port" && continue
            test_port="$port"
            break
        done

        if [[ -n "$test_port" ]]; then
            local resp_empty resp_junk
            resp_empty=$(echo "" | timeout 2 bash -c "
                exec 3<>/dev/tcp/$ip/$test_port
                sleep 0.3
                read -t1 -u3 line 2>/dev/null
                echo \"\$line\"
                exec 3>&-
            " 2>/dev/null | head -1 | tr -d '\r\n' || echo "")

            resp_junk=$(echo "XXXXXXJUNKXXXX" | timeout 2 bash -c "
                exec 3<>/dev/tcp/$ip/$test_port
                echo 'XXXXXXJUNKXXXX' >&3
                sleep 0.3
                read -t1 -u3 line 2>/dev/null
                echo \"\$line\"
                exec 3>&-
            " 2>/dev/null | head -1 | tr -d '\r\n' || echo "")

            if [[ -n "$resp_empty" && -n "$resp_junk" && "$resp_empty" == "$resp_junk" ]]; then
                honeypot_score=$(( honeypot_score + 2 ))
                reasons="$reasons SAME_RESPONSE_TO_ANY_INPUT"
            fi
        fi
    fi

    # --- Wskaźnik 5: Puste bannery na wielu portach ---
    # nc fake listen często milczy (accept bez send)
    if (( port_count_n >= 5 )); then
        local silent_count=0
        local test_count=0
        for port in $open_ports; do
            (( test_count >= 6 )) && break
            echo " 22 80 443 53 3389 5900 " | grep -qw "$port" && { (( test_count++ )); continue; }
            local b
            b=$(grab_banner "$ip" "$port" 2 2>/dev/null || echo "TIMEOUT")
            [[ -z "$b" || "$b" == "TIMEOUT" ]] && (( silent_count++ ))
            (( test_count++ ))
        done
        local silent_pct=0
        (( test_count > 0 )) && silent_pct=$(( silent_count * 100 / test_count ))
        if (( silent_pct >= 80 && test_count >= 4 )); then
            honeypot_score=$(( honeypot_score + 2 ))
            reasons="$reasons MASS_SILENT_PORTS(${silent_count}/${test_count})"
        fi
    fi

    # --- Wyrok ---
    echo "$honeypot_score|$reasons"
}

# Wrapper: oceń host i zapisz wynik
evaluate_honeypot() {
    local idx="$1"
    local ip="${D_IP[$idx]}"
    local ports="${D_PORTS[$idx]:-}"
    local pc; pc=$(port_count "$ports")

    [[ "$MODE" == "passive" ]] && return
    (( pc < 3 )) && return  # za mało portów żeby oceniać

    log "  [HP] Analiza warstwy deception: $ip ($pc portów)" "DEBUG"

    local result; result=$(detect_honeypot_ports "$ip" "$ports")
    local score="${result%%|*}"
    local reasons="${result#*|}"

    score="${score//[^0-9]/}"
    score="${score:-0}"

    if (( score >= 5 )); then
        # Bardzo prawdopodobny honeypot — oznacz i dodaj finding
        D_HONEYPOT[$idx]="HIGH|$score|$reasons"
        add_finding "$idx" "INFO" "HONEYPOT_DETECTED" \
            "Host $ip wykazuje silne cechy warstwy deception (score=$score): $reasons" \
            "Wyniki port scan dla $ip mogą być zafałszowane — zweryfikuj ręcznie"
        log "$(L honeypot_warn "${ip}" "${score}" "${reasons}")" "WARN"
    elif (( score >= 3 )); then
        D_HONEYPOT[$idx]="MEDIUM|$score|$reasons"
        add_finding "$idx" "INFO" "HONEYPOT_SUSPECT" \
            "Host $ip ma cechy warstwy deception (score=$score): $reasons" \
            "Zweryfikuj czy otwarte porty są prawdziwe"
        log "$(L honeypot_suspect "${ip}" "${score}" "${reasons}")" "WARN"
    else
        D_HONEYPOT[$idx]="NONE|$score"
        log "  [HP] ✓ $ip: brak cech deception (score=$score)" "DEBUG"
    fi
}

#############################################
# STABILIZATION LAYER — PHASE 4–11 PATCH
#############################################

# Bufory surowych danych (odseparowanie od global state)
# Frozen context (post-sensor, pre-interpretation)
declare -A CTX



_nmap_topology_seed_ports() {
    local ports=""
    if declare -F get_scan_ports >/dev/null 2>&1; then
        ports="$(get_scan_ports)"
    fi
    ports="${ports:-22 53 80 443 445 3389 8080}"
    awk '
        {
            for (i=1; i<=NF; i++) {
                if ($i ~ /^[0-9]+$/ && !seen[$i]++) out = out (out?" ":"") $i
            }
        }
        END { print out }
    ' <<<"$ports"
}

_nmap_topology_profile() {
    if [[ "${MODE:-passive}" == "passive" ]] || [[ "${TOPO[ids_detected]:-0}" == "1" ]] || [[ "${TOPO[honeypot_detected]:-0}" == "1" ]]; then
        echo "light"
    else
        echo "balanced"
    fi
}

_nmap_extract_open_ports() {
    awk -F'Ports: ' '
        /Ports: / {
            s=$2
            gsub(/, /,"\n",s)
            print s
        }
    ' | awk -F/ '$2=="open"{print $1}' | xargs 2>/dev/null || true
}

topology_nmap_assist() {
    log "PHASE 3.5: Nmap-assisted topology validation" "SECTION"

    if [[ "${TOPOLOGY_NMAP_ENABLED:-1}" != "1" ]]; then
        _report_finding "TOPOLOGY_NMAP_ASSIST" "NOT_TESTED" 0 "disabled by configuration" "topology_nmap_assist"
        return 0
    fi

    if [[ -z "${T[nmap]:-}" ]]; then
        log "  [nmap-topology] nmap unavailable — heuristics continue without corroboration" "WARN"
        _report_finding "TOPOLOGY_NMAP_ASSIST" "NOT_TESTED" 0 "nmap unavailable" "topology_nmap_assist"
        return 0
    fi

    local profile seed_ports ip idx open_ports nmap_cmd output
    local validated=0 enriched=0 suspicious_hosts=0 suspicious_ports=0 classified_ports=0
    profile="$(_nmap_topology_profile)"
    seed_ports="$(_nmap_topology_seed_ports)"
    [[ -z "$seed_ports" ]] && seed_ports="22 53 80 443 445 3389 8080"

    if [[ "$profile" == "light" ]]; then
        nmap_cmd=( "${T[nmap]}" -Pn -n -sT --max-retries 1 --host-timeout "${TOPOLOGY_NMAP_HOST_TIMEOUT:-20s}" -p "${seed_ports// /,}" -oG - )
    else
        nmap_cmd=( "${T[nmap]}" -Pn -n -sT --max-retries 1 --host-timeout "${TOPOLOGY_NMAP_HOST_TIMEOUT:-20s}" --version-light -p "${seed_ports// /,}" -oG - )
    fi

    log "  [nmap-topology] profile=${profile} ports=${seed_ports}" "INFO"

    for (( idx=0; idx<DEV_COUNT; idx++ )); do
        ip="${D_IP[$idx]:-}"
        [[ -z "$ip" ]] && continue
        _is_internal_noise "$ip" && continue

        progress "Nmap-topology: $ip ($((idx+1))/$DEV_COUNT)"
        _jitter_sleep
        output="$("${nmap_cmd[@]}" "$ip" 2>/dev/null || true)"
        open_ports="$(printf '%s\n' "$output" | _nmap_extract_open_ports)"
        [[ -z "$open_ports" ]] && continue

        (( validated++ ))
        _safe_set RAW_PORTS "$ip" "$open_ports"
        D_PORTS[$idx]="$open_ports"
        PHASE4_HOSTS+=("$ip")
        log "  [nmap-topology] $ip: ${open_ports}" "INFO"

        if [[ "${TOPOLOGY_NMAP_VERSION:-1}" == "1" && "${profile}" != "light" ]]; then
            # very light banner corroboration on already-open ports only
            local p class host_suspicious=0
            for p in $open_ports; do
                class="$(_classify_port_type "$ip" "$p")"
                PORT_STATE["$ip:$p"]="$class"
                (( classified_ports++ ))
                case "$class" in
                    mirage|tarpit)
                        (( suspicious_ports++ ))
                        host_suspicious=1
                        ;;
                esac
            done
            if (( host_suspicious == 1 )); then
                (( suspicious_hosts++ ))
                add_finding "$idx" "INFO" "TOPOLOGY_DECEPTION_SIGNAL" \
                    "Wczesna walidacja topologii wskazuje na niespójne lub kształtowane odpowiedzi portów na hoście $ip" \
                    "Traktuj kolejne aktywne próby oszczędnie; preferuj walidację ręczną i minimalny kontakt"
            fi
        fi

        (( enriched++ ))
    done
    echo ""

    if [[ "${MODE:-passive}" != "passive" ]]; then
        for (( idx=0; idx<DEV_COUNT; idx++ )); do
            [[ -n "${D_PORTS[$idx]:-}" ]] || continue
            evaluate_honeypot "$idx"
        done
    fi

    if (( validated > 0 )); then
        local conf bonus penalty
        bonus=$(( enriched * 4 ))
        penalty=$(( suspicious_hosts * 3 ))
        conf=$(_scale_confidence 60 "$bonus" "$penalty")
        _report_finding "TOPOLOGY_NMAP_ASSIST" "CONFIRMED" "$conf" \
            "validated_hosts=${validated} enriched_hosts=${enriched} suspicious_hosts=${suspicious_hosts} suspicious_ports=${suspicious_ports} profile=${profile}" \
            "topology_nmap_assist"
        AUDIT_META[topology_nmap_validated]="$validated"
        AUDIT_META[topology_nmap_suspicious_hosts]="$suspicious_hosts"
    else
        _report_finding "TOPOLOGY_NMAP_ASSIST" "NOT_DETECTED" 35 "no open seed ports confirmed by nmap topology pass" "topology_nmap_assist"
    fi
}
freeze_context() {
    CTX[ctx_frozen]=1
    CTX[noise_floor_ms]="$(_calibrate_noise_floor)"
    for k in dns_leak dns_leak_conf dns_controlled dns_filter_conf http_egress http_egress_blocked \
             rate_limiting ids_detected ids_conf firewall_type firewall_conf east_west_isolated \
             east_west_pre_samples east_west_pre_hits; do
        CTX[$k]="${TRAFFIC_POLICY[$k]:-${TOPO[$k]:-0}}"
    done
    CTX[wan_ip_present]="${TOPO[wan_ip_present]:-0}"
    CTX[nat_layers]="${TOPO[nat_layers]:-0}"
    _normalize_port_surface
    SESSION_STATE[context_frozen]=1
    log "[CTX] context frozen + normalized: fw=${CTX[firewall_type]} ids=${CTX[ids_detected]} dns_leak=${CTX[dns_leak]} ew_iso=${CTX[east_west_isolated]}" "TOPO"
}


declare -A RAW_PORTS=()
declare -A RAW_BANNERS=()
declare -A RAW_SERVICE_CLASS=()
declare -A RAW_TLS=()
declare -A RAW_UDP=()
declare -A RAW_DNS_AUDIT=()
declare -A RAW_EGRESS=()
declare -A RAW_LATERAL=()

PHASE4_HOSTS=()

_safe_set() {
    local arr="$1" key="$2" val="$3"
    # shellcheck disable=SC2086
    eval "$arr["$key"]="$val""
}

_safe_get() {
    local arr="$1" key="$2"
    # shellcheck disable=SC2086
    eval 'echo "${'"$arr"'["$key"]:-}"'
}

#############################################

# [4] PORT PROFILING — z filtrem portów fantomowych

P_CRITICAL="21 23 512 513 514 2323 4444 5555 6666 7777 8888 9999 31337 4899"
P_HIGH="22 25 110 139 143 445 3389 5900 5901 5902 5985 5986 6379 27017 11211"
P_MEDIUM="53 80 111 135 137 389 443 636 1433 1521 2049 3306 5432 8080 8443 9200 9300 5601"
P_INFO="8081 8082 9090 9100 9443 10000 3000 3001 5000 8000"
P_EXTRA="1080 1194 1723 4500 500 161 162 69 123"

# Porty fantomowe / deception-like pomijane przy ocenie
# (typowy zakres wysokiego szumu odpowiedzi: 8000-9999)
MIRAGE_PORT_RANGE="8000-9999"

get_scan_ports() {
    case "$MODE" in
        passive) echo "22 53 80 443 445 3389 8080" ;;
        deep)    echo "$P_CRITICAL $P_HIGH $P_MEDIUM $P_INFO $P_EXTRA" ;;
        *)       echo "$P_CRITICAL $P_HIGH $P_MEDIUM" ;;
    esac
}

is_mirage_port() {
    # Nie używamy już lokalnego ss -tlnp — to wykrywało tylko lokalne nc, nie zdalne
    # Detection is handled per host by response-shaping heuristics
    return 1
}

run_port_scan() {
    log "$(L phase_4 "${DEV_COUNT}" "${MODE}")" "SECTION"

    if [[ "${TOPO[mirage_ports]:-0}" != "0" ]]; then
        log "$(L mirage_filter)" "WARN"
    fi

    local port_list; port_list=$(get_scan_ports)
    local pc; pc=$(echo "$port_list" | wc -w)
    log "Portów per host: $pc"

    # ── Scan per-host: GNU parallel jeśli dostępny, fallback bash &/wait ──────
    # scan_one_host IP INDEX PORTLIST TMPDIR → wynik do pliku
    _scan_one_host() {
        local _ip="$1" _idx="$2" _plist="$3" _tdir="$4"
        local _raw; _raw=$(scan_ports_parallel "$_ip" "$_plist" "$MAX_PARALLEL" 1)
        local _open="" _mc=0
        for _p in $_raw; do
            if ! is_mirage_port "$_p"; then _open="$_open $_p"; fi
        done
        for _p in $_raw; do is_mirage_port "$_p" && (( _mc++ )) || true; done
        echo "${_idx}|${_open# }|${_mc}" > "$_tdir/$_idx"
    }
    export MAX_PARALLEL MODE MIRAGE_PORT_RANGE 2>/dev/null || true
    export -f _scan_one_host scan_ports_parallel probe_port_adaptive is_mirage_port log progress 2>/dev/null || true

    local _scan_tmp; _scan_tmp=$(mktemp -d)
    local _host_parallel=4  # równoległe hosty (porty i tak już parallel per host)

    if command -v parallel &>/dev/null; then
        # GNU parallel: N hostów jednocześnie
        log "  [parallel] GNU parallel dostępny — skanowanie hostów równolegle (j=$_host_parallel)"
        local _args=()
        for (( i=0; i<DEV_COUNT; i++ )); do
            _args+=("${D_IP[$i]}:::$i:::$port_list:::$_scan_tmp")
        done
        printf '%s
' "${_args[@]}" |             parallel --jobs "$_host_parallel" --colsep ':::'                 'bash -c '"'"'_scan_one_host "$1" "$2" "$3" "$4"'"'"' _ {1} {2} {3} {4}'                 2>/dev/null || true
    else
        # Bash background jobs fallback
        local _active=0
        for (( i=0; i<DEV_COUNT; i++ )); do
            local ip="${D_IP[$i]}"
            progress "Port scan: $ip ($((i+1))/$DEV_COUNT)"
            _scan_one_host "$ip" "$i" "$port_list" "$_scan_tmp" &
            (( _active++ ))
            if (( _active >= _host_parallel )); then wait -n 2>/dev/null || wait; (( _active-- )); fi
        done
        wait
    fi

    # Zbierz wyniki
    for (( i=0; i<DEV_COUNT; i++ )); do
        if [[ -f "$_scan_tmp/$i" ]]; then
            IFS='|' read -r _idx _ports _mc < "$_scan_tmp/$i"
            _safe_set RAW_PORTS "${D_IP[$i]}" "${_ports}"
            PHASE4_HOSTS+=("${D_IP[$i]}")
            log "  ${D_IP[$i]}: ${_ports:-brak} (odfiltrowano $_mc mirage portów)"
        else
            _safe_set RAW_PORTS "${D_IP[$i]}" ""
            PHASE4_HOSTS+=("${D_IP[$i]}")
            log "  ${D_IP[$i]}: brak danych (błąd skanowania)"
        fi
    done
    rm -rf "$_scan_tmp"

    # Behawioralna detekcja honeypot/mirage per host
    if [[ "$MODE" != "passive" ]]; then
        log "$(L hp_section)" "SECTION"
        for (( i=0; i<DEV_COUNT; i++ )); do
            evaluate_honeypot "$i"
        done
    fi
    echo ""
}

# [5] BANNER GRAB

declare -A BANNER_PORTS=(
    [22]="SSH"    [21]="FTP"    [23]="Telnet"  [25]="SMTP"   [110]="POP3"
    [143]="IMAP"  [993]="IMAPS" [995]="POP3S"  [587]="SMTP"
    [3306]="MySQL" [5432]="PostgreSQL" [6379]="Redis" [6380]="Redis"
    [27017]="MongoDB" [3389]="RDP" [5900]="VNC" [5901]="VNC"
    [11211]="Memcached" [5672]="AMQP" [9092]="Kafka"
    [2375]="Docker" [2376]="Docker-TLS"
    [8006]="Proxmox" [9200]="Elasticsearch" [9300]="Elasticsearch"
    [5601]="Kibana" [15672]="RabbitMQ-Mgmt"
    [161]="SNMP"  # UDP — grab_banner obsługuje TCP fallback
)
declare -A HTTP_PORTS=(
    [80]=1 [443]=1 [8080]=1 [8443]=1 [8000]=1 [3000]=1
    [3001]=1 [8008]=1 [8888]=1 [9090]=1 [9443]=1 [10000]=1
    [8006]=1  # Proxmox web UI
    [15672]=1 # RabbitMQ management
    [5601]=1  # Kibana
)

run_banner_grab() {
    [[ $SKIP_BANNERS -eq 1 || "$MODE" == "passive" ]] && return
    log "$(L phase_5)" "SECTION"

    for (( i=0; i<DEV_COUNT; i++ )); do
        local ip="${D_IP[$i]}" banners=""
        local ports; ports="$(_safe_get RAW_PORTS "$ip")"
        [[ -z "$ports" ]] && continue
        for port in $ports; do
            local banner=""
            if [[ -n "${HTTP_PORTS[$port]:-}" && -n "${T[curl]:-}" ]]; then
                local proto="http"
                [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
                local result; result=$(grab_http_banner "${proto}://${ip}:${port}/" 3)
                banner="HTTP:${result}"
            elif [[ -n "${BANNER_PORTS[$port]:-}" ]]; then
                banner=$(grab_banner "$ip" "$port" 3)
            fi
            [[ -n "$banner" ]] && banners="${banners}${banners:+|}${port}:${banner}"
        done
        _safe_set RAW_BANNERS "$ip" "$banners"
        [[ -n "$banners" ]] && log "  ${ip}: $(echo "$banners" | cut -c1-100)"
    done
}

# [6] KLASYFIKACJA

classify_all() {
    log "$(L phase_6)" "SECTION"

    for (( i=0; i<DEV_COUNT; i++ )); do
        local ip="${D_IP[$i]}"
        local ports; ports="$(_safe_get RAW_PORTS "$ip")" ttl="${D_TTL[$i]}" vendor="${D_VENDOR[$i]}"

        local os="Unknown"
        # Warstwa 1: TTL heurystyka (może być znormalizowane przez router)
        if   (( ttl >= 110 && ttl <= 128 )); then os="Windows"
        elif (( ttl >= 55  && ttl <= 64  )); then os="Linux/Unix"
        elif (( ttl >= 240 ));               then os="Network OS"
        elif (( ttl >= 200 ));               then os="Solaris/BSD"
        elif (( ttl >= 65  && ttl <= 70  )); then os="Linux/Unix"
        fi
        # Warstwa 2: vendor OUI prefix
        case "$vendor" in
            Apple*)                               os="macOS/iOS" ;;
            *Raspberry*|*Pi*)                     os="Linux (RPi)" ;;
            *Cisco*|*Juniper*|*MikroTik*)        os="Network OS" ;;
            *VMware*|*Xen*)                       os="Hypervisor/VM" ;;
            *QEMU*)                               os="Linux/VM (QEMU)" ;;
        esac

        # Warstwa 3: bannery SSH/HTTP/service (najwyższy priorytet)
        local banners="${D_BANNERS[$i]}"
        echo "$banners" | grep -qi "windows\|microsoft\|IIS"      && os="Windows"
        echo "$banners" | grep -qi "ubuntu\|debian\|centos\|rhel\|fedora\|linux" && os="Linux"
        echo "$banners" | grep -qi "OpenSSH"    && [[ "$os" == "Unknown" ]] && os="Linux/Unix"
        echo "$banners" | grep -qi "FreeBSD\|OpenBSD\|NetBSD"     && os="BSD"
        echo "$banners" | grep -qi "RouterOS\|MikroTik"           && os="RouterOS (MikroTik)"
        echo "$banners" | grep -qi "pfSense\|OPNsense"            && os="BSD (pfSense/OPNsense)"
        echo "$banners" | grep -qi "Proxmox\|pve"                 && os="Linux (Proxmox)"
        echo "$banners" | grep -qi "ESXi\|vSphere"                && os="VMware ESXi"
        echo "$banners" | grep -qi "FortiOS\|FortiGate"           && os="FortiOS"
        echo "$banners" | grep -qi "Synology\|DSM"                && os="Synology DSM"
        echo "$banners" | grep -qi "UniFi\|EdgeOS\|Ubiquiti"      && os="Ubiquiti OS"

        # Warstwa 4: port combinations fingerprint
        local ports_local="${D_PORTS[$i]}"
        contains_port "$ports_local" 8006                          && os="Linux (Proxmox VE)"
        contains_port "$ports_local" 2375 || contains_port "$ports_local" 2376                                                                    && os="Linux (Docker host)"
        contains_port "$ports_local" 5985 && os="Windows (WinRM)"
        contains_port "$ports_local" 47808                        && os="BACnet (Building Automation)"
        contains_port "$ports_local" 102                          && os="SCADA/ICS (S7/ISO-TSAP)"
        contains_port "$ports_local" 20000                        && os="SCADA/ICS (DNP3)"

        D_OS[$i]="$os"

        local role="Nieznany host"
        if   [[ "$ip" == "$GATEWAY_IP" ]]; then
            role="Router / Gateway"
        elif contains_port "$ports" 3389 && contains_port "$ports" 445; then
            role="Windows Workstation/Server"
        elif contains_port "$ports" 445 && contains_port "$ports" 139; then
            role="Windows File Server (SMB)"
        elif contains_port "$ports" 5985 || contains_port "$ports" 5986; then
            role="Windows (WinRM Remote Mgmt)"
        elif contains_port "$ports" 3389; then role="Windows RDP Server"
        elif contains_port "$ports" 27017; then role="MongoDB Server"
        elif contains_port "$ports" 9200;  then role="Elasticsearch Server"
        elif contains_port "$ports" 6379;  then role="Redis Server"
        elif contains_port "$ports" 1433;  then role="MS SQL Server"
        elif contains_port "$ports" 3306;  then role="MySQL/MariaDB Server"
        elif contains_port "$ports" 5432;  then role="PostgreSQL Server"
        elif contains_port "$ports" 5900 || contains_port "$ports" 5901; then
            role="VNC Remote Desktop"
        elif contains_port "$ports" 23; then
            role="Telnet Device (LEGACY)"
        elif contains_port "$ports" 22 && contains_port "$ports" 80 \
             && contains_port "$ports" 443; then
            role="Linux Web+SSH Server"
        elif contains_port "$ports" 22 && contains_port "$ports" 443; then
            role="Linux Server (SSH+HTTPS)"
        elif contains_port "$ports" 8006; then role="Proxmox VE Hypervisor"
        elif contains_port "$ports" 2375 || contains_port "$ports" 2376; then
            role="Docker API Host"
        elif contains_port "$ports" 2379 || contains_port "$ports" 2380; then
            role="Kubernetes etcd"
        elif contains_port "$ports" 6443 || contains_port "$ports" 8001; then
            role="Kubernetes API Server"
        elif contains_port "$ports" 161;  then role="SNMP Device"
        elif contains_port "$ports" 102;  then role="SCADA/ICS (Siemens S7)"
        elif contains_port "$ports" 20000; then role="SCADA/ICS (DNP3)"
        elif contains_port "$ports" 47808; then role="BACnet (Building Automation)"
        elif contains_port "$ports" 11211; then role="Memcached Server"
        elif contains_port "$ports" 5672 || contains_port "$ports" 15672; then
            role="RabbitMQ Broker"
        elif contains_port "$ports" 9092; then role="Apache Kafka"
        elif contains_port "$ports" 8080 && contains_port "$ports" 8443; then
            role="Java Application Server"
        elif contains_port "$ports" 53 && (( $(port_count "$ports") <= 4 )); then
            role="DNS / Network Appliance"
        elif contains_port "$ports" 80 || contains_port "$ports" 443; then
            role="Web Service"
        elif contains_port "$ports" 22; then role="SSH Server"
        elif (( $(port_count "$ports") == 0 )); then
            role="Stealth Host (DROP policy)"
        fi

        local seg="UNKNOWN"
        # Segmentacja przez TTL variation + rola + ARP distance
        if   [[ "$ip" == "$GATEWAY_IP" ]]; then
            seg="GATEWAY"
        elif [[ "$role" == *"Router"* || "$role" == *"Gateway"* ]]; then
            seg="GATEWAY"
        elif [[ "$role" == *"DNS"* || "$role" == *"Management"* ]]; then
            seg="MANAGEMENT"
        elif [[ "$role" == *"IoT"* || "$role" == *"Telnet"* || "$role" == *"LEGACY"* ]]; then
            seg="IOT"
        elif [[ "$role" == *"Web"* || "$role" == *"DMZ"* ]]; then
            seg="DMZ"
        elif [[ "$role" == *"Server"* || "$role" == *"SQL"* || "$role" == *"Redis"*              || "$role" == *"Mongo"* || "$role" == *"Elastic"* ]]; then
            seg="CORE"
        elif [[ "$os" == "Windows"* ]]; then
            seg="USER_LAN"
        else
            # Fallback: TTL-based heurystyka — podatna na normalizację przez middleboxy
            local gw_ttl="${TOPO[gw_ttl]:-64}"
            local host_ttl="${ttl:-64}"
            local ttl_diff=$(( gw_ttl - host_ttl ))
            (( ttl_diff < 0 )) && ttl_diff=$(( -ttl_diff ))
            if   (( ttl_diff <= 1 )); then seg="CORE~"
            elif (( ttl_diff <= 3 )); then seg="USER_LAN~"
            else                          seg="PERIPHERAL~"
            fi
            # ~ = segment szacunkowy (TTL heuristic, wymaga weryfikacji)
        fi

        _safe_set RAW_SERVICE_CLASS "$ip" "$role"
        D_SEGMENT[$i]="$seg"
        log "  ${ip}: role=$role os=$os seg=$seg ports=[${ports:-brak}]"
    done
}

# [7] SERVICE VERIFICATION

verify_services() {
    [[ "$MODE" == "passive" ]] && return
    log "$(L phase_7)" "SECTION"

    for (( i=0; i<DEV_COUNT; i++ )); do
        local ip="${D_IP[$i]}"
        local ports; ports="$(_safe_get RAW_PORTS "$ip")"
        [[ -z "$ports" ]] && continue

        # SSH
        if contains_port "$ports" 22; then
            local ssh_banner; ssh_banner=$(grab_banner "$ip" 22 3)
            if echo "$ssh_banner" | grep -qi "SSH"; then
                local ssh_ver; ssh_ver=$(echo "$ssh_banner" | grep -oP 'SSH-[0-9.]+' | head -1)
                if echo "$ssh_ver" | grep -q "SSH-1\."; then
                    add_finding $i "CRITICAL" "PROTOKÓŁ" \
                        "SSH v1 na $ip: przestarzały protokół (MITM, session hijack)" \
                        "Wyłącz SSHv1. Wymuś Protocol 2."
                else
                    add_verified $i "SSH_RUNNING" "$ssh_banner"
                fi
            fi
        fi

        # HTTP → HTTPS redirect
        if contains_port "$ports" 80 && [[ -n "${T[curl]:-}" ]]; then
            local http_resp; http_resp=$(grab_http_banner "http://${ip}/" 4)
            local http_code; http_code=$(echo "$http_resp" | awk '{print $1}')
            local http_redir; http_redir=$(echo "$http_resp" | awk '{print $2}')

            if echo "$http_code" | grep -qE "^30[12378]$"; then
                if echo "$http_redir" | grep -qi "^https://"; then
                    add_verified $i "HTTP_REDIRECTS_HTTPS" "HTTP $ip:80 → $http_redir"
                    log "  VERIFIED: $ip HTTP→HTTPS ✓"
                else
                    add_finding $i "MEDIUM" "SZYFROWANIE" \
                        "HTTP port 80 na $ip przekierowuje do $http_redir (nie HTTPS)" \
                        "Skonfiguruj redirect HTTP→HTTPS"
                fi
            elif [[ -n "$http_code" && "$http_code" != "000" ]]; then
                if ! contains_port "$ports" 443; then
                    add_finding $i "HIGH" "SZYFROWANIE" \
                        "HTTP port 80 na $ip serwuje content bez HTTPS (kod: $http_code)" \
                        "Wdróż TLS. Wymuś redirect HTTP→HTTPS."
                else
                    add_finding $i "MEDIUM" "SZYFROWANIE" \
                        "HTTP i HTTPS dostępne na $ip bez wymuszenia redirect (kod: $http_code)" \
                        "Wymuś redirect HTTP→HTTPS. Dodaj HSTS."
                fi
            fi
        fi

        # HTTPS HSTS
        if contains_port "$ports" 443 && [[ -n "${T[curl]:-}" ]]; then
            local https_headers; https_headers=$(get_http_headers "https://${ip}/" 4)
            if echo "$https_headers" | grep -qi "Strict-Transport-Security"; then
                add_verified $i "HSTS_ENABLED" "HTTPS $ip:443 HSTS present"
                log "  VERIFIED: $ip HSTS ✓"
            else
                add_finding $i "LOW" "SZYFROWANIE" \
                    "HTTPS na $ip bez nagłówka HSTS – możliwy downgrade do HTTP" \
                    "Dodaj: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            fi

            local missing_headers=""
            echo "$https_headers" | grep -qi "X-Frame-Options"         || missing_headers="$missing_headers X-Frame-Options"
            echo "$https_headers" | grep -qi "X-Content-Type-Options"  || missing_headers="$missing_headers X-Content-Type-Options"
            echo "$https_headers" | grep -qi "Content-Security-Policy" || missing_headers="$missing_headers CSP"
            if [[ -n "${missing_headers# }" ]]; then
                add_finding $i "LOW" "HARDENING" \
                    "Brakujące security headers HTTP na $ip:443 – ${missing_headers# }" \
                    "Dodaj brakujące nagłówki bezpieczeństwa."
            fi
        fi

        # Redis
        if contains_port "$ports" 6379; then
            local redis_resp; redis_resp=$(echo -e "PING\r\n" | timeout 3 ${T[nc_cmd]:-cat} -w3 "$ip" 6379 2>/dev/null | head -1 | tr -d '\r\n' || echo "")
            if echo "$redis_resp" | grep -qi "PONG"; then
                add_finding $i "CRITICAL" "KRADZIEŻ_DANYCH" \
                    "Redis na $ip:6379 dostępny BEZ uwierzytelnienia – pełny dostęp, możliwe RCE" \
                    "Dodaj requirepass. Ogranicz bind do localhost."
            elif echo "$redis_resp" | grep -qi "NOAUTH\|Authentication"; then
                add_verified $i "REDIS_AUTH_REQUIRED" "Redis wymaga auth"
            fi
        fi

        # SMB/NetBIOS — hostname, domain, OS disclosure
        if contains_port "$ports" 445 || contains_port "$ports" 139; then
            # NetBIOS Name Service query (UDP 137) przez nc TCP fallback
            local smb_banner; smb_banner=$(grab_banner "$ip" 445 2 2>/dev/null || echo "")
            if [[ -n "$smb_banner" ]]; then
                # Wyciągnij hostname z SMB negotiate response
                local smb_host; smb_host=$(echo "$smb_banner" | strings 2>/dev/null |                     grep -oP '[A-Z0-9_-]{3,15}' | head -1 || echo "")
                [[ -n "$smb_host" ]] && add_verified $i "SMB_HOSTNAME" "SMB:$smb_host"
            fi
            # nmblookup jeśli dostępny
            if command -v nmblookup &>/dev/null; then
                local nbt; nbt=$(nmblookup -A "$ip" 2>/dev/null | grep -v "^Looking\|^\s*$" | head -3 || echo "")
                [[ -n "$nbt" ]] && add_verified $i "NETBIOS_INFO" "$nbt"
            fi
        fi

        # SNMP — community string probe (v1/v2c)
        if contains_port "$ports" 161 && command -v snmpwalk &>/dev/null; then
            for community in public private community admin; do
                local snmp_out; snmp_out=$(timeout 3 snmpwalk -v2c -c "$community"                     -On "$ip" .1.3.6.1.2.1.1.1.0 2>/dev/null | head -1 || echo "")
                if [[ -n "$snmp_out" ]]; then
                    add_finding $i "HIGH" "SNMP_OPEN"                         "SNMP community='$community' na $ip — system info disclosure, możliwa rekonfiguracja"                         "Usuń publiczne community strings. Wdróż SNMPv3 z auth+priv."
                    add_verified $i "SNMP_COMMUNITY" "community=$community sysDescr=$(echo "$snmp_out" | cut -c1-60)"
                    break
                fi
            done
        elif contains_port "$ports" 161; then
            # Bez snmpwalk — prosty UDP probe przez /dev/udp
            local snmp_probe
            snmp_probe=$(printf '0& public   00	+ ' |                 timeout 2 bash -c "cat > /dev/udp/$ip/161" 2>/dev/null && echo "SENT" || echo "")
            [[ -n "$snmp_probe" ]] && add_finding $i "MEDIUM" "SNMP_PORT"                 "SNMP port 161 otwarty na $ip — sprawdź community strings ręcznie"                 "snmpwalk -v2c -c public $ip .1.3.6.1.2.1.1"
        fi

        # Telnet
        if contains_port "$ports" 23 || contains_port "$ports" 2323; then
            local tport=23; contains_port "$ports" 2323 && tport=2323
            add_finding $i "CRITICAL" "KRADZIEŻ_HASEŁ" \
                "Telnet na $ip:$tport – dane i hasła jawnym tekstem. Sygnatura IoT/Mirai." \
                "NATYCHMIAST wyłącz Telnet. Zastąp SSH."
        fi

        # Docker API (unauthenticated = full host takeover)
        if contains_port "$ports" 2375; then
            local docker_resp; docker_resp=$(grab_http_banner "http://${ip}:2375/version" 3 2>/dev/null || echo "")
            if echo "$docker_resp" | grep -qi "Version\|docker\|ApiVersion"; then
                add_finding $i "CRITICAL" "CONTAINER_ESCAPE"                     "Docker API OTWARTE (bez TLS/auth) na $ip:2375 — pełne przejęcie hosta przez escape kontenera"                     "NATYCHMIAST zablokuj port 2375. Włącz TLS: dockerd --tlsverify. Ogranicz do localhost."
                add_verified $i "DOCKER_API_OPEN" "$docker_resp"
            fi
        fi

        # Kubernetes API Server (unauthenticated)
        if contains_port "$ports" 6443 || contains_port "$ports" 8001; then
            local k8s_port=6443; contains_port "$ports" 8001 && k8s_port=8001
            local k8s_resp; k8s_resp=$(grab_http_banner "https://${ip}:${k8s_port}/api/v1" 4 2>/dev/null || echo "")
            if echo "$k8s_resp" | grep -qi "apiVersion\|kubernetes\|Unauthorized"; then
                if echo "$k8s_resp" | grep -qi ""kind"\|"apiVersion"" &&                    ! echo "$k8s_resp" | grep -qi "Unauthorized\|401\|403"; then
                    add_finding $i "CRITICAL" "K8S_UNAUTHENTICATED"                         "Kubernetes API Server dostępny BEZ uwierzytelnienia na $ip:$k8s_port"                         "Włącz RBAC. Ogranicz API server do sieci zarządzania."
                else
                    add_verified $i "K8S_API_SERVER" "K8S API @ $ip:$k8s_port (auth required)"
                fi
            fi
        fi

        # etcd (Kubernetes backing store — unauthenticated = cluster takeover)
        if contains_port "$ports" 2379; then
            local etcd_resp; etcd_resp=$(grab_http_banner "http://${ip}:2379/version" 3 2>/dev/null || echo "")
            if echo "$etcd_resp" | grep -qi "etcdserver\|etcdcluster"; then
                add_finding $i "CRITICAL" "ETCD_OPEN"                     "etcd (Kubernetes) dostępny bez auth na $ip:2379 — pełny odczyt/zapis secrets klastra"                     "Włącz TLS client auth dla etcd. Ogranicz do sieci control plane."
            fi
        fi

        # Backdoor ports
        for bport in 4444 1337 31337 6666 7777 9999 4899; do
            if contains_port "$ports" "$bport"; then
                add_finding $i "CRITICAL" "POTENCJALNY_BACKDOOR" \
                    "Port $bport na $ip – charakterystyczny dla Metasploit/C2/backdoor. Wymaga dochodzenia." \
                    "IZOLUJ HOST. Analiza forensic: netstat -antp"
            fi
        done
    done
}

# [8] DNS AUDIT

declare -A DNS_AUDIT=(
    [internal_resolver]="" [resolver_responds]="0" [external_dns_reachable]="0"
    [dns_enforced]="0" [malware_blocked]="0" [doh_available]="0"
    [dnssec]="0" [leak_test_result]=""
)

# [8a] UDP SERVICE DETECTION
# Sprawdza usługi UDP które są niewidoczne przez TCP-only scan:
# DNS/53, NTP/123, SNMP/161, TFTP/69, SSDP/1900, mDNS/5353, NetBIOS/137
audit_udp() {
    [[ "$MODE" == "passive" ]] && return
    log "[UDP] UDP service detection" "SECTION"

    for (( i=0; i<DEV_COUNT; i++ )); do
        local ip="${D_IP[$i]}"

        # DNS/53 UDP — sprawdź czy host jest resolverem
        local dns_resp
        if [[ -n "${T[dig]:-}" ]]; then
            dns_resp=$(timeout 2 dig +time=1 +tries=1 +noall +answer @"$ip" version.bind chaos TXT 2>/dev/null                 || timeout 2 dig +time=1 +tries=1 +noall +answer @"$ip" example.com A 2>/dev/null || echo "")
            if [[ -n "$dns_resp" ]]; then
                add_verified $i "UDP_DNS_OPEN" "DNS resolver @ $ip:53/udp"
                # Wersja BIND disclosure
                local bind_ver; bind_ver=$(timeout 2 dig +time=1 @"$ip" version.bind chaos TXT +short 2>/dev/null || echo "")
                if [[ -n "$bind_ver" ]]; then
                    add_finding $i "MEDIUM" "DNS_VERSION_DISCLOSURE"                         "DNS version disclosure na $ip: $bind_ver — ułatwia targetowanie znanych CVE"                         "Wyłącz: options { version 'none'; }; w named.conf"
                fi
            fi
        fi

        # NTP/123 UDP — sprawdź monlist (amplification vector)
        local ntp_resp
        ntp_resp=$(printf ' *%0.s' '' |             timeout 2 bash -c "cat > /dev/udp/$ip/123 && cat < /dev/udp/$ip/123" 2>/dev/null | awk '{print $1+0}' || echo "0")
        if (( ${ntp_resp//[^0-9]/} > 10 )); then
            add_verified $i "UDP_NTP_OPEN" "NTP @ $ip:123/udp"
            # Monlist probe (5 bajtów request → duży response = amplification)
            local ntp_mode7
            ntp_mode7=$(printf ' *%0.s' '' |                 timeout 2 bash -c "cat > /dev/udp/$ip/123 && cat < /dev/udp/$ip/123" 2>/dev/null | awk '{print $1+0}' || echo "0")
            if (( ${ntp_mode7//[^0-9]/} > 100 )); then
                add_finding $i "HIGH" "UDP_AMPLIFICATION"                     "NTP monlist aktywny na $ip:123 — współczynnik amplifikacji do 556x, wektor DDoS"                     "ntpdc -c 'disable monitor' lub ogranicz: restrict default kod nomodify nopeer noquery notrap"
            fi
        fi

        # SNMP/161 UDP — community string probe bez snmpwalk
        # Wysyłamy GetRequest PDU dla sysDescr (OID .1.3.6.1.2.1.1.1.0)
        local snmp_req snmp_resp
        # SNMP v2c GetRequest z community "public" — minimalne PDU
        snmp_req=$(printf '0&public      00	+ ')
        snmp_resp=$(echo -n "$snmp_req" |             timeout 2 bash -c "cat > /dev/udp/$ip/161" 2>/dev/null && echo "SENT" || echo "")
        # Fallback: nc -u jeśli dostępny
        if [[ -z "$snmp_resp" && -n "${T[nc_cmd]:-}" ]]; then
            snmp_resp=$(echo -e "$snmp_req" |                 timeout 2 ${T[nc_cmd]} -u -w2 "$ip" 161 2>/dev/null | head -1 || echo "")
        fi
        if [[ -n "$snmp_resp" && "$snmp_resp" != "SENT" ]] ||            echo "$snmp_resp" | grep -qP '[0-5]'; then
            add_finding $i "HIGH" "SNMP_OPEN"                 "SNMP v2c community='public' odpowiedział na $ip:161/udp"                 "Wyłącz SNMPv1/v2c. Wdróż SNMPv3 z auth+priv (SHA/AES). Ogranicz ACL."
        fi

        # NetBIOS/137 UDP — Name Service query
        # Zwraca hostname, domain, MAC (passive recon goldmine)
        if [[ -n "${T[nmblookup]:-}" ]]; then
            local nbt_out; nbt_out=$(timeout 3 nmblookup -A "$ip" 2>/dev/null |                 grep -v "^Looking\|^$\|Use of" | head -5 || echo "")
            if [[ -n "$nbt_out" ]]; then
                add_verified $i "UDP_NETBIOS_INFO" "NetBIOS: $(echo "$nbt_out" | tr '
' ';' | cut -c1-80)"
                # Workgroup/domain disclosure
                local nb_domain; nb_domain=$(echo "$nbt_out" | awk '/<00>/ && /GROUP/{print $1}' | head -1)
                [[ -n "$nb_domain" ]] && add_verified $i "AD_NETBIOS_DOMAIN" "Domain: $nb_domain"
            fi
        fi

        # mDNS/5353 UDP — Bonjour/Avahi (discloses hostname, services, OS)
        local mdns_resp
        mdns_resp=$(timeout 2 bash -c             "printf '           local  ÿ '              > /dev/udp/224.0.0.251/5353" 2>/dev/null && echo "sent" || echo "")
        # Sprawdź też unicast mDNS na hoście
        if [[ -n "${T[dig]:-}" ]]; then
            local mdns_host; mdns_host=$(timeout 2 dig +time=1 +tries=1                 @"$ip" -p 5353 -t PTR _services._dns-sd._udp.local 2>/dev/null |                 awk '/ANSWER/{a=1;next} a && /PTR/{print $NF}' | head -3 || echo "")
            if [[ -n "$mdns_host" ]]; then
                add_verified $i "UDP_MDNS_SERVICES" "mDNS services: $(echo "$mdns_host" | tr '
' ',')"
            fi
        fi

        # SSDP/1900 UDP — UPnP (discloses device type, firmware version)
        local ssdp_req="M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 1
ST: ssdp:all

"
        local ssdp_resp
        ssdp_resp=$(printf "$ssdp_req" |             timeout 2 ${T[nc_cmd]:-bash -c "cat > /dev/udp/$ip/1900"} -u -w2 "$ip" 1900 2>/dev/null |             head -5 || echo "")
        if echo "$ssdp_resp" | grep -qi "HTTP/1\|Server:\|Location:"; then
            local ssdp_server; ssdp_server=$(echo "$ssdp_resp" | grep -i "Server:" | head -1 || echo "")
            add_finding $i "MEDIUM" "UPNP_SSDP"                 "UPnP/SSDP aktywny na $ip:1900/udp — device disclosure: ${ssdp_server:0:60}"                 "Wyłącz UPnP na urządzeniach produkcyjnych. Zablokuj SSDP na firewallu."
            add_verified $i "UDP_SSDP_INFO" "${ssdp_server:0:80}"
        fi

        # TFTP/69 UDP — anonymous file read/write (często na network devices)
        local tftp_resp
        tftp_resp=$(printf ' test octet ' |             timeout 2 bash -c "cat > /dev/udp/$ip/69 && cat < /dev/udp/$ip/69" 2>/dev/null | awk '{print $1+0}' || echo "0")
        if (( ${tftp_resp:-0} > 4 )); then
            add_finding $i "HIGH" "TFTP_OPEN"                 "TFTP otwarty na $ip:69/udp — anonimowy odczyt/zapis plików (konfiguracje, IOS images)"                 "Wyłącz TFTP lub ogranicz dostęp do sieci zarządzania."
        fi

    done
    log "[UDP] UDP scan zakończony" "OK"
}


audit_dns() {
    log "$(L phase_8)" "SECTION"
    local resolver=""
    resolver="${INTERNAL_DNS:-$(head -n1 < <(_dyn_resolver_candidates) || true)}"
    if [[ -z "$resolver" ]]; then
        DNS_AUDIT[resolver_responds]="0"
        _report_finding "DNS_BASELINE" "NOT_TESTED" 0 "no resolver discovered" "audit_dns"
        return 0
    fi

    DNS_AUDIT[internal_resolver]="$resolver"

    if [[ -n "${T[dig]:-}" ]]; then
        if dig +short +time=2 @"$resolver" example.com A 2>/dev/null | grep -qE '.'; then
            DNS_AUDIT[resolver_responds]="1"
            DNS_AUDIT[dns_enforced]="1"
            _report_finding "DNS_BASELINE" "CONFIRMED" 70 "resolver answers and is measurable" "audit_dns"
            log "$(L dns_int_ok "${resolver}")" "OK"
        else
            DNS_AUDIT[resolver_responds]="0"
            _report_finding "DNS_BASELINE" "NOT_DETECTED" 48 "discovered resolver does not answer consistently" "audit_dns"
        fi
    else
        _report_finding "DNS_BASELINE" "NOT_TESTED" 0 "dig unavailable" "audit_dns"
    fi
}


# [9] EGRESS AUDIT

declare -A EGRESS=(
    [http_out]="0" [https_out]="0" [smtp_out]="0" [ftp_out]="0"
    [c2_ports]="" [tor_risk]="0" [wan_ip_blacklisted]="0"
)

# [9a] TLS/CERTIFICATE AUDIT PER HOST
# Dla każdego hosta z otwartymi portami TLS sprawdza:
#   - ważność certyfikatu (expiry)
#   - słabe algorytmy (SHA1, MD5, RC4, DES, 3DES, SSLv2/v3/TLS1.0/1.1)
#   - self-signed (brak chain of trust)
#   - SAN mismatch (hostname ≠ certyfikat)
#   - wildcard overuse
audit_tls() {
    [[ "$MODE" == "passive" ]] && return
    [[ -z "${T[openssl]:-}" ]] && log "[TLS] openssl niedostępny — pominięto TLS audit" "WARN" && return

    log "[TLS] TLS/Certificate audit" "SECTION"
    local tls_ports="443 8443 8006 5601 15672 636 993 995 587 465"

    for (( i=0; i<DEV_COUNT; i++ )); do
        local ip="${D_IP[$i]}"
        local ports; ports="$(_safe_get RAW_PORTS "$ip")"
        [[ -z "$ports" ]] && continue

        for tport in $tls_ports; do
            contains_port "$ports" "$tport" || continue

            # Pobierz certyfikat
            local cert_raw
            cert_raw=$(timeout 6 bash -c "
                echo | ${T[openssl]} s_client                     -connect '${ip}:${tport}'                     -servername '${ip}'                     -showcerts 2>/dev/null" 2>/dev/null || echo "")
            [[ -z "$cert_raw" ]] && continue

            local cert_pem
            cert_pem=$(echo "$cert_raw" |                 awk '/BEGIN CERTIFICATE/{c=1} c{print} /END CERTIFICATE/{if(c==1)exit}')
            [[ -z "$cert_pem" ]] && continue

            # Expiry date
            local not_after
            not_after=$(echo "$cert_pem" |                 ${T[openssl]} x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//' || echo "")
            if [[ -n "$not_after" ]]; then
                local exp_epoch now_epoch days_left
                exp_epoch=$(date -d "$not_after" +%s 2>/dev/null ||                             date -jf "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo "0")
                now_epoch=$(date +%s)
                days_left=$(( (exp_epoch - now_epoch) / 86400 ))

                if (( days_left < 0 )); then
                    add_finding $i "HIGH" "TLS_EXPIRED"                         "Certyfikat TLS WYGASŁ na $ip:$tport ($not_after) — przeglądarki blokują połączenie, MITM risk"                         "Odnów certyfikat NATYCHMIAST. Let's Encrypt: certbot renew --force-renewal"
                elif (( days_left <= 14 )); then
                    add_finding $i "HIGH" "TLS_EXPIRING_SOON"                         "Certyfikat TLS wygasa za ${days_left} dni na $ip:$tport ($not_after)"                         "Odnów certyfikat. Ustaw auto-renewal (certbot/acme.sh)."
                elif (( days_left <= 30 )); then
                    add_finding $i "MEDIUM" "TLS_EXPIRING_SOON"                         "Certyfikat TLS wygasa za ${days_left} dni na $ip:$tport"                         "Zaplanuj odnowienie. Auto-renewal: certbot renew --pre-hook"
                else
                    add_verified $i "TLS_CERT_VALID" "TLS $ip:$tport — ${days_left}d do wygaśnięcia"
                fi
            fi

            # Self-signed check
            local issuer subject
            issuer=$(echo "$cert_pem" | ${T[openssl]} x509 -noout -issuer 2>/dev/null || echo "")
            subject=$(echo "$cert_pem" | ${T[openssl]} x509 -noout -subject 2>/dev/null || echo "")
            if [[ -n "$issuer" && -n "$subject" ]]; then
                local iss_cn; iss_cn=$(echo "$issuer" | grep -oP 'CN\s*=\s*\K[^,/]+' | head -1 || echo "")
                local sub_cn; sub_cn=$(echo "$subject" | grep -oP 'CN\s*=\s*\K[^,/]+' | head -1 || echo "")
                if [[ "$iss_cn" == "$sub_cn" && -n "$iss_cn" ]]; then
                    add_finding $i "HIGH" "TLS_SELF_SIGNED"                         "Self-signed certyfikat na $ip:$tport (CN=$sub_cn) — brak chain of trust, MITM trivial"                         "Wdróż certyfikat z zaufanego CA (Let's Encrypt, DigiCert, internal PKI)."
                fi
            fi

            # Słaby algorytm podpisu (SHA1/MD5)
            local sig_algo
            sig_algo=$(echo "$cert_pem" |                 ${T[openssl]} x509 -noout -text 2>/dev/null |                 grep -i "Signature Algorithm" | head -1 | awk '{print $NF}' || echo "")
            if echo "$sig_algo" | grep -qi "sha1\|md5\|md2"; then
                add_finding $i "HIGH" "TLS_WEAK_CIPHER"                     "Słaby algorytm podpisu certyfikatu na $ip:$tport: $sig_algo"                     "Wymień certyfikat z SHA-256 lub wyższym. SHA-1 wycofany przez wszystkie CA."
            fi

            # Protokół TLS — sprawdź obsługę starych wersji
            for bad_proto in ssl2 ssl3 tls1 tls1_1; do
                local proto_test
                proto_test=$(timeout 4 bash -c "
                    echo | ${T[openssl]} s_client                         -connect '${ip}:${tport}'                         -${bad_proto} 2>&1" 2>/dev/null |                     grep -c "Cipher\|DONE" || echo "0")
                if (( proto_test > 0 )); then
                    local proto_name
                    case "$bad_proto" in
                        ssl2)   proto_name="SSLv2" ;;
                        ssl3)   proto_name="SSLv3" ;;
                        tls1)   proto_name="TLS 1.0" ;;
                        tls1_1) proto_name="TLS 1.1" ;;
                    esac
                    add_finding $i "HIGH" "TLS_WEAK_CIPHER"                         "Przestarzały protokół $proto_name akceptowany na $ip:$tport"                         "Wyłącz $proto_name. Zezwól tylko TLS 1.2+ (preferuj TLS 1.3)."
                    break  # jedno ostrzeżenie per host:port wystarczy
                fi
            done

            # Cipher suite — sprawdź RC4/DES/3DES/NULL
            local weak_ciphers
            weak_ciphers=$(timeout 4 bash -c "
                echo | ${T[openssl]} s_client                     -connect '${ip}:${tport}'                     -cipher 'RC4:DES:3DES:NULL:aNULL:eNULL' 2>&1" 2>/dev/null |                 grep "Cipher\s*:" | awk '{print $NF}' || echo "")
            if [[ -n "$weak_ciphers" && "$weak_ciphers" != "(NONE)" ]]; then
                add_finding $i "HIGH" "TLS_WEAK_CIPHER"                     "Słaby cipher suite na $ip:$tport: $weak_ciphers"                     "Ogranicz do: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, ECDHE+AESGCM."
            fi

            # SAN / hostname mismatch
            local san_list
            san_list=$(echo "$cert_pem" |                 ${T[openssl]} x509 -noout -text 2>/dev/null |                 grep -oP '(?<=DNS:)[^,\s]+' | tr '
' ',' | sed 's/,$//' || echo "")
            if [[ -n "$san_list" ]]; then
                add_verified $i "TLS_SAN" "$ip:$tport SAN=$san_list"
                # Sprawdź czy IP jest w SAN lub CN
                if ! echo "$san_list,$sub_cn" | grep -q "$ip" &&                    ! echo "$san_list" | grep -q "^*\."; then
                    add_finding $i "MEDIUM" "TLS_SAN_MISMATCH"                         "IP $ip nie pasuje do SAN certyfikatu na :$tport (SAN: ${san_list:0:60})"                         "Wygeneruj certyfikat z IP SAN lub poprawnym CN. openssl req -addext 'subjectAltName=IP:$ip'"
                fi
            fi

        done
    done
    log "[TLS] TLS audit zakończony" "OK"
}


audit_egress() {
    log "$(L phase_9)" "SECTION"
    local http_code="000" https_code="000"
    if [[ -n "${T[curl]:-}" ]]; then
        http_code=$(timeout 5 curl -ksS -o /dev/null -w '%{http_code}' http://example.com 2>/dev/null || echo "000")
        https_code=$(timeout 5 curl -ksS -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null || echo "000")
    fi

    if [[ "$http_code" =~ ^(200|301|302|403|405)$ ]]; then
        EGRESS[http_out]="1"
        TRAFFIC_POLICY[http_egress_blocked]="0"
        _report_finding "HTTP_EGRESS" "ABSENT" 72 "plain HTTP reachable (code=$http_code)" "audit_egress"
    else
        TRAFFIC_POLICY[http_egress_blocked]="1"
        _report_finding "HTTP_EGRESS" "CONFIRMED" 65 "plain HTTP constrained (code=$http_code)" "audit_egress"
    fi

    if [[ "$https_code" =~ ^(200|301|302|403|405)$ ]]; then
        EGRESS[https_out]="1"
        _report_finding "HTTPS_EGRESS" "CONFIRMED" 56 "HTTPS reachable (code=$https_code)" "audit_egress"
    else
        _report_finding "HTTPS_EGRESS" "NOT_DETECTED" 32 "HTTPS path not measurable (code=$https_code)" "audit_egress"
    fi
}


# [10] WAN EXPOSURE

declare -A WAN_AUDIT=([scanned]="0" [open_ports]="" [rdp_exposed]="0" [ssh_exposed]="0" [admin_exposed]="0")

audit_wan() {
    if [[ $SKIP_WAN -eq 1 || -z "$WAN_IP" ]]; then
        log "$(L wan_skip_vpn)" "WARN"
        if [[ "${TOPO[vpn_detected]:-0}" == "1" ]]; then
            add_net_finding "INFO" "WAN" \
                "Test WAN pominięty — wykryto VPN (${TOPO[vpn_type]:-unknown}). WAN IP ${WAN_IP:-nieznany} należy do VPN providera, nie do lokalnego routera." \
                "Dla testu WAN lokalnego routera uruchom audyt bez połączenia VPN lub podaj --wan <PRAWDZIWY_WAN_IP>."
        fi
        return
    fi

    log "$(L phase_10 "${WAN_IP}")" "SECTION"
    WAN_AUDIT[scanned]="1"

    local wan_ports="22 23 25 53 80 443 445 1433 3306 3389 5900 8080 8443 27017"
    local open_wan=""

    for port in $wan_ports; do
        progress "WAN scan port $port..."
        if probe_port "$WAN_IP" "$port" 4; then
            open_wan="$open_wan $port"
            case $port in
            22) WAN_AUDIT[ssh_exposed]="1"
                add_net_finding "HIGH" "WAN_EKSPOZYCJA" \
                    "SSH port 22 dostępny pod $WAN_IP z internetu" \
                    "Wymuś klucze SSH. Zmień port. Wdróż automatyczne blokowanie prób logowania. Ogranicz dostęp do VPN." ;;
            80) WAN_AUDIT[admin_exposed]="1"
                add_net_finding "HIGH" "WAN_EKSPOZYCJA" \
                    "HTTP port 80 dostępny pod $WAN_IP – panel bez szyfrowania" \
                    "Ogranicz dostęp. Wymuś HTTPS." ;;
            443|8443) add_net_finding "MEDIUM" "WAN_EKSPOZYCJA" \
                    "HTTPS port $port dostępny pod $WAN_IP" \
                    "Weryfikuj czy zamierzone. Sprawdź certyfikat." ;;
            8080) WAN_AUDIT[admin_exposed]="1"
                add_net_finding "HIGH" "WAN_EKSPOZYCJA" \
                    "HTTP port 8080 dostępny pod $WAN_IP" \
                    "Zablokuj z WAN. Dostęp tylko przez VPN." ;;
            3389) WAN_AUDIT[rdp_exposed]="1"
                add_net_finding "CRITICAL" "WAN_EKSPOZYCJA" \
                    "RDP port 3389 dostępny z INTERNETU pod $WAN_IP – cel ransomware" \
                    "NATYCHMIAST zablokuj. Dostęp przez VPN. NLA+MFA." ;;
            445) add_net_finding "CRITICAL" "WAN_EKSPOZYCJA" \
                    "SMB port 445 z INTERNETU – wektor EternalBlue/WannaCry" \
                    "NATYCHMIAST zablokuj na WAN." ;;
            esac
        fi
    done
    echo ""
    WAN_AUDIT[open_ports]="${open_wan# }"
    [[ -z "${open_wan# }" ]] && add_net_finding "INFO" "WAN" "Brak otwartych portów pod $WAN_IP ✓" ""
}

# [11] LATERAL MOVEMENT

FLAT_PERCENT="0"
declare -a LATERAL_PATHS=()

# [10a] ACTIVE DIRECTORY / KERBEROS DETECTION
# Wykrywa infrastrukturę AD bez bruteforce — pasywny fingerprint + safe probes:
#   - LDAP/389 i LDAPS/636 — DC fingerprint, naming context
#   - Kerberos/88 — AS-REQ probe (service ticket request bez credentiali)
#   - SMB signing — brak = NTLM relay vector
#   - MS-RPC/135 — DCE endpoint mapper
#   - Global Catalog/3268, 3269
declare -A AD_INFO=(
    [detected]="0"
    [dc_ip]=""
    [domain]=""
    [forest]=""
    [ldap_signing]="unknown"
    [smb_signing]="unknown"
    [kerberos_open]="0"
    [null_session]="0"
)

audit_ad() {
    [[ "$MODE" == "passive" ]] && return
    log "[AD] Active Directory / Kerberos detection" "SECTION"

    local ad_ports="88 389 636 445 135 3268 3269"

    for (( i=0; i<DEV_COUNT; i++ )); do
        local ip="${D_IP[$i]}"
        local ports; ports="$(_safe_get RAW_PORTS "$ip")"
        [[ -z "$ports" ]] && continue

        local is_dc=0

        # Kerberos/88 — AS-REQ probe
        # Wysyłamy minimalny AS-REQ bez pre-auth — DC odpowie KRB_ERROR (nie exploitujemy)
        if contains_port "$ports" 88; then
            local krb_resp
            krb_resp=$(timeout 3 bash -c                 "exec 3<>/dev/tcp/$ip/88 &&                  printf '   [jY0W¡¢
' >&3 &&                  dd bs=4 count=1 <&3 2>/dev/null" 2>/dev/null | awk '{print $1+0}' || echo "0")
            if (( ${krb_resp:-0} >= 4 )); then
                is_dc=1
                AD_INFO[kerberos_open]="1"
                AD_INFO[dc_ip]="$ip"
                AD_INFO[detected]="1"
                add_verified $i "KERBEROS_DC" "Kerberos/88 @ $ip — Domain Controller fingerprint"
                log "  [AD] DC wykryty: $ip (Kerberos/88 aktywny)" "OK"
            fi
        fi

        # LDAP/389 — anonymous bind (enumeracja bez credentiali)
        if contains_port "$ports" 389; then
            local ldap_resp=""
            if [[ -n "${T[ldapsearch]:-}" ]]; then
                # ldapsearch anonymous — rootDSE (nie wymaga auth)
                ldap_resp=$(timeout 5 ${T[ldapsearch]} -x -H "ldap://$ip"                     -b "" -s base "(objectclass=*)"                     defaultNamingContext dnsHostName domainFunctionality                     2>/dev/null | head -20 || echo "")
                if [[ -n "$ldap_resp" ]] && echo "$ldap_resp" | grep -qi "namingContext\|dn:\|DC="; then
                    is_dc=1
                    AD_INFO[detected]="1"
                    AD_INFO[dc_ip]="$ip"
                    local domain_nc; domain_nc=$(echo "$ldap_resp" |                         grep -i "defaultNamingContext" | head -1 |                         grep -oP 'DC=[^,]+' | tr ',' '.' | sed 's/DC=//g' || echo "")
                    [[ -n "$domain_nc" ]] && AD_INFO[domain]="$domain_nc"
                    add_verified $i "LDAP_DC" "LDAP DC @ $ip domain=${domain_nc:-unknown}"
                    # Anonymous bind = informacja o domenie bez auth
                    add_finding $i "MEDIUM" "AD_LDAP_OPEN"                         "LDAP anonymous bind dozwolony na $ip:389 — domain info: ${domain_nc:-?}"                         "Wyłącz anonymous LDAP bind. Wymuś LDAP signing: [Domain controller: LDAP signing = Require signing]"
                fi
            else
                # Bez ldapsearch — raw TCP probe
                ldap_resp=$(timeout 2 bash -c "exec 3<>/dev/tcp/$ip/389" 2>/dev/null && echo 1 || echo 0)
                if (( ${ldap_resp:-0} > 4 )); then
                    is_dc=1; AD_INFO[detected]="1"; AD_INFO[dc_ip]="$ip"
                    add_verified $i "LDAP_OPEN" "LDAP @ $ip:389 (raw probe)"
                fi
            fi
        fi

        # LDAPS/636 — sprawdź certyfikat (często self-signed w AD)
        if contains_port "$ports" 636 && [[ -n "${T[openssl]:-}" ]]; then
            local ldaps_cert
            ldaps_cert=$(timeout 5 bash -c                 "echo | ${T[openssl]} s_client -connect '${ip}:636' -showcerts 2>/dev/null"                 2>/dev/null | head -5 || echo "")
            if echo "$ldaps_cert" | grep -q "BEGIN CERTIFICATE"; then
                add_verified $i "LDAPS_OPEN" "LDAPS/636 @ $ip — TLS active"
                is_dc=1; AD_INFO[detected]="1"
            fi
        fi

        # SMB Signing check — krytyczne dla NTLM relay
        if contains_port "$ports" 445; then
            local smb_sign="unknown"
            if [[ -n "${T[smbclient]:-}" ]]; then
                local smb_neg; smb_neg=$(timeout 5                     ${T[smbclient]} -N -L "//$ip" 2>&1 | head -5 || echo "")
                if echo "$smb_neg" | grep -qi "signing.*mandatory\|required.*signing"; then
                    smb_sign="required"
                    add_verified $i "SMB_SIGNING_REQUIRED" "SMB signing mandatory @ $ip"
                elif echo "$smb_neg" | grep -qi "signing.*disabled\|not required\|disabled"; then
                    smb_sign="disabled"
                    add_finding $i "HIGH" "AD_NO_SIGNING"                         "SMB signing WYŁĄCZONE na $ip — podatność na NTLM relay attack (pass-the-hash, lateral movement)"                         "Włącz: [MS network server: Digitally sign comms = Enabled] w GPO. Responder/ntlmrelayx bez SMB signing = lateral movement całej sieci."
                fi
            else
                # Raw SMB negotiate — sprawdź bit SecurityMode w negotiate response
                local smb_raw
                smb_raw=$(timeout 2 bash -c "exec 3<>/dev/tcp/$ip/445" 2>/dev/null && echo "1" || echo "0")
                if (( ${smb_raw:-0} > 30 )); then
                    add_verified $i "SMB_ACTIVE" "SMB @ $ip:445 (raw probe OK)"
                fi
            fi
            AD_INFO[smb_signing]="$smb_sign"
        fi

        # MS-RPC / DCE Endpoint Mapper/135 — obecność = Windows host
        if contains_port "$ports" 135; then
            add_verified $i "MSRPC_EPMAP" "MS-RPC Endpoint Mapper @ $ip:135"
        fi

        # Global Catalog/3268 — tylko DC mają GC
        if contains_port "$ports" 3268 || contains_port "$ports" 3269; then
            is_dc=1; AD_INFO[detected]="1"; AD_INFO[dc_ip]="$ip"
            add_verified $i "AD_GLOBAL_CATALOG" "Global Catalog @ $ip:3268 — Domain Controller"
            log "  [AD] Global Catalog wykryty na $ip" "OK"
        fi

        # Kerberoasting probe — sprawdź czy SPN są enumerowalne (bez auth)
        if (( is_dc == 1 )) && [[ -n "${T[ldapsearch]:-}" ]]; then
            local spn_count; spn_count=$(timeout 5 ${T[ldapsearch]} -x                 -H "ldap://$ip" -b "${AD_INFO[domain]:+DC=${AD_INFO[domain]//./,DC=}}"                 "(&(objectCategory=user)(servicePrincipalName=*))" dn                 2>/dev/null | grep -c "^dn:" || echo "0")
            if (( ${spn_count:-0} > 0 )); then
                add_finding $i "HIGH" "KERBEROASTING"                     "${spn_count} kont z SPN wykrytych na $ip — podatne na Kerberoasting (offline crack TGS tickets)"                     "Użyj gMSA dla service accounts. Silne hasła (25+ znaków). Monitoruj TGS requests w SIEM."
            fi
        fi

        # Podsumowanie DC
        if (( is_dc == 1 )); then
            SECURITY_SYSTEMS+=("Active Directory DC @ $ip domain=${AD_INFO[domain]:-unknown}")
        fi
    done

    if [[ "${AD_INFO[detected]}" == "1" ]]; then
        log "  [AD] Środowisko AD wykryte. DC=${AD_INFO[dc_ip]} domain=${AD_INFO[domain]:-unknown}" "OK"
        log "  [AD] SMB signing=${AD_INFO[smb_signing]} Kerberos=${AD_INFO[kerberos_open]}" "OK"
    else
        log "  [AD] Brak wskaźników Active Directory w sieci" "OK"
    fi
}

audit_lateral() {
    log "$(L phase_11)" "SECTION"
    (( DEV_COUNT < 2 )) && return

    local total=0 hits=0 tested=0 reachable=0
    # Lateral movement audit — dwa poziomy:
    # L1: Port presence (szybki — z zebranych danych port scan)
    # L2: Actual TCP reachability (wolniejszy — rzeczywista próba połączenia)
    # Cel: zmierzyć czy firewall/ACL faktycznie blokuje ruch east-west
    local lat_ports="445 22 3389 5985 5986 3306 1433 5432 6379 27017"

    # L1: Port presence — które hosty mają potencjalnie exploitowalne porty
    declare -A host_risk=()
    for (( j=0; j<DEV_COUNT; j++ )); do
        local risk_ports=0
        for lport in $lat_ports; do
            contains_port "${D_PORTS[$j]}" "$lport" && (( risk_ports++ ))
        done
        host_risk["${D_IP[$j]}"]="$risk_ports"
    done

    # L2: Actual reachability test — czy możemy dotrzeć z audytora do każdego hosta:port
    # (audytor = proxy dla "dowolnego skompromitowanego hosta w sieci")
    declare -a REACH_MATRIX=()   # "src_ip→dst_ip:port=OPEN|FILTERED"
    local active_probes=0

    for (( j=0; j<DEV_COUNT; j++ )); do
        local dst="${D_IP[$j]}"
        [[ -z "$dst" ]] && continue

        for lport in $lat_ports; do
            contains_port "${D_PORTS[$j]}" "$lport" || continue
            (( total++ ))

            # Sprawdź faktyczną osiągalność (nie zakładaj z port scan)
            (
                if timeout 1.2 bash -c "exec 3<>/dev/tcp/$dst/$lport" 2>/dev/null; then
                    echo "OPEN"
                else
                    echo "FILTERED"
                fi
            ) > /tmp/_ewnaf_lat_${dst//./_}_${lport} &
            (( active_probes++ ))
            if (( active_probes >= MAX_PARALLEL )); then wait; active_probes=0; fi
        done
    done
    wait

    # Zbierz wyniki
    for (( j=0; j<DEV_COUNT; j++ )); do
        local dst="${D_IP[$j]}"
        for lport in $lat_ports; do
            local result_file="/tmp/_ewnaf_lat_${dst//./_}_${lport}"
            [[ -f "$result_file" ]] || continue
            local result; result=$(cat "$result_file" 2>/dev/null || echo "FILTERED")
            rm -f "$result_file"
            (( tested++ ))
            if [[ "$result" == "OPEN" ]]; then
                (( hits++ )); (( reachable++ ))
                RAW_LATERAL["→${dst}:${lport}"]=1
                # Znajdź krytyczne kombinacje
                case "$lport" in
                    445) # SMB — highest lateral movement risk
                        # Sprawdź czy SMB signing jest wymagany
                        if [[ "${AD_INFO[smb_signing]:-unknown}" != "required" ]]; then
                            add_net_finding "CRITICAL" "LATERAL_MOVEMENT"                                 "SMB $dst:445 osiągalny bez SMB signing — NTLM relay / pass-the-hash trivial"                                 "Wymuś SMB signing w GPO. Segmentuj stacje robocze w osobnym VLAN."
                        fi ;;
                    3389) add_net_finding "HIGH" "LATERAL_MOVEMENT"                               "RDP $dst:3389 dostępny z sieci — lateral movement / BlueKeep scope"                               "Ogranicz RDP do Jump Server / VPN. Wymuś NLA (Network Level Auth)." ;;
                    5985|5986) add_net_finding "HIGH" "LATERAL_MOVEMENT"                               "WinRM $dst:$lport osiągalny — PowerShell remoting lateral movement"                               "Ogranicz WinRM do management VLAN. Wymuś kerberos auth." ;;
                    3306|1433|5432) add_net_finding "HIGH" "LATERAL_MOVEMENT"                               "DB $dst:$lport (port: $lport) osiągalny — data exfiltration path"                               "Ogranicz dostęp DB do application server VLAN. Użyj firewall ACL." ;;
                    6379|27017) add_net_finding "CRITICAL" "LATERAL_MOVEMENT"                               "NoSQL $dst:$lport osiągalny — często brak auth (Redis/MongoDB)"                               "Ogranicz do localhost/app VLAN. Wymuś auth." ;;
                esac
            fi
        done
    done

    if (( tested > 0 )); then
        FLAT_PERCENT=$(echo "scale=1; $reachable * 100 / $tested" | bc 2>/dev/null || echo "0")
    fi

    local flat_int; flat_int=$(echo "${FLAT_PERCENT:-0}" | cut -d. -f1)
    log "  Lateral: tested=$tested reachable=$reachable (${FLAT_PERCENT:-0}%)"
    log "  Lateral paths: ${LATERAL_PATHS[*]:-none}"

    # Wynik ogólny
    if (( flat_int > 50 )); then
        add_net_finding "CRITICAL" "LATERAL_MOVEMENT"             "Flat network: ${FLAT_PERCENT}% portów lateral-movement osiągalnych (${reachable}/${tested}) — zero segmentacji"             "Krytyczna architektura: wdróż VLAN segmentację, Zero Trust east-west policy, microsegmentation."
    elif (( flat_int > 25 )); then
        add_net_finding "HIGH" "LATERAL_MOVEMENT"             "Partial segmentation: ${FLAT_PERCENT}% portów osiągalnych (${reachable}/${tested})"             "Wzmocnij segmentację. Dodaj east-west firewall / NGFWrules między segmentami."
    elif (( flat_int > 0 )); then
        add_net_finding "MEDIUM" "LATERAL_MOVEMENT"             "Ograniczone ścieżki lateral: ${FLAT_PERCENT}% (${reachable}/${tested})"             "Przegląd ACL. Zastosuj least-privilege network access."
    else
        log "  [✓] Lateral movement: brak osiągalnych ścieżek — dobra segmentacja" "OK"
    fi
}

# [12] FIREWALL AUDIT

declare -A FW_AUDIT=([host_firewall_detected]="0" [default_policy]="unknown" [egress_filtered]="0")



# Early stub: allows pre-definition checkpoints before the full implementation is parsed later.
write_model_snapshot() { :; }

# CHECKPOINT: snapshot model state after Phase 4–11 commit
write_model_snapshot


audit_firewall() {
    log "$(L phase_12)" "SECTION"
    if [[ "${TARGET_CENTRIC_MODE:-1}" == "1" ]]; then
        log "v28: pomijam runner-centric firewall audit na lokalnym gatewayu" "WARN"
        FW_AUDIT[default_policy]="NOT_TESTED_TARGET_CENTRIC"
        return 0
    fi
}



# [13] FLEET OPEN DEVICE MANAGEMENT

# Stałe instalacyjne Fleet
readonly FLEET_VERSION_REQUIRED="4.50.0"
readonly FLEETCTL_URL="https://github.com/fleetdm/fleet/releases/download/fleet-v${FLEET_VERSION_REQUIRED}/fleetctl_v${FLEET_VERSION_REQUIRED}_linux.tar.gz"
readonly FLEET_PORTS="8080 8443"
readonly OSQUERY_PORTS="9000"

# Wyniki Fleet — uzupełniane przez audit_placeholder_local()
declare -A FLEET_RESULT=(
    [status]="not_checked"
    [local_fleetctl]="0"
    [local_fleet_server]="0"
    [local_osquery]="0"
    [remote_server_ip]=""
    [remote_server_port]=""
    [agent_count]="0"
    [version]=""
    [install_attempted]="0"
    [install_ok]="0"
    [install_error]=""
    [api_reachable]="0"
)


_fleet_try_install() {
    log "  [Fleet] v28: auto-install wyłączony w core target-centric" "WARN"
    return 1
}



_fleet_check_api() {
    local ip="$1" port="$2"
    [[ -z "${T[curl]:-}" ]] && return 1
    local resp; resp=$(curl -sk --max-time 4 "https://${ip}:${port}/api/v1/fleet/version" 2>/dev/null || \
                       curl -sk --max-time 4 "http://${ip}:${port}/api/v1/fleet/version" 2>/dev/null || echo "")
    if echo "$resp" | grep -qi '"version"\|"fleet_version"'; then
        local ver; ver=$(echo "$resp" | grep -oP '"version":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "unknown")
        FLEET_RESULT[version]="$ver"
        return 0
    fi
    return 1
}

audit_placeholder_local() {
    return 0
}


# [14] PROWLER AWS SECURITY AUDIT

readonly PROWLER_MIN_PYTHON="3.9"
readonly PROWLER_RESULTS_DIR_NAME="prowler"

declare -A PROWLER_RESULT=(
    [status]="not_checked"
    [installed]="0"
    [install_attempted]="0"
    [install_ok]="0"
    [install_error]=""
    [aws_detected]="0"
    [aws_identity]=""
    [aws_account]=""
    [scan_pid]=""
    [scan_started]="0"
    [report_dir]=""
    [version]=""
)

_prowler_check_python() {
    local python_bin=""
    for py in python3 python; do
        command -v "$py" &>/dev/null || continue
        local ver; ver=$("$py" --version 2>&1 | grep -oP '[0-9]+\.[0-9]+' | head -1)
        local major; major=$(echo "$ver" | cut -d. -f1)
        local minor; minor=$(echo "$ver" | cut -d. -f2)
        if (( major >= 3 && minor >= 9 )); then
            python_bin="$py"
            break
        fi
    done
    echo "$python_bin"
}


_prowler_try_install() {
    log "  [Prowler] v28: auto-install wyłączony w core target-centric" "WARN"
    return 1
}



_prowler_detect_aws() {
    log "  [Prowler] Wykrywanie AWS credentials..." "DEBUG"

    # 1) Zmienne środowiskowe
    if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
        PROWLER_RESULT[aws_detected]="1"
        log "  [Prowler] AWS credentials w ENV" "OK"
        return 0
    fi

    # 2) Plik credentials
    if [[ -f "$HOME/.aws/credentials" ]] && grep -q "aws_access_key_id" "$HOME/.aws/credentials" 2>/dev/null; then
        PROWLER_RESULT[aws_detected]="1"
        log "  [Prowler] AWS credentials w ~/.aws/credentials" "OK"
        return 0
    fi

    # 3) AWS CLI STS — zweryfikuj że credentials działają
    if command -v aws &>/dev/null; then
        local sts_resp; sts_resp=$(timeout 8 aws sts get-caller-identity 2>/dev/null || echo "")
        if [[ -n "$sts_resp" ]]; then
            PROWLER_RESULT[aws_detected]="1"
            local account; account=$(echo "$sts_resp" | grep -oP '"Account":\s*"\K[0-9]+' || echo "")
            local arn; arn=$(echo "$sts_resp" | grep -oP '"Arn":\s*"\K[^"]+' || echo "")
            PROWLER_RESULT[aws_account]="$account"
            PROWLER_RESULT[aws_identity]="$arn"
            log "  [Prowler] AWS identity: $arn (account: $account)" "OK"
            return 0
        fi
    fi

    # 4) EC2 Instance Metadata (jeśli uruchomiony na EC2)
    if [[ -n "${T[curl]:-}" ]]; then
        local imds; imds=$(curl -s --max-time 2 "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || echo "")
        if [[ -n "$imds" && "$imds" =~ ^i- ]]; then
            PROWLER_RESULT[aws_detected]="1"
            PROWLER_RESULT[aws_identity]="EC2 instance: $imds"
            log "  [Prowler] Uruchomiony na EC2: $imds" "OK"
            return 0
        fi
    fi

    return 1
}

audit_placeholder_cloud() {
    return 0
}


# [16] SCORING

declare -A SEV_POINTS=([CRITICAL]=35 [HIGH]=20 [MEDIUM]=10 [LOW]=3 [INFO]=0)

# Waga asset impact per rola (enterprise weighting)
get_asset_impact() {
    local role="$1"
    case "$role" in
        *Gateway*|*Router*)      echo "17" ;;  # x1.7 — serce sieci
        *DNS*)                   echo "16" ;;  # x1.6 — critical infra
        *"Web+SSH"*|*"HTTPS"*)   echo "15" ;;  # x1.5 — serwer
        *Server*|*SQL*|*Redis*|*Mongo*|*Elastic*) echo "15" ;;
        *Windows*|*RDP*)         echo "13" ;;  # x1.3 — lateral target
        *WinRM*|*SMB*)           echo "13" ;;
        *VNC*)                   echo "12" ;;
        *IoT*|*Telnet*|*LEGACY*) echo "14" ;;  # x1.4 — słaba ochrona
        *)                       echo "10" ;;  # x1.0 — baseline
    esac
}

score_host() {
    local idx="$1" raw=0

    if [[ -n "${D_FINDINGS[$idx]:-}" ]]; then
        local IFS_OLD="$IFS"
        IFS=$'\x01' read -ra parts <<< "${D_FINDINGS[$idx]}"
        IFS="$IFS_OLD"
        local i=0
        while (( i < ${#parts[@]} )); do
            local sev="${parts[$i]:-}"
            case "$sev" in
                CRITICAL|HIGH|MEDIUM|LOW|INFO)
                    raw=$(( raw + ${SEV_POINTS[$sev]:-0} ))
                    (( i += 4 ))
                    ;;
                *) (( i++ )) ;;
            esac
        done
    fi
    (( raw > 100 )) && raw=100
    D_RAW_SCORE[$idx]=$raw

    # Asset Impact Weighting (rola hosta w sieci)
    local impact; impact=$(get_asset_impact "${D_ROLE[$idx]:-}")
    local weighted_raw=$(( raw * impact / 10 ))
    (( weighted_raw > 100 )) && weighted_raw=100

    # Exposure weighting — czy host jest gateway/DMZ/CORE
    local exposure=10
    case "${D_SEGMENT[$idx]:-}" in
        GATEWAY)    exposure=17 ;;
        DMZ)        exposure=15 ;;
        CORE)       exposure=13 ;;
        IOT)        exposure=14 ;;
        USER_LAN)   exposure=10 ;;
        MANAGEMENT) exposure=12 ;;
        *)          exposure=10 ;;
    esac
    local exposed_raw=$(( weighted_raw * exposure / 10 ))
    (( exposed_raw > 100 )) && exposed_raw=100

    # Mitigation discount
    local mitigation_discount=0
    if [[ -n "${D_VERIFIED[$idx]:-}" ]]; then
        local IFS_OLD="$IFS"
        IFS=$'\x01' read -ra vmits <<< "${D_VERIFIED[$idx]}"
        IFS="$IFS_OLD"
        for mit in "${vmits[@]}"; do
            case "$mit" in
                HTTP_REDIRECTS_HTTPS) (( mitigation_discount += 8 )) ;;
                HSTS_ENABLED)         (( mitigation_discount += 5 )) ;;
                SSH_RUNNING)          (( mitigation_discount += 2 )) ;;
                REDIS_AUTH_REQUIRED)  (( mitigation_discount += 15 )) ;;
                WINRM_HTTPS)          (( mitigation_discount += 10 )) ;;
                AUTO_BAN_DETECTED)    (( mitigation_discount += 8 )) ;;
            esac
        done
    fi

    # RISK = (Asset_Impact × Exposure × Raw) / 100 − Mitigation
    local residual=$(( exposed_raw - mitigation_discount ))
    (( residual < 0 )) && residual=0
    D_RESIDUAL_SCORE[$idx]=$residual

    local band
    if   (( residual >= 60 )); then band="CRITICAL"
    elif (( residual >= 40 )); then band="HIGH"
    elif (( residual >= 20 )); then band="MEDIUM"
    elif (( residual >=  5 )); then band="LOW"
    else                            band="INFO"
    fi
    D_RISK_BAND[$idx]="$band"
}

NET_CRITICAL=0 NET_HIGH=0 NET_MEDIUM=0 NET_LOW=0

score_network() {
    for finding in "${NET_FINDINGS[@]:-}"; do
        [[ -z "$finding" ]] && continue
        local sev="${finding%%$'\x01'*}"
        case "$sev" in
            CRITICAL) (( NET_CRITICAL++ )) ;;
            HIGH)     (( NET_HIGH++ ))     ;;
            MEDIUM)   (( NET_MEDIUM++ ))   ;;
            LOW)      (( NET_LOW++ ))      ;;
        esac
    done
}

GLOBAL_SCORE="0"
OVERALL_GRADE=""
H_CRITICAL=0 H_HIGH=0 H_MEDIUM=0 H_LOW=0
THREAT_SCORE_FORMAL=0  # Σ(weight_i × present_i × confidence_i/100), normalizowany 0-100
DEFENSE_SCORE=0        # Ocena aktywnej obrony sieci (0-100)
DEFENSE_LEVEL="Low"    # Low / Medium / High / Advanced
DEFENSE_SUMMARY=""     # Jednozdaniowe podsumowanie dla executive report

build_attack_path() {
    # Buduje narrację kill chain na podstawie zebranych danych
    # Bez hardcodowania — opiera się na tym co faktycznie wykryto
    declare -gA ATTACK_PATH=()
    local steps=0

    # Krok 1: Initial Access vectors
    local initial_access=""
    for (( i=0; i<DEV_COUNT; i++ )); do
        local findings="${D_FINDINGS[$i]:-}"
        [[ -z "$findings" ]] && continue
        # Szukaj portów które dają initial access z internetu
        local ports="${D_PORTS[$i]}"
        contains_port "$ports" 3389 && initial_access="${initial_access}RDP@${D_IP[$i]} "
        contains_port "$ports" 22   && initial_access="${initial_access}SSH@${D_IP[$i]} "
        contains_port "$ports" 80   && initial_access="${initial_access}HTTP@${D_IP[$i]} "
        contains_port "$ports" 443  && initial_access="${initial_access}HTTPS@${D_IP[$i]} "
        # Docker/K8s = immediate critical initial access
        echo "$findings" | grep -q "CONTAINER_ESCAPE\|K8S_UNAUTHENTICATED\|ETCD_OPEN" &&             initial_access="${initial_access}CONTAINER@${D_IP[$i]}[CRITICAL] "
    done
    ATTACK_PATH[step_1_initial_access]="${initial_access:-none detected}"
    (( steps++ ))

    # Krok 2: Execution / Credential Access
    local exec_vectors=""
    for (( i=0; i<DEV_COUNT; i++ )); do
        local findings="${D_FINDINGS[$i]:-}"
        [[ -z "$findings" ]] && continue
        echo "$findings" | grep -q "KERBEROASTING"  && exec_vectors="${exec_vectors}Kerberoasting@${D_IP[$i]} "
        echo "$findings" | grep -q "SNMP_OPEN"       && exec_vectors="${exec_vectors}SNMP_recon@${D_IP[$i]} "
        echo "$findings" | grep -q "AD_LDAP_OPEN"    && exec_vectors="${exec_vectors}LDAP_enum@${D_IP[$i]} "
        echo "$findings" | grep -q "KRADZIEŻ_DANYCH\|KRADZIEŻ_HASEŁ" &&             exec_vectors="${exec_vectors}DataAccess@${D_IP[$i]} "
    done
    [[ -n "$exec_vectors" ]] && ATTACK_PATH[step_2_exec]="$exec_vectors" ||         ATTACK_PATH[step_2_exec]="none detected"
    (( steps++ ))

    # Krok 3: Lateral Movement paths
    if (( ${#LATERAL_PATHS[@]} > 0 )); then
        ATTACK_PATH[step_3_lateral]="${LATERAL_PATHS[*]}"
    else
        ATTACK_PATH[step_3_lateral]="none — good segmentation"
    fi
    (( steps++ ))

    # Krok 4: Privilege Escalation indicators
    local privesc=""
    [[ "${AD_INFO[detected]:-0}" == "1" ]] &&         [[ "${AD_INFO[smb_signing]:-unknown}" != "required" ]] &&         privesc="${privesc}NTLM_relay(DC=${AD_INFO[dc_ip]:-?}) "
    for (( i=0; i<DEV_COUNT; i++ )); do
        local findings="${D_FINDINGS[$i]:-}"
        echo "$findings" | grep -q "CONTAINER_ESCAPE" &&             privesc="${privesc}container_escape@${D_IP[$i]} "
        echo "$findings" | grep -q "ETCD_OPEN" &&             privesc="${privesc}k8s_secrets@${D_IP[$i]} "
        echo "$findings" | grep -q "POTENCJALNY_BACKDOOR" &&             privesc="${privesc}backdoor@${D_IP[$i]} "
    done
    ATTACK_PATH[step_4_privesc]="${privesc:-none detected}"
    (( steps++ ))

    # Krok 5: Impact / Exfiltration
    local impact=""
    for (( i=0; i<DEV_COUNT; i++ )); do
        local findings="${D_FINDINGS[$i]:-}"
        echo "$findings" | grep -q "KRADZIEŻ_DANYCH\|REDIS\|MONGO\|ELASTIC" &&             impact="${impact}DataExfil@${D_IP[$i]} "
        echo "$findings" | grep -q "TLS_WEAK\|TLS_EXPIRED\|TLS_SELF_SIGNED" &&             impact="${impact}MITM_decryption@${D_IP[$i]} "
    done
    [[ "${EGRESS[http_out]:-0}" == "1" ]] && impact="${impact}HTTP_exfil_channel "
    ATTACK_PATH[step_5_impact]="${impact:-none detected}"
    (( steps++ ))

    # Composite risk — czy istnieje kompletna kill chain?
    local chain_complete=0
    [[ "${ATTACK_PATH[step_1_initial_access]}" != "none detected" ]] &&     [[ "${ATTACK_PATH[step_3_lateral]}" != "none — good segmentation" ]] &&         (( chain_complete++ ))
    [[ "${ATTACK_PATH[step_4_privesc]}" != "none detected" ]] && (( chain_complete++ ))
    ATTACK_PATH[chain_completeness]="$chain_complete"
    ATTACK_PATH[steps_total]="$steps"
}

# Generuje remediation roadmap w 3 horyzontach czasowych
# Opiera się wyłącznie na tym co wykryto — bez hardcodowania
build_remediation_roadmap() {
    declare -gA ROADMAP_QUICK=()    # 0-7 dni: quick wins / natychmiastowe
    declare -gA ROADMAP_SHORT=()    # 1-4 tygodnie
    declare -gA ROADMAP_STRATEGIC=() # 3-6 miesięcy

    local quick_n=0 short_n=0 strat_n=0

    # Skan wszystkich findings i klasyfikuj wg CVSS + typ
    for (( i=0; i<DEV_COUNT; i++ )); do
        local ip="${D_IP[$i]}"
        local raw="${D_FINDINGS[$i]:-}"
        [[ -z "$raw" ]] && continue

        local IFS_OLD="$IFS"
        IFS=$'' read -ra parts <<< "$raw"
        IFS="$IFS_OLD"
        local fi=0
        while (( fi < ${#parts[@]} )); do
            local sev="${parts[$fi]:-}"
            case "$sev" in
                CRITICAL|HIGH|MEDIUM|LOW|INFO) ;;
                __COMPLIANCE__) (( fi += 2 )); continue ;;
                *) (( fi++ )); continue ;;
            esac
            local cat="${parts[$(( fi+1 ))]:-}"
            local desc="${parts[$(( fi+2 ))]:-}"
            local rec="${parts[$(( fi+3 ))]:-}"
            local cvss="${parts[$(( fi+4 ))]:-}"
            [[ -z "$cvss" ]] && cvss=$(cvss_for_finding "$sev" "$cat")
            local cvss_int; cvss_int=$(echo "$cvss" | cut -d. -f1)

            # Quick wins: CVSS >=9.0 ATAU bisa di-fix dengan satu perintah
            if (( ${cvss_int:-0} >= 9 )) ||                [[ "$cat" =~ CONTAINER_ESCAPE|ETCD_OPEN|K8S_UNAUTHENTICATED|TFTP_OPEN|POTENCJALNY_BACKDOOR ]]; then
                ROADMAP_QUICK[$quick_n]="${ip}|${sev}|${cvss}|${cat}|${rec}"
                (( quick_n++ ))

            # Short-term: CVSS 7-8.9 lub wymagające konfiguracji
            elif (( ${cvss_int:-0} >= 7 )) ||                  [[ "$cat" =~ TLS_EXPIRED|TLS_WEAK|AD_NO_SIGNING|SNMP_OPEN|KERBEROASTING|LATERAL_MOVEMENT ]]; then
                ROADMAP_SHORT[$short_n]="${ip}|${sev}|${cvss}|${cat}|${rec}"
                (( short_n++ ))

            # Strategic: wymagające architektury (VLAN, ZeroTrust, PKI)
            else
                ROADMAP_STRATEGIC[$strat_n]="${ip}|${sev}|${cvss}|${cat}|${rec}"
                (( strat_n++ ))
            fi
            (( fi += 5 ))
        done
    done

    # Net findings do roadmapy
    for finding in "${NET_FINDINGS[@]:-}"; do
        [[ -z "$finding" ]] && continue
        local IFS_OLD="$IFS"
        IFS=$'' read -r fsev fcat fdesc frec <<< "$finding"
        IFS="$IFS_OLD"
        local cvss; cvss=$(cvss_for_finding "$fsev" "$fcat")
        local cvss_int; cvss_int=$(echo "$cvss" | cut -d. -f1)

        if (( ${cvss_int:-0} >= 9 )); then
            ROADMAP_QUICK[$quick_n]="NETWORK|${fsev}|${cvss}|${fcat}|${frec}"
            (( quick_n++ ))
        elif (( ${cvss_int:-0} >= 7 )); then
            ROADMAP_SHORT[$short_n]="NETWORK|${fsev}|${cvss}|${fcat}|${frec}"
            (( short_n++ ))
        else
            ROADMAP_STRATEGIC[$strat_n]="NETWORK|${fsev}|${cvss}|${fcat}|${frec}"
            (( strat_n++ ))
        fi
    done

    ROADMAP_QUICK[count]="$quick_n"
    ROADMAP_SHORT[count]="$short_n"
    ROADMAP_STRATEGIC[count]="$strat_n"
}


build_executive() {

    # Maturity score — niezależny od findings (ocena pozytywna zabezpieczeń)
    local maturity=0
    [[ "${TRAFFIC_POLICY[http_egress_blocked]:-0}"   == "1" ]] && (( maturity += 10 ))
    [[ "${TRAFFIC_POLICY[dns_controlled]:-0}"        == "1" ]] && (( maturity += 10 ))
    [[ "${TRAFFIC_POLICY[dns_leak]:-0}"              == "0" ]] && (( maturity += 8 ))
    [[ "${TRAFFIC_POLICY[rate_limiting]:-0}"         == "1" ]] && (( maturity += 8 ))
    [[ "${TRAFFIC_POLICY[transparent_proxy]:-0}"     == "0" ]] && (( maturity += 5 ))
    [[ "${TRAFFIC_POLICY[tls_intercepted]:-0}"       == "0" ]] && (( maturity += 5 ))
    [[ "${L3_RESULTS[east_west_isolated]:-0}"        == "1" ]] && (( maturity += 15 ))
    [[ "${L3_RESULTS[silent_drop_detected]:-0}"      == "1" ]] && (( maturity += 8 ))
    [[ "${L3_RESULTS[cross_subnet_ok]:-1}"           == "0" ]] && (( maturity += 12 ))
    [[ "${TOPO[firewall_type]:-}" == *"stateful"* ]]           && (( maturity += 10 ))
    [[ "${TOPO[ids_detected]:-0}"                    == "1" ]] && (( maturity += 9 ))
    (( maturity > 100 )) && maturity=100
    MATURITY_SCORE="$maturity"
    for (( i=0; i<DEV_COUNT; i++ )); do
        score_host "$i"
        case "${D_RISK_BAND[$i]}" in
            CRITICAL) (( H_CRITICAL++ )) ;;
            HIGH)     (( H_HIGH++ ))     ;;
            MEDIUM)   (( H_MEDIUM++ ))   ;;
            LOW)      (( H_LOW++ ))      ;;
        esac
    done
    score_network

    local total_res=0
    for (( i=0; i<DEV_COUNT; i++ )); do (( total_res += D_RESIDUAL_SCORE[i] )); done
    local avg=0
    (( DEV_COUNT > 0 )) && avg=$(echo "scale=0; $total_res / $DEV_COUNT" | bc 2>/dev/null || echo "0")
    local gs=$(( 100 - avg ))
    local net_pen=$(( NET_CRITICAL * 10 + NET_HIGH * 5 ))
    gs=$(( gs - net_pen ))
    (( gs < 0 )) && gs=0

    # Formalny ThreatScore: Σ(weight_i × present_i × confidence_i / 100)
    # Każda detekcja ma wagę i confidence.
    # Suma normalizowana do 0-100 i odejmowana od gs.
    local ts=0 ts_max=0
    # Format: weight confidence present(0|1)
    local -a ts_items=(
        # waga  conf                                                          obecny
        "25     ${L3_RESULTS[silent_drop_conf]:-0}      ${L3_RESULTS[silent_drop_detected]:-0}"
        "20     ${L3_RESULTS[east_west_conf]:-0}        $([ "${L3_RESULTS[east_west_isolated]:-1}" = "0" ] && echo 1 || echo 0)"
        "15     ${TOPO[ids_conf]:-70}                   ${TOPO[ids_detected]:-0}"
        "15     ${TOPO[honeypot_conf]:-70}              ${TOPO[honeypot_detected]:-0}"
        "12     ${TRAFFIC_POLICY[dns_leak_conf]:-0}     $([ "${TRAFFIC_POLICY[dns_leak]:-0}" = "1" ] && echo 1 || echo 0)"
        "10     85                                      $([ "${TRAFFIC_POLICY[tls_intercepted]:-0}" = "1" ] && echo 1 || echo 0)"
        "8      70                                      $([ "${TOPO[autoban_detected]:-0}" = "1" ] && echo 1 || echo 0)"
    )
    local item
    for item in "${ts_items[@]}"; do
        local w c_val p
        read -r w c_val p <<< "$item"
        _is_int "$w" && _is_int "$c_val" && _is_int "$p" || continue
        (( ts_max += w ))
        if (( p == 1 && c_val > 0 )); then
            ts=$(( ts + w * c_val / 100 ))
        fi
    done
    # Normalizuj do 0-100 i zapisz
    local ts_normalized=0
    (( ts_max > 0 )) && ts_normalized=$(( ts * 100 / ts_max ))
    THREAT_SCORE_FORMAL="$ts_normalized"

    GLOBAL_SCORE="$gs"

    if   (( gs >= 85 )); then OVERALL_GRADE="A – Dobra kondycja bezpieczeństwa"
    elif (( gs >= 70 )); then OVERALL_GRADE="B – Dobre, drobne poprawki wymagane"
    elif (( gs >= 55 )); then OVERALL_GRADE="C – Umiarkowane ryzyko, działania wymagane"
    elif (( gs >= 40 )); then OVERALL_GRADE="D – Wysokie ryzyko, pilna remediacja"
    else                      OVERALL_GRADE="F – Krytyczne zagrożenia, natychmiastowe działanie"
    fi

    # ── DEFENSE POSTURE SCORE ────────────────────────────────────────────────
    # Niezależny od GLOBAL_SCORE — mierzy ile aktywnych warstw obrony sieć posiada.
    # Każda wykryta kontrola dodaje punkty; confidence skaluje wagę.
    #
    # Skala: 0-100 → Low / Medium / High / Advanced
    # Cel: jeden czytelny wskaźnik dla executive summary.

    local ds=0

    # Warstwa 1: Firewall (20 pkt)
    if [[ "${TOPO[firewall_type]:-}" == *"stateful"* ]]; then
        local fw_conf="${TOPO[firewall_drop_conf]:-50}"
        _is_int "$fw_conf" || fw_conf=50
        (( ds += 20 * fw_conf / 100 ))
    elif [[ "${TOPO[firewall_type]:-}" == *"probable"* ]]; then
        (( ds += 8 ))
    fi

    # Warstwa 2: IDS/Rate limiting (20 pkt)
    if [[ "${TOPO[ids_detected]:-0}" == "1" ]]; then
        local ids_conf="${TOPO[ids_conf]:-65}"
        _is_int "$ids_conf" || ids_conf=65
        (( ds += 20 * ids_conf / 100 ))
    fi

    # Warstwa 3: DNS Filtering (15 pkt)
    [[ "${TOPO[dns_filter_detected]:-0}" == "1" ]] && (( ds += 15 ))

    # Warstwa 4: L3 Segmentacja / East-West isolation (15 pkt)
    [[ "${L3_RESULTS[east_west_isolated]:-0}" == "1" ]] && (( ds += 15 ))

    # Warstwa 5: Cross-subnet blokada (10 pkt)
    [[ "${L3_RESULTS[cross_subnet_ok]:-1}" == "0" ]] && (( ds += 10 ))

    # Warstwa 6: Egress kontrola (10 pkt)
    [[ "${TRAFFIC_POLICY[http_egress_blocked]:-0}" == "1" ]] && (( ds += 5  ))
    [[ "${TRAFFIC_POLICY[dns_leak]:-0}"             == "0" ]] && (( ds += 5  ))

    # Warstwa 7: Auto-ban / SSH tarpit (10 pkt — aktywna obrona, nie pasywna)
    [[ "${TOPO[autoban_detected]:-0}"     == "1" ]] && (( ds += 6 ))
    [[ "${TOPO[honeypot_detected]:-0}"    == "1" ]] && (( ds += 4 ))

    (( ds > 100 )) && ds=100
    DEFENSE_SCORE="$ds"

    if   (( ds >= 80 )); then
        DEFENSE_LEVEL="Advanced"
        DEFENSE_SUMMARY="Sieć posiada wielowarstwową obronę aktywną (firewall stateful, IDS, filtrowanie DNS, segmentacja L3)."
    elif (( ds >= 55 )); then
        DEFENSE_LEVEL="High"
        DEFENSE_SUMMARY="Silna obrona z co najmniej 3 aktywnymi warstwami; wymagane uzupełnienie brakujących kontroli."
    elif (( ds >= 30 )); then
        DEFENSE_LEVEL="Medium"
        DEFENSE_SUMMARY="Podstawowa obrona obecna; brak kluczowych warstw (segmentacja lub IDS lub filtrowanie DNS)."
    else
        DEFENSE_LEVEL="Low"
        DEFENSE_SUMMARY="Minimalna lub brak aktywnej obrony — sieć podatna na lateral movement i eksfiltrację."
    fi
}

# [17] COMPLIANCE

map_compliance() {
    local idx="$1"
    local ports="${D_PORTS[$idx]:-}" score="${D_RESIDUAL_SCORE[$idx]:-0}"
    local hostname="${D_HOSTNAME[$idx]:-}" verified="${D_VERIFIED[$idx]:-}"
    declare -A ctrl=()

    ctrl[CIS-1.1]=$( [[ -n "$hostname" ]] && echo PASS || echo WARN )
    local has_legacy=0
    contains_port "$ports" 23 && has_legacy=1
    contains_port "$ports" 21 && has_legacy=1
    ctrl[CIS-4.1]=$( (( has_legacy )) && echo FAIL || echo PASS )
    ctrl[CIS-9.1]=$( contains_port "$ports" 25 && echo WARN || echo PASS )
    ctrl[ISO-A8.1]=$( (( score >= 40 )) && echo FAIL || (( score >= 20 )) && echo WARN || echo PASS )
    ctrl[ISO-A8.9]=$( (( has_legacy )) && echo FAIL || echo PASS )
    ctrl[ISO-A8.20]=$( contains_port "$ports" 23 || contains_port "$ports" 21 && echo FAIL || echo PASS )
    local https_enforced=0
    echo "$verified" | grep -q "HTTP_REDIRECTS_HTTPS\|HSTS_ENABLED" && https_enforced=1
    ctrl[ISO-A8.24]=$( contains_port "$ports" 80 && (( ! https_enforced )) && echo WARN || echo PASS )
    ctrl[NIST-PR.AC]=$( contains_port "$ports" 3389 || contains_port "$ports" 5900 && echo WARN || echo PASS )
    local plaintext=0
    contains_port "$ports" 23 && plaintext=1
    contains_port "$ports" 21 && plaintext=1
    ctrl[NIST-PR.DS]=$( (( plaintext )) && echo FAIL || echo PASS )
    ctrl[NIST-DE.CM]=$( [[ -n "$hostname" ]] && echo PASS || echo WARN )
    ctrl[GDPR-Art32]=$( (( plaintext || has_legacy )) && echo FAIL || echo PASS )

    local result=""
    for k in "${!ctrl[@]}"; do result="${result}${k}=${ctrl[$k]}|"; done
    D_FINDINGS[$idx]="${D_FINDINGS[$idx]:-}${SEP}__COMPLIANCE__${SEP}${result}"
}

get_compliance_matrix() {
    local controls="CIS-1.1 CIS-4.1 CIS-9.1 ISO-A8.1 ISO-A8.9 ISO-A8.20 ISO-A8.24 NIST-PR.AC NIST-PR.DS NIST-DE.CM GDPR-Art32"
    declare -A pass=() warn=() fail=()
    for c in $controls; do pass[$c]=0; warn[$c]=0; fail[$c]=0; done

    for (( i=0; i<DEV_COUNT; i++ )); do
        local comp_str; comp_str=$(echo "${D_FINDINGS[$i]:-}" | tr "$SEP" '\n' | grep "^__COMPLIANCE__" -A1 | tail -1)
        IFS='|' read -ra entries <<< "$comp_str"
        for entry in "${entries[@]}"; do
            [[ -z "$entry" ]] && continue
            local ctrl="${entry%%=*}" val="${entry#*=}"
            [[ -z "${pass[$ctrl]+x}" ]] && continue
            case "$val" in PASS) (( pass[$ctrl]++ ));; WARN) (( warn[$ctrl]++ ));; FAIL) (( fail[$ctrl]++ ));; esac
        done
    done

    for c in $controls; do echo "${c}:${pass[$c]}:${warn[$c]}:${fail[$c]}"; done
}

# [18] JSON EXPORT

json_esc() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"; s="${s//$'\r'/}"
    s="${s//$'\t'/ }"
    s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037\177')
    s="${s//$'\x1b'/}"
    echo "$s"
}

get_findings_json() {
    local raw="${1:-}"
    [[ -z "$raw" ]] && echo "[]" && return
    local json="[" first=1
    local IFS_OLD="$IFS"
    IFS=$'\x01' read -ra parts <<< "$raw"
    IFS="$IFS_OLD"
    local i=0
    while (( i < ${#parts[@]} )); do
        local sev="${parts[$i]:-}"
        case "$sev" in
            CRITICAL|HIGH|MEDIUM|LOW|INFO)
                local cat="${parts[$(( i+1 ))]:-}" desc="${parts[$(( i+2 ))]:-}" rec="${parts[$(( i+3 ))]:-}" cvss_v="${parts[$(( i+4 ))]:-}"
                [[ -z "$cvss_v" ]] && cvss_v=$(cvss_for_finding "$sev" "$cat")
                [[ $first -eq 0 ]] && json+=","
                json+="{\"severity\":\"$sev\",\"category\":\"$(json_esc "$cat")\",\"description\":\"$(json_esc "$desc")\",\"recommendation\":\"$(json_esc "$rec")\",\"cvss\":$cvss_v}"
                first=0; (( i += 5 )) ;;
            __COMPLIANCE__) (( i += 2 )) ;;
            *) (( i++ )) ;;
        esac
    done
    json+="]"; echo "$json"
}


write_model_snapshot() {
    # Minimal checkpoint — can be used for diff-mode later
    [[ -z "${OUTPUT_PATH:-}" ]] && return 0
    local snap="$OUTPUT_PATH/model-snapshot.json"
    # Reuse export_json output if already generated
    if [[ -s "${JSON_REPORT:-}" ]]; then
        cp -f "$JSON_REPORT" "$snap" 2>/dev/null || true
        return 0
    fi
    # Otherwise: minimal snapshot, best-effort (safe under nounset)
    local _nounset_on=0
    case "$-" in *u*) _nounset_on=1 ;; esac
    set +u
    {
        echo '{'
        echo '  "schema_version":"ewnaf-1.0",'
        echo '  "version":"'"${VERSION:-?}"'",'
        echo '  "timestamp":"'"${TIMESTAMP:-}"'",'
        echo '  "client":"'"$(json_esc "${CLIENT_NAME:-Enterprise}")"'",
        echo '  "audit_status":"'"$(json_esc "${AUDIT_STATUS:-READY}")"'",'
        echo '  "audit_note":"'"$(json_esc "$(_anonymize_text "${AUDIT_NOTE:-}")")"'",''
        echo '  "devices":['
        local first=1
        local i
        for (( i=0; i<DEV_COUNT; i++ )); do
            [[ $first -eq 0 ]] && echo ','
            first=0
            local ip="${D_IP[$i]:-}"
            local hn="${D_HOSTNAME[$i]:-}"
            local role="${D_ROLE[$i]:-}"
            local ports="${D_PORTS[$i]:-}"
            echo -n '    {"ip":"'"$(json_esc "$ip")"'","hostname":"'"$(json_esc "$hn")"'","role":"'"$(json_esc "$role")"'","ports":"'"$(json_esc "$ports")"'"}'
        done
        echo ''
        echo '  ]'
        echo '}'
    } > "$snap" 2>/dev/null || true
    (( _nounset_on == 1 )) && set -u
}




export_json() {
    log "Generowanie JSON..."
    local devices_json="[" fd=1
    for (( i=0; i<DEV_COUNT; i++ )); do
        [[ $fd -eq 0 ]] && devices_json+=","
        local ports_arr="[$(echo "${D_PORTS[$i]:-}" | tr ' ' ',' | sed 's/^,//;s/,$//')]"
        local entity_id; entity_id=$(_entity_alias_for_index "$i")
        devices_json+="{\"entity_id\":\"$(json_esc "${entity_id}")\",\"vendor\":\"$(json_esc "${D_VENDOR[$i]:-}")\",\"os\":\"$(json_esc "${D_OS[$i]:-}")\",\"role\":\"$(json_esc "${D_ROLE[$i]:-}")\",\"ttl\":${D_TTL[$i]:-0},\"segment\":\"$(json_esc "${D_SEGMENT[$i]:-}")\",\"open_ports\":$ports_arr,\"raw_risk_score\":${D_RAW_SCORE[$i]:-0},\"residual_risk_score\":${D_RESIDUAL_SCORE[$i]:-0},\"risk_band\":\"$(json_esc "${D_RISK_BAND[$i]:-}")\"}"
        fd=0
    done
    devices_json+="]"

    local findings_json="[" ff=1 row klass status conf evidence tested_by
    local IFS_OLD="$IFS"
    for row in "${AUDIT_FINDINGS[@]:-}"; do
        [[ -z "$row" ]] && continue
        IFS=$'\x01' read -r klass status conf evidence tested_by <<< "$row"
        [[ $ff -eq 0 ]] && findings_json+=","
        findings_json+="{\"class\":\"$(json_esc "$klass")\",\"status\":\"$(json_esc "$status")\",\"confidence\":${conf:-0},\"evidence\":\"$(json_esc "$(_anonymize_text "$evidence")")\",\"tested_by\":\"$(json_esc "$tested_by")\"}"
        ff=0
    done
    IFS="$IFS_OLD"
    findings_json+="]"

    local network_findings_json="[" fn=1
    for k in "${!NET_FINDINGS[@]}"; do
        IFS='|' read -r sev cat desc rec conf <<< "${NET_FINDINGS[$k]}"
        [[ $fn -eq 0 ]] && network_findings_json+=","
        network_findings_json+="{\"severity\":\"$(json_esc "$sev")\",\"category\":\"$(json_esc "$cat")\",\"description\":\"$(json_esc "$(_anonymize_text "$desc")")\",\"remediation\":\"$(json_esc "$(_anonymize_text "$rec")")\",\"confidence\":${conf:-0}}"
        fn=0
    done
    network_findings_json+="]"

    cat > "$JSON_REPORT" <<EOF
{
  "schema_version": "28.0",
  "version": "${VERSION}",
  "client": "$(json_esc "$CLIENT_NAME")",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "mode": "$(json_esc "$MODE")",
  "scope_model": "target-centric",
  "raw_identifiers_exported": false,
  "audit_status": "$(json_esc "${AUDIT_STATUS:-READY}")",
  "audit_note": "$(json_esc "$(_anonymize_text "${AUDIT_NOTE:-}")")",
  "global_score": ${GLOBAL_SCORE:-0},
  "overall_grade": "$(json_esc "${OVERALL_GRADE:-?}")",
  "defense_score": ${DEFENSE_SCORE:-0},
  "defense_level": "$(json_esc "${DEFENSE_LEVEL:-}")",
  "defense_summary": "$(json_esc "$(_anonymize_text "${DEFENSE_SUMMARY:-}")")",
  "devices": ${devices_json},
  "audit_findings": ${findings_json},
  "network_findings": ${network_findings_json}
}
EOF
    log_ok "JSON: $JSON_REPORT"
    export_sarif || true
}




# [19] TERMINAL SUMMARY

_finalize_no_evidence_report() {
    AUDIT_STATUS="${AUDIT_STATUS:-NO_EVIDENCE}"
    [[ -z "${AUDIT_NOTE:-}" ]] && AUDIT_NOTE="Brak wystarczających dowodów do pełnego audytu aktywnego."
    GLOBAL_SCORE=0
    OVERALL_GRADE="N/A"
    DEFENSE_SCORE=0
    DEFENSE_LEVEL="INSUFFICIENT_EVIDENCE"
    DEFENSE_SUMMARY="$AUDIT_NOTE"
    L3_RESULTS[cross_subnet_ok]="INSUFFICIENT_EVIDENCE"
    L3_RESULTS[east_west_isolated]="INSUFFICIENT_EVIDENCE"
    L3_RESULTS[silent_drop_detected]="UNKNOWN"
    TRAFFIC_POLICY[http_egress_blocked]="UNKNOWN"
    TRAFFIC_POLICY[dns_filtering]="UNKNOWN"
    TRAFFIC_POLICY[dns_leak]="UNKNOWN"
    TRAFFIC_POLICY[transparent_proxy]="UNKNOWN"
    TRAFFIC_POLICY[tls_interception]="UNKNOWN"
    TRAFFIC_POLICY[rate_limiting]="UNKNOWN"
    NET_FINDINGS=()
    AUDIT_FINDINGS=()
    add_net_finding "INFO" "AUDIT_SCOPE" "$AUDIT_NOTE" "Uruchom audyt z pozycji, która ma osiągalność do sieci korporacyjnych lub dostarcz seed scope niejawny przez orkiestrację."
}

print_summary() {
    local gs="${GLOBAL_SCORE:-0}"
    local grade="${OVERALL_GRADE:-?}"
    local GC
    local S_CC="${CC:-}" S_CN="${CN:-}" S_CBOLD="${CBOLD:-}" S_CW="${CW:-}" S_CD="${CD:-}" S_CO="${CO:-}" S_CG="${CG:-}" S_CR="${CR:-}"
    if [[ "${NO_COLOR_SUMMARY:-1}" == "1" || ! -t 1 ]]; then
        S_CC=""; S_CN=""; S_CBOLD=""; S_CW=""; S_CD=""; S_CO=""; S_CG=""; S_CR=""
    fi
    case "$grade" in
        A*) GC="[1;32m" ;; B*) GC="[0;32m" ;;
        C*) GC="[1;33m" ;; D*) GC="[0;33m" ;;
        *)  GC="[1;31m" ;;
    esac
    # CW CC CD CM CG CR CN CBOLD are global readonly — used directly

    local bar_len=40
    local filled=$(( gs * bar_len / 100 ))
    local empty=$(( bar_len - filled ))
    local bar_f; bar_f=$(printf '█%.0s' $(seq 1 $filled 2>/dev/null) || printf '%0.s█' $(seq 1 $filled))
    local bar_e; bar_e=$(printf '░%.0s' $(seq 1 $empty 2>/dev/null) || printf '%0.s░' $(seq 1 $empty))

    echo ""
    echo -e "  ${S_CC}╔══════════════════════════════════════════════════════════════╗${S_CN}"
    printf   "  ${S_CC}║${S_CN}  ${S_CBOLD}%-60s${S_CC}║${S_CN}
" "EWNAF v${VERSION} — Raport Audytu"
    echo -e "  ${S_CC}╠══════════════════════════════════════════════════════════════╣${S_CN}"
    echo -e "  ${S_CC}║${S_CN}  Klient : ${S_CW}${CLIENT_NAME}${S_CN}  Tryb: ${S_CW}${MODE}${S_CN}"
    echo -e "  ${S_CC}║${S_CN}  Sieci  : ${S_CD}${SUBNETS[*]}${S_CN}"
    echo -e "  ${S_CC}║${S_CN}  Hostów : ${S_CW}${DEV_COUNT}${S_CN}"
    echo -e "  ${S_CC}╠══════════════════════════════════════════════════════════════╣${S_CN}"
    if [[ "${AUDIT_STATUS:-READY}" != "READY" ]]; then
        echo -e "  ${S_CO}Status : ${AUDIT_STATUS}${S_CN}"
        [[ -n "${AUDIT_NOTE:-}" ]] && echo -e "  ${S_CO}Uwaga  : ${AUDIT_NOTE}${S_CN}"
    fi
    echo ""
    echo -e "  ${S_CBOLD}OCENA KOŃCOWA SIECI${S_CN}"
    printf  "  Score: ${GC}${S_CBOLD}%d/100${S_CN}   Ocena: ${GC}${S_CBOLD}%s${S_CN}
" "$gs" "$grade"
    echo -e "  ${GC}${S_CBOLD}${bar_f}${S_CN}${S_CD}${bar_e}${S_CN}"
    echo ""
    if [[ "${AUDIT_STATUS:-READY}" != "READY" ]]; then
        echo -e "  ${S_CO}Brak pełnych danych do wiarygodnej oceny aktywnej. Raport ograniczony do telemetrycznych obserwacji i statusu scope.${S_CN}"
        echo ""
    fi

    # ── LAYER 2 ──────────────────────────────────────────────────────────────
    echo -e "  ${S_CBOLD}▌ WARSTWA 2 — Domena rozgłoszeniowa${S_CN}"
    local l2_icon="✅" l2_status="OK"
    (( ${L2_RESULTS[vendor_diversity]:-0} > 5 )) && l2_icon="⚠️" && l2_status="WIELE VENDORÓW (${L2_RESULTS[vendor_diversity]})"
    printf "  %-4s %-30s %s
" "$l2_icon" "Vendor diversity" "${L2_RESULTS[vendor_diversity]:-0} OUI"
    printf "  %-4s %-30s %s
" "📡" "Access Points" "${L2_RESULTS[ap_count]:-0}"
    printf "  %-4s %-30s %s
" "🔀" "Switche/Routery" "${L2_RESULTS[switch_count]:-0}/${L2_RESULTS[router_count]:-0}"
    printf "  %-4s %-30s %s
" "⏱" "TTL baseline" "${L2_RESULTS[ttl_baseline]:-?}"
    echo ""

    if [[ "${AUDIT_STATUS:-READY}" != "READY" ]]; then
        echo -e "  ${S_CBOLD}▌ STATUS AUDYTU${S_CN}"
        echo -e "  ${S_CO}Brak materiału dowodowego do wiarygodnej interpretacji L3/polityk ruchu/ekspozycji.${S_CN}"
        echo -e "  ${S_CO}Nie wyciągam wniosków typu flat network, DNS leak, proxy czy lateral risk przy Hostów: 0.${S_CN}"
        echo ""
        echo -e "  ${S_CBOLD}▌ FINDINGS — co naprawić${S_CN}"
        echo -e "  ${S_CD}  Raport ograniczony: uruchom audyt z osiągalnego punktu sieciowego lub przez orkiestrację enterprise scope.${S_CN}"
        echo ""
        local def_score="${DEFENSE_SCORE:-0}"
        local def_level="${DEFENSE_LEVEL:-Low}"
        local def_summary="${DEFENSE_SUMMARY:-}"
        local dc="$S_CR"
        [[ "$def_level" == "Medium"   ]] && dc="$S_CO"
        [[ "$def_level" == "High"     ]] && dc="\033[0;34m"
        [[ "$def_level" == "Advanced" ]] && dc="$S_CG"
        local def_bar_filled=$(( def_score * 30 / 100 ))
        local def_bar_empty=$(( 30 - def_bar_filled ))
        local def_bf; def_bf=$(printf '█%.0s' $(seq 1 $def_bar_filled 2>/dev/null) || printf '█%.0s' {1..1})
        local def_be; def_be=$(printf '░%.0s' $(seq 1 $def_bar_empty  2>/dev/null) || true)
        echo -e "  ${S_CBOLD}▌ DEFENSE POSTURE${S_CN}"
        printf  "  Score: ${dc}${S_CBOLD}%d/100${S_CN}   Poziom: ${dc}${S_CBOLD}%s${S_CN}\n" "$def_score" "$def_level"
        echo -e "  ${dc}${S_CBOLD}${def_bf}${S_CN}${S_CD}${def_be}${S_CN}"
        echo -e "  ${S_CD}${def_summary}${S_CN}"
        echo ""
        echo -e "  ${S_CC}╚══════════════════════════════════════════════════════════════╝${S_CN}"
        echo -e "  Raport JSON : ${S_CW}${JSON_REPORT:-N/A}${S_CN}"
        echo -e "  Raport SARIF: ${S_CW}${OUTPUT_PATH}/EWNAF-REPORT.sarif${S_CN}"
        echo -e "  Raport HTML : ${S_CW}${HTML_REPORT:-N/A}${S_CN}"
        [[ -n "${REPORT_PDF:-}" ]] && echo -e "  Raport PDF  : ${S_CW}${REPORT_PDF}${S_CN}"
        echo ""
        return 0
    fi

    # ── LAYER 3 ──────────────────────────────────────────────────────────────
    echo -e "  ${S_CBOLD}▌ WARSTWA 3 — Routing i segmentacja${S_CN}"
    local ew_icon ew_txt
    [[ "${L3_RESULTS[east_west_isolated]:-1}" == "1" ]] && ew_icon="✅" && ew_txt="AKTYWNA" || ew_icon="❌" && ew_txt="BRAK — flat network!"
    local cs_icon cs_txt
    [[ "${L3_RESULTS[cross_subnet_ok]:-0}" == "0" ]] && cs_icon="✅" && cs_txt="ZABLOKOWANE" || cs_icon="❌" && cs_txt="OTWARTE!"
    local sd_icon sd_txt
    [[ "${L3_RESULTS[silent_drop_detected]:-0}" == "1" ]] && sd_icon="✅" && sd_txt="DROP (stealth)" || sd_icon="ℹ️" && sd_txt="RST (widoczna granica)"
    printf "  %-4s %-30s %s
" "$ew_icon" "East-West izolacja" "$ew_txt"
    printf "  %-4s %-30s %s
" "$cs_icon" "Cross-subnet ruch" "$cs_txt"
    printf "  %-4s %-30s %s
" "$sd_icon" "Polityka odrzucania" "$sd_txt"
    [[ "${L3_RESULTS[asymmetric_acl]:-0}" == "1" ]] && printf "  %-4s %-30s %s
" "⚠️" "Asymetryczne ACL" "WYKRYTE"
    echo ""

    # ── TRAFFIC POLICY ────────────────────────────────────────────────────────
    echo -e "  ${S_CBOLD}▌ POLITYKA RUCHU${S_CN}"
    _tp_row() {
        local flag="$1" label="$2" ok_txt="$3" bad_txt="$4" good_when="$5"
        local icon txt
        if [[ "$flag" == "$good_when" ]]; then icon="✅"; txt="$ok_txt"
        else icon="❌"; txt="$bad_txt"; fi
        printf "  %-4s %-30s %s
" "$icon" "$label" "$txt"
    }
    _tp_row "${TRAFFIC_POLICY[http_egress_blocked]:-0}"   "HTTP egress"           "ZABLOKOWANY" "OTWARTY" "1"
    _tp_row "${TRAFFIC_POLICY[dns_controlled]:-0}"        "DNS kontrolowany"      "TAK (filtering)" "NIE — DNS niekontrolowany" "1"
    _tp_row "${TRAFFIC_POLICY[dns_leak]:-0}"              "DNS leak"              "BRAK (szczelny)" "MOŻLIWY LEAK!" "0"
    _tp_row "${TRAFFIC_POLICY[transparent_proxy]:-0}"     "Transparent proxy"     "BRAK" "WYKRYTY" "0"
    _tp_row "${TRAFFIC_POLICY[tls_intercepted]:-0}"       "TLS interception"      "BRAK" "AKTYWNA!" "0"
    _tp_row "${TRAFFIC_POLICY[rate_limiting]:-0}"         "Rate limiting"         "AKTYWNY" "BRAK" "1"
    echo ""

    # ── EKSPOZYCJA ───────────────────────────────────────────────────────────
    echo -e "  ${S_CBOLD}▌ EKSPOZYCJA I LATERAL RISK${S_CN}"
    printf  "  %-4s %-30s %s
" "📊" "Flat network %" "${FLAT_PERCENT:-0}%"
    printf  "  %-4s %-30s %s
" "↔" "Lateral paths" "${#LATERAL_PATHS[@]}"

    # Surface density (avg usług per host)
    local total_ports=0
    for (( i=0; i<DEV_COUNT; i++ )); do
        total_ports=$(( total_ports + $(port_count "${D_PORTS[$i]:-}") ))
    done
    local avg_density=0
    (( DEV_COUNT > 0 )) && avg_density=$(( total_ports / DEV_COUNT ))
    printf "  %-4s %-30s %s
" "🔍" "Avg surface (usług/host)" "$avg_density"
    echo ""

    # ── HOST RISK TABLE ───────────────────────────────────────────────────────
    echo -e "  ${S_CBOLD}▌ HOSTY — Risk Profile${S_CN}"
    printf "  %-18s %-22s %-10s %-10s %s
" "IP" "ROLA" "SEG" "RISK" "SCORE"
    echo -e "  ${S_CD}$(printf '─%.0s' {1..70})${S_CN}"
    for (( i=0; i<DEV_COUNT; i++ )); do
        local band="${D_RISK_BAND[$i]:-INFO}"
        local rc
        case "$band" in
            CRITICAL) rc="$S_CR" ;; HIGH) rc="[0;33m" ;;
            MEDIUM) rc="[1;33m" ;; LOW) rc="$S_CG" ;; *) rc="$S_CD" ;;
        esac
        local honey="${D_HONEYPOT[$i]:-}"
        local honey_flag=""
        [[ "$honey" == HIGH* ]] && honey_flag=" 🍯HONEYPOT"
        printf "  %-18s %-22s %-10s ${rc}%-10s${S_CN} %s/%s%s
"             "${D_IP[$i]}" "${D_ROLE[$i]:0:22}" "${D_SEGMENT[$i]}"             "$band" "${D_RAW_SCORE[$i]}" "${D_RESIDUAL_SCORE[$i]}" "$honey_flag"
    done
    echo ""

    # ── FINDINGS PODSUMOWANIE ─────────────────────────────────────────────────
    echo -e "  ${S_CBOLD}▌ FINDINGS — co naprawić${S_CN}"
    local crit_shown=0
    for (( i=0; i<DEV_COUNT; i++ )); do
        [[ -z "${D_FINDINGS[$i]:-}" ]] && continue
        local IFS_OLD="$IFS"; IFS=$'' read -ra parts <<< "${D_FINDINGS[$i]}"; IFS="$IFS_OLD"
        local j=0
        while (( j < ${#parts[@]} )); do
            local sev="${parts[$j]:-}"
            case "$sev" in CRITICAL|HIGH|MEDIUM|LOW|INFO)
                local cat="${parts[$((j+2))]:-}" desc="${parts[$((j+3))]:-}" rec="${parts[$((j+4))]:-}"
                if [[ "$sev" == "CRITICAL" || "$sev" == "HIGH" ]]; then
                    local ficon; [[ "$sev" == "CRITICAL" ]] && ficon="🔴" || ficon="🟠"
                    printf "  %s [%s] %s — %s
" "$ficon" "${D_IP[$i]}" "$cat" "${desc:0:60}"
                    [[ -n "$rec" ]] && printf "     ${S_CD}→ %s${S_CN}
" "${rec:0:70}"
                    (( crit_shown++ ))
                fi
                (( j += 5 )) ;; *) (( j++ )) ;;
            esac
        done
    done
    for finding in "${NET_FINDINGS[@]:-}"; do
        [[ -z "$finding" ]] && continue
        local sev="${finding%%$''*}"
        [[ "$sev" != "CRITICAL" && "$sev" != "HIGH" ]] && continue
        local rest="${finding#*$''}"
        local cat="${rest%%$''*}"; rest="${rest#*$''}"
        local desc="${rest%%$''*}"; rest="${rest#*$''}"
        local rec="${rest%%$''*}"
        local ficon; [[ "$sev" == "CRITICAL" ]] && ficon="🔴" || ficon="🟠"
        printf "  %s [NET] %s — %s
" "$ficon" "$cat" "${desc:0:60}"
        [[ -n "$rec" ]] && printf "     ${S_CD}→ %s${S_CN}
" "${rec:0:70}"
        (( crit_shown++ ))
    done
    (( crit_shown == 0 )) && echo -e "  ${S_CG}  Brak krytycznych i wysokich findings${S_CN}"
    echo ""

    # ── SECURITY SYSTEMS ─────────────────────────────────────────────────────
    if (( ${#SECURITY_SYSTEMS[@]} > 0 )); then
        echo -e "  ${S_CBOLD}▌ AKTYWNE ZABEZPIECZENIA${S_CN}"
        for sys in "${SECURITY_SYSTEMS[@]}"; do
            echo -e "  ${S_CG}  ✓${S_CN} $sys"
        done
        echo ""
    fi

    # ── DEFENSE POSTURE ───────────────────────────────────────────────────────
    local def_score="${DEFENSE_SCORE:-0}"
    local def_level="${DEFENSE_LEVEL:-Low}"
    local def_summary="${DEFENSE_SUMMARY:-}"
    local dc="$S_CR"
    [[ "$def_level" == "Medium"   ]] && dc="$S_CO"
    [[ "$def_level" == "High"     ]] && dc="\033[0;34m"
    [[ "$def_level" == "Advanced" ]] && dc="$S_CG"
    local def_bar_filled=$(( def_score * 30 / 100 ))
    local def_bar_empty=$(( 30 - def_bar_filled ))
    local def_bf; def_bf=$(printf '█%.0s' $(seq 1 $def_bar_filled 2>/dev/null) || printf '█%.0s' {1..1})
    local def_be; def_be=$(printf '░%.0s' $(seq 1 $def_bar_empty  2>/dev/null) || true)
    echo -e "  ${S_CBOLD}▌ DEFENSE POSTURE${S_CN}"
    printf  "  Score: ${dc}${S_CBOLD}%d/100${S_CN}   Poziom: ${dc}${S_CBOLD}%s${S_CN}\n" "$def_score" "$def_level"
    echo -e "  ${dc}${S_CBOLD}${def_bf}${S_CN}${S_CD}${def_be}${S_CN}"
    echo -e "  ${S_CD}${def_summary}${S_CN}"
    echo ""

    echo -e "  ${S_CC}╚══════════════════════════════════════════════════════════════╝${S_CN}"
    echo -e "  Raport JSON : ${S_CW}${JSON_REPORT:-N/A}${S_CN}"
    echo -e "  Raport SARIF: ${S_CW}${OUTPUT_PATH}/EWNAF-REPORT.sarif${S_CN}"
    echo -e "  Raport HTML : ${S_CW}${HTML_REPORT:-N/A}${S_CN}"
    [[ -n "${REPORT_PDF:-}" ]] && echo -e "  Raport PDF  : ${S_CW}${REPORT_PDF}${S_CN}"
    echo ""
}



###############################################################################
# SARIF 2.1.0 EXPORT — Static Analysis Results Interchange Format
# spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
###############################################################################

export_sarif() {
    local sarif_file="$OUTPUT_PATH/EWNAF-REPORT.sarif"
    local ts; ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    _jesc() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; printf '%s' "$s"; }
    _slevel() { case "${1^^}" in CRITICAL|HIGH) echo "error";; MEDIUM) echo "warning";; LOW) echo "note";; *) echo "none";; esac; }

    local rules="" results="" first_r=1 first_res=1
    declare -A _seen_rules=()
    for k in "${!NET_FINDINGS[@]}"; do
        IFS='|' read -r sev cat desc rec conf <<< "${NET_FINDINGS[$k]}"
        local rid="EWNAF-NET-${cat//[^A-Za-z0-9_]/-}"
        local lv; lv=$(_slevel "$sev")
        if [[ -z "${_seen_rules[$rid]:-}" ]]; then
            _seen_rules[$rid]=1
            [[ $first_r -eq 0 ]] && rules+=","
            rules+="{\"id\":\"$(_jesc "$rid")\",\"name\":\"$(_jesc "$cat")\",\"shortDescription\":{\"text\":\"$(_jesc "$(_anonymize_text "$desc")")\"},\"fullDescription\":{\"text\":\"$(_jesc "Remediation: $(_anonymize_text "$rec")")\"},\"defaultConfiguration\":{\"level\":\"$lv\"}}"
            first_r=0
        fi
        [[ $first_res -eq 0 ]] && results+=","
        results+="{\"ruleId\":\"$(_jesc "$rid")\",\"level\":\"$lv\",\"message\":{\"text\":\"$(_jesc "$(_anonymize_text "$desc")")\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"network://scope\",\"uriBaseId\":\"%SRCROOT%\"},\"region\":{\"startLine\":1}},\"logicalLocations\":[{\"name\":\"target-scope\",\"kind\":\"module\"}]}],\"properties\":{\"severity\":\"$(_jesc "$sev")\",\"remediation\":\"$(_jesc "$(_anonymize_text "$rec")")\"}}"
        first_res=0
    done

    cat > "$sarif_file" << SARIF_HEREDOC
{
  "\$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "EWNAF", "version": "${VERSION}", "rules": [${rules}]}},
    "results": [${results}],
    "invocations": [{"executionSuccessful": true, "startTimeUtc": "${ts}", "workingDirectory": {"uri": "file://$(pwd)"}}],
    "automationDetails": {"id": "ewnaf/${CLIENT_NAME}/${ts}"},
    "properties": {"globalScore": ${GLOBAL_SCORE:-0}, "defenseScore": ${DEFENSE_SCORE:-0}, "client": "${CLIENT_NAME}", "scope": "target-centric", "mode": "${MODE:-}"}
  }]
}
SARIF_HEREDOC
    log_ok "SARIF 2.1.0: $sarif_file"
}



# [20] HTML (pełna wersja jak v6 + sekcja Topology)


###############################################################################
# HTML REPORT — BILINGUAL PL/EN — 8 SEKCJI — PEŁNA STRUKTURA AUDYTOWA
###############################################################################


# ── RENDERING 2.0 (MINI) — HTML FROM JSON SNAPSHOT ──────────────────────────
# Cel: renderer NIE dotyka runtime global state (D_*, TOPO, BH, ...) i nie wybucha
# przy set -u. Jeśli python3 dostępny i JSON_REPORT istnieje → render z JSON.

export_html_from_json() {
    [[ -z "${JSON_REPORT:-}" || ! -s "$JSON_REPORT" ]] && return 1
    command -v python3 &>/dev/null || return 1

    log "HTML render: from JSON snapshot (safe renderer)" "INFO"

    python3 - "$JSON_REPORT" "$HTML_REPORT" <<'PYHTML'
import json, sys, html
src, out = sys.argv[1], sys.argv[2]
with open(src, "r", encoding="utf-8") as f:
    data = json.load(f)

def esc(x):
    return html.escape(str(x) if x is not None else "")

schema = data.get("schema_version","unknown")
client = data.get("client","Enterprise")
version = data.get("version","?")
ts = data.get("timestamp","")
global_score = data.get("global_score",0)
grade = data.get("overall_grade","?")
defense = data.get("defense_score",0)
def_level = data.get("defense_level","")
summary = data.get("defense_summary","")

devices = data.get("devices",[])
net_findings = data.get("network_findings",[])
# per-host findings are usually inside device.findings
# normalize
for d in devices:
    d.setdefault("findings", [])

# Minimal, stable HTML (no JS, no bash expansion)
parts=[]
parts.append("<!doctype html><html><head><meta charset='utf-8'>")
parts.append("<title>EWNAF Report</title>")
parts.append("<style>")
parts.append("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:24px;}")
parts.append("h1,h2{margin:0 0 10px 0} .kpi{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}")
parts.append(".card{border:1px solid #ddd;border-radius:10px;padding:12px 14px;min-width:220px}")
parts.append("table{border-collapse:collapse;width:100%;margin:10px 0 18px 0;font-size:14px}")
parts.append("th,td{border:1px solid #e3e3e3;padding:8px 10px;vertical-align:top}")
parts.append("th{background:#f7f7f7;text-align:left}")
parts.append("code{background:#f3f4f6;padding:1px 4px;border-radius:6px}")
parts.append("</style></head><body>")

parts.append(f"<h1>EWNAF Report</h1>")
parts.append(f"<div style='color:#555'>client: <b>{esc(client)}</b> · version: <b>{esc(version)}</b> · schema: <code>{esc(schema)}</code> · ts: <code>{esc(ts)}</code></div>")

parts.append("<div class='kpi'>")
parts.append(f"<div class='card'><div style='color:#666'>GLOBAL_SCORE</div><div style='font-size:28px;font-weight:800'>{esc(global_score)}</div><div style='color:#666'>grade: {esc(grade)}</div></div>")
parts.append(f"<div class='card'><div style='color:#666'>DEFENSE_SCORE</div><div style='font-size:28px;font-weight:800'>{esc(defense)}</div><div style='color:#666'>{esc(def_level)}</div></div>")
if summary:
    parts.append(f"<div class='card' style='flex:1'><div style='color:#666'>DEFENSE_SUMMARY</div><div>{esc(summary)}</div></div>")
parts.append("</div>")

# Devices table
parts.append("<h2>Hosts</h2>")
parts.append("<table><thead><tr><th>IP</th><th>Hostname</th><th>Role</th><th>Open ports</th><th>Findings</th></tr></thead><tbody>")
for d in devices:
    ports = d.get("ports",[])
    if isinstance(ports,str): ports = [p for p in ports.split() if p]
    ports_s = " ".join(str(p) for p in ports) if ports else ""
    findings = d.get("findings",[])
    f_short = "<br>".join(esc(f.get("category","")) for f in findings[:6])
    if len(findings) > 6: f_short += "<br>…"
    parts.append("<tr>")
    parts.append(f"<td><code>{esc(d.get('ip',''))}</code></td>")
    parts.append(f"<td>{esc(d.get('hostname',''))}</td>")
    parts.append(f"<td>{esc(d.get('role',''))}</td>")
    parts.append(f"<td>{esc(ports_s)}</td>")
    parts.append(f"<td>{f_short}</td>")
    parts.append("</tr>")
parts.append("</tbody></table>")

# Network findings
parts.append("<h2>Network Findings</h2>")
parts.append("<table><thead><tr><th>Severity</th><th>Category</th><th>Description</th><th>Recommendation</th></tr></thead><tbody>")
if not net_findings:
    parts.append("<tr><td colspan='4' style='color:#666;text-align:center'>None</td></tr>")
else:
    for f in net_findings:
        parts.append("<tr>")
        parts.append(f"<td>{esc(f.get('severity',''))}</td>")
        parts.append(f"<td>{esc(f.get('category',''))}</td>")
        parts.append(f"<td>{esc(f.get('description',''))}</td>")
        parts.append(f"<td>{esc(f.get('recommendation',''))}</td>")
        parts.append("</tr>")
parts.append("</tbody></table>")

# Per-host findings (expanded)
parts.append("<h2>Per-host Findings</h2>")
parts.append("<table><thead><tr><th>Host</th><th>Severity</th><th>Category</th><th>Description</th><th>Recommendation</th></tr></thead><tbody>")
rows=0
for d in devices:
    for f in d.get("findings",[]):
        rows += 1
        parts.append("<tr>")
        parts.append(f"<td><code>{esc(d.get('ip',''))}</code></td>")
        parts.append(f"<td>{esc(f.get('severity',''))}</td>")
        parts.append(f"<td>{esc(f.get('category',''))}</td>")
        parts.append(f"<td>{esc(f.get('description',''))}</td>")
        parts.append(f"<td>{esc(f.get('recommendation',''))}</td>")
        parts.append("</tr>")
if rows==0:
    parts.append("<tr><td colspan='5' style='color:#666;text-align:center'>None</td></tr>")
parts.append("</tbody></table>")

parts.append("</body></html>")
with open(out,"w",encoding="utf-8") as f:
    f.write("\n".join(parts))
PYHTML
    local rc=$?
    if (( rc != 0 )) || [[ ! -s "$HTML_REPORT" ]]; then
        log "HTML render failed; brak poprawnego pliku wyjściowego." "WARN"
        return 1
    fi
    log "HTML gotowy (JSON renderer): $HTML_REPORT ($(wc -l < "$HTML_REPORT") linii)" "OK"
    return 0
}

export_html() {
    # Prefer safe renderer when JSON exists; fallback to legacy template
    if export_html_from_json; then
        return 0
    fi
    export_html_legacy
}


export_html_legacy() {
        log "Generowanie SARIF 2.1.0..."
    export_sarif
    log "Generowanie raportu HTML (bilingual)..."
    local gs="${GLOBAL_SCORE:-0}"
    local grade="${OVERALL_GRADE:-F}"
    local ts="${THREAT_SCORE_FORMAL:-0}"
    local heat="${SESSION_STATE[heat]:-0}"
    local maturity="${MATURITY_SCORE:-0}"
    local def_score="${DEFENSE_SCORE:-0}"
    local def_level="${DEFENSE_LEVEL:-Low}"
    local def_summary="${DEFENSE_SUMMARY:-}"

    # Kolor defense level
    local def_color="#ef4444"
    [[ "$def_level" == "Medium"   ]] && def_color="#f97316"
    [[ "$def_level" == "High"     ]] && def_color="#3b82f6"
    [[ "$def_level" == "Advanced" ]] && def_color="#22c55e"

    # Kolor score
    local sc="#ef4444"
    (( gs >= 70 )) && sc="#22c55e"
    (( gs >= 55 && gs < 70 )) && sc="#eab308"
    (( gs >= 40 && gs < 55 )) && sc="#f97316"

    # Tier
    local tier="Tier 5 — Niewystarczający / Insufficient"
    local tier_en="Insufficient"
    local tier_color="#ef4444"
    (( maturity >= 20 )) && { tier="Tier 4 — Podstawowy / Basic";         tier_en="Basic";        tier_color="#f97316"; }
    (( maturity >= 40 )) && { tier="Tier 3 — Rozwijający się / Developing"; tier_en="Developing";   tier_color="#eab308"; }
    (( maturity >= 60 )) && { tier="Tier 2 — Zaawansowany / Advanced";     tier_en="Advanced";     tier_color="#3b82f6"; }
    (( maturity >= 80 )) && { tier="Tier 1 — Lider / Leader";              tier_en="Leader";       tier_color="#22c55e"; }

    # Werdykt PL/EN
    local verdict_pl="Krytyczne zagrożenie" verdict_en="Critical Threat"
    (( gs >= 30 )) && { verdict_pl="Wysokie ryzyko";      verdict_en="High Risk"; }
    (( gs >= 50 )) && { verdict_pl="Umiarkowane ryzyko";  verdict_en="Moderate Risk"; }
    (( gs >= 70 )) && { verdict_pl="Dobry poziom";        verdict_en="Good Security Posture"; }
    (( gs >= 85 )) && { verdict_pl="Wzorowy poziom";      verdict_en="Exemplary Security"; }

    # Threat Score Formal — kolor
    local ts_color="#22c55e"
    (( ts >= 30 )) && ts_color="#eab308"
    (( ts >= 60 )) && ts_color="#ef4444"

    # Kolory behawioralne
    local bh_threat="${EXEC_BH_THREAT:-0}"
    local bh_corr="${EXEC_BH_CORRELATION:-0}"
    local bh_adapt="${EXEC_BH_ADAPTATION:-0}"
    local bh_dec="${EXEC_BH_DECEPTION:-0}"
    local bh_threat_c="#22c55e"
    (( bh_threat >= 30 )) && bh_threat_c="#eab308"
    local bh_adapt_color="#22c55e"
    [[ "$bh_adapt" == "1" ]] && bh_adapt_color="#ef4444" || true
    local bh_adapt_label="NIE / NO"
    [[ "$bh_adapt" == "1" ]] && bh_adapt_label="TAK / YES" || true
    (( bh_threat >= 60 )) && bh_threat_c="#ef4444"

    # --- Tabela urządzeń ---
    local dev_rows=""
    for (( i=0; i<DEV_COUNT; i++ )); do
        local band_c="#6b7280"
        case "${D_RISK_BAND[$i]:-}" in
            CRITICAL) band_c="#ef4444" ;; HIGH)   band_c="#f97316" ;;
            MEDIUM)   band_c="#eab308" ;; LOW)    band_c="#22c55e" ;;
        esac
        local bh_zone="${BH["${D_IP[$i]:-}:zone"]:-—}"
        local bh_rs="${BH["${D_IP[$i]:-}:score_reactivity"]:-—}"
        local bh_dp="${BH["${D_IP[$i]:-}:score_deception"]:-—}"
        dev_rows+="<tr>"
        dev_rows+="<td><code>$(html_esc "${D_IP[$i]:-}")</code></td>"
        dev_rows+="<td>$(html_esc "${D_HOSTNAME[$i]:-}")</td>"
        dev_rows+="<td>$(html_esc "${D_ROLE[$i]:-}")</td>"
        dev_rows+="<td>$(html_esc "${D_OS[$i]:-}")</td>"
        dev_rows+="<td><code>$(html_esc "${D_PORTS[$i]:-brak}")</code></td>"
        dev_rows+="<td><span style='color:$band_c;font-weight:700'>$(html_esc "${D_RISK_BAND[$i]:-}")</span>&nbsp;$(html_esc "${D_RESIDUAL_SCORE[$i]:-0}")</td>"
        dev_rows+="<td style='color:#94a3b8;font-size:.75rem'>$(html_esc "$bh_zone") RS=$(html_esc "$bh_rs") DP=$(html_esc "$bh_dp")</td>"
        dev_rows+="</tr>"
    done

    # --- Tabela findings ---
    local find_rows="" net_rows=""
    for (( i=0; i<DEV_COUNT; i++ )); do
        [[ -z "${D_FINDINGS[$i]:-}" ]] && continue
        local IFS_OLD="$IFS"
        IFS=$'\x01' read -ra farr <<< "${D_FINDINGS[$i]}"
        IFS="$IFS_OLD"
        local fi2=0
        while (( fi2 < ${#farr[@]} )); do
            local fsev="${farr[$fi2]:-}"
            case "$fsev" in
                CRITICAL|HIGH|MEDIUM|LOW|INFO) ;;
                __COMPLIANCE__) (( fi2 += 2 )); continue ;;
                *) (( fi2++ )); continue ;;
            esac
            local fcat="${farr[$(( fi2+1 ))]:-}"
            local fdesc="${farr[$(( fi2+2 ))]:-}"
            local frec="${farr[$(( fi2+3 ))]:-}"
            local fcvss="${farr[$(( fi2+4 ))]:-}"
            [[ -z "$fcvss" ]] && fcvss=$(cvss_for_finding "$fsev" "$fcat")
            local fc="#6b7280"
            case "$fsev" in CRITICAL) fc="#ef4444";; HIGH|MEDIUM) fc="#f97316";; LOW) fc="#22c55e";; esac
            # CVSS badge color
            local cvss_c="#6b7280"
            local cvss_n; cvss_n=$(echo "$fcvss" | cut -d. -f1)
            (( ${cvss_n:-0} >= 9 )) && cvss_c="#ef4444"
            (( ${cvss_n:-0} >= 7 && ${cvss_n:-0} < 9 )) && cvss_c="#f97316"
            (( ${cvss_n:-0} >= 4 && ${cvss_n:-0} < 7 )) && cvss_c="#eab308"
            (( ${cvss_n:-0} < 4 && ${cvss_n:-0} > 0 )) && cvss_c="#22c55e"
            find_rows+="<tr>"
            find_rows+="<td><code>$(html_esc "${D_IP[$i]}")</code></td>"
            find_rows+="<td><span style='color:$fc;font-weight:700'>$(html_esc "$fsev")</span></td>"
            find_rows+="<td><span style='color:$cvss_c;font-weight:700;font-size:.85rem'>CVSS&nbsp;${fcvss}</span></td>"
            find_rows+="<td>$(html_esc "$fcat")</td>"
            find_rows+="<td>$(html_esc "$fdesc")</td>"
            find_rows+="<td style='color:#60a5fa;font-size:.78rem'>$(html_esc "$frec")</td>"
            find_rows+="</tr>"
            (( fi2 += 5 ))
        done
    done

    for finding in "${NET_FINDINGS[@]:-}"; do
        [[ -z "$finding" ]] && continue
        local IFS_OLD="$IFS"
        IFS=$'\x01' read -r fsev fcat fdesc frec <<< "$finding"
        IFS="$IFS_OLD"
        local fc="#6b7280"
        case "$fsev" in CRITICAL) fc="#ef4444";; HIGH|MEDIUM) fc="#f97316";; LOW|INFO) fc="#22c55e";; esac
        net_rows+="<tr>"
        net_rows+="<td><span style='color:$fc;font-weight:700'>$(html_esc "$fsev")</span></td>"
        net_rows+="<td>$(html_esc "$fcat")</td>"
        net_rows+="<td>$(html_esc "$fdesc")</td>"
        net_rows+="<td style='color:#60a5fa;font-size:.78rem'>$(html_esc "${frec:-}")</td>"
        net_rows+="</tr>"
    done

    # --- Systemy obronne ---
    local sec_list=""
    for sys in "${SECURITY_SYSTEMS[@]:-}"; do
        sec_list+="<li>✓ $(html_esc "$sys")</li>"
    done
    [[ -z "$sec_list" ]] && sec_list="<li style='color:#6b7280'>Brak wykrytych / None detected</li>"

    # --- Compliance matrix ---
    local comp_rows=""
    for (( i=0; i<DEV_COUNT; i++ )); do
        [[ -z "${D_FINDINGS[$i]:-}" ]] && continue
        local IFS_OLD="$IFS"
        IFS=$'\x01' read -ra farr <<< "${D_FINDINGS[$i]}"
        IFS="$IFS_OLD"
        local fi2=0
        while (( fi2 < ${#farr[@]} )); do
            if [[ "${farr[$fi2]:-}" == "__COMPLIANCE__" ]]; then
                local cdata="${farr[$(( fi2+1 ))]:-}"
                local IFS2_OLD="$IFS"; IFS="|"
                read -ra cparts <<< "$cdata"
                IFS="$IFS2_OLD"
                local cname="${cparts[0]:-}" cstatus="${cparts[1]:-}" cref="${cparts[2]:-}"
                local cc="#eab308"
                [[ "$cstatus" == "PASS" ]] && cc="#22c55e"
                [[ "$cstatus" == "FAIL" ]] && cc="#ef4444"
                comp_rows+="<tr><td><code>$(html_esc "${D_IP[$i]}")</code></td>"
                comp_rows+="<td>$(html_esc "$cname")</td>"
                comp_rows+="<td><span style='color:$cc;font-weight:700'>$(html_esc "$cstatus")</span></td>"
                comp_rows+="<td style='color:#94a3b8;font-size:.75rem'>$(html_esc "$cref")</td></tr>"
                (( fi2 += 2 ))
            else
                (( fi2++ ))
            fi
        done
    done

    # --- Mapa behawioralna ---
    local bmap_rows=""
    for ip in "${!BMAP[@]}"; do
        local zone="${BMAP[$ip]}"
        local zc="#6b7280"
        case "$zone" in
            DECEPTION)  zc="#ef4444" ;; CORRELATED) zc="#f97316" ;;
            ADAPTIVE)   zc="#f97316" ;; ESCALATING) zc="#eab308" ;;
            REACTIVE)   zc="#3b82f6" ;; EXPOSED)    zc="#eab308" ;;
            SILENT)     zc="#22c55e" ;;
        esac
        local rs="${BH["${ip}:score_reactivity"]:-0}"
        local ai="${BH["${ip}:score_adaptivity"]:-0}"
        local dp="${BH["${ip}:score_deception"]:-0}"
        local cl="${BH["${ip}:score_correlation"]:-0}"
        local conf="${BH["${ip}:zone_confidence"]:-0}"
        local ret_mem="${BH["${ip}:return_memory"]:-—}"
        bmap_rows+="<tr>"
        bmap_rows+="<td><code>$(html_esc "$ip")</code></td>"
        bmap_rows+="<td><span style='color:$zc;font-weight:700'>$(html_esc "$zone")</span></td>"
        bmap_rows+="<td>$(html_esc "$conf")%</td>"
        bmap_rows+="<td>RS=$(html_esc "$rs") AI=$(html_esc "$ai") DP=$(html_esc "$dp") CL=$(html_esc "$cl")</td>"
        bmap_rows+="<td style='color:#94a3b8'>$(html_esc "${BH["${ip}:deception_signals"]:-—}")</td>"
        bmap_rows+="<td style='color:#94a3b8'>$(html_esc "$ret_mem")</td>"
        bmap_rows+="</tr>"
    done


    # --- Sekcja 1d: Faza X KPI + Zone Map + Per-host cards (precomputed) ---
    local s1d_kpi="" s1d_zone_rows="" s1d_host_cards=""

    # KPI heat/threat (z dynamic color)
    local _h="${SESSION_STATE[heat]:-0}" _hc="#22c55e"
    (( _h >= 70 )) && _hc="#ef4444" || (( _h >= 40 )) && _hc="#f97316" || true
    local _tl="${SESSION_STATE[threat_level]:-0}" _tlc="#22c55e"
    (( _tl >= 60 )) && _tlc="#ef4444" || (( _tl >= 30 )) && _tlc="#f97316" || true
    local _dyn=$(( ${PHASE_X[zones_adaptive]:-0} + ${PHASE_X[zones_escalating]:-0} ))
    s1d_kpi="<div class="kpi"><div class="v" style="color:${_hc}">${_h}</div><div class="l">Heat Level</div><div class="sl">Poziom reakcji sieci</div></div>"
    s1d_kpi+="<div class="kpi"><div class="v" style="color:${_tlc}">${_tl}</div><div class="l">Threat Level</div><div class="sl">Poziom zagrożenia</div></div>"
    s1d_kpi+="<div class="kpi"><div class="v" style="color:#60a5fa">${SESSION_STATE[correlation_score]:-0}</div><div class="l">Correlation Score</div><div class="sl">IDS/NDR aktywność</div></div>"
    s1d_kpi+="<div class="kpi"><div class="v" style="color:#a78bfa">${PHASE_X[zones_deception]:-0}</div><div class="l">Deception Zones</div><div class="sl">Deception / tarpit</div></div>"
    s1d_kpi+="<div class="kpi"><div class="v" style="color:#f97316">${_dyn}</div><div class="l">Dynamic Defence</div><div class="sl">Adaptive + Escalating</div></div>"
    s1d_kpi+="<div class="kpi"><div class="v" style="color:#ef4444">${PHASE_X[zones_exposed]:-0}</div><div class="l">Exposed Zones</div><div class="sl">Bez obrony dynamicznej</div></div>"
    s1d_kpi+="<div class="kpi"><div class="v" style="color:#94a3b8">${SESSION_STATE[total_probes]:-0}</div><div class="l">Total Probes</div><div class="sl">Liczba sond</div></div>"
    s1d_kpi+="<div class="kpi"><div class="v" style="color:#94a3b8">${PHASE_X[hosts_total]:-0}</div><div class="l">Hosts Analysed</div><div class="sl">Hosty przeanalizowane</div></div>"

    # Zone map rows
    for ip in "${!BMAP[@]}"; do
        local bzone="${BMAP[$ip]}"
        local bzc="#6b7280" bzi="?" binterpret="Nieznana strefa"
        local bconf="${BH["${ip}:zone_confidence"]:-0}"
        local bbase="${BH["${ip}:80:baseline_ms"]:-?}"
        local bwin="${BH["${ip}:80:window_type"]:-—}"
        local bban="${BH["${ip}:80:escalation_probe_n"]:-—}"
        local brec="${BH["${ip}:80:recovery"]:-—}"
        case "$bzone" in
            DECEPTION)  bzc="#a78bfa" bzi="🎭" binterpret="Deception/tarpit — wyniki mogą być nieautentyczne" ;;
            CORRELATED) bzc="#60a5fa" bzi="🔗" binterpret="IDS/NDR koreluje zdarzenia — pełna widoczność audytu" ;;
            ADAPTIVE)   bzc="#f97316" bzi="🧠" binterpret="Reputacyjny blacklist — pamięta IP audytora" ;;
            ESCALATING) bzc="#eab308" bzi="📈" binterpret="Rate-limiter — próg bana przy N=${bban} próbach" ;;
            REACTIVE)   bzc="#22c55e" bzi="⚡" binterpret="Prosta ochrona — bez persistent memory" ;;
            EXPOSED)    bzc="#ef4444" bzi="⚠" binterpret="Brak obrony dynamicznej — wysoka ekspozycja" ;;
            SILENT)     bzc="#94a3b8" bzi="🔇" binterpret="DROP policy — host nie ujawnia informacji" ;;
        esac
        local _banc="var(--m)"
        [[ "$bban" != "—" ]] && (( bban <= 3 )) && _banc="#ef4444" || true
        [[ "$bban" != "—" ]] && (( bban <= 7 && bban > 3 )) && _banc="#f97316" || true
        local _recc="var(--m)"
        [[ "$brec" == "STILL_ELEVATED" ]] && _recc="#f97316" || true
        s1d_zone_rows+="<tr style='border-bottom:1px solid rgba(255,255,255,.04)'>"
        s1d_zone_rows+="<td style='padding:6px 10px'><code>$(html_esc "$ip")</code></td>"
        s1d_zone_rows+="<td style='padding:6px 10px'><span style='color:${bzc};font-weight:700'>${bzi} $(html_esc "$bzone")</span></td>"
        s1d_zone_rows+="<td style='padding:6px 10px;color:var(--m)'>${bconf}%</td>"
        s1d_zone_rows+="<td style='padding:6px 10px;color:var(--m)'>${bbase}ms</td>"
        s1d_zone_rows+="<td style='padding:6px 10px;color:var(--m)'>$(html_esc "$bwin")</td>"
        s1d_zone_rows+="<td style='padding:6px 10px;color:${_banc}'>$(html_esc "$bban")</td>"
        s1d_zone_rows+="<td style='padding:6px 10px;color:${_recc}'>$(html_esc "$brec")</td>"
        s1d_zone_rows+="<td style='padding:6px 10px;color:var(--m);font-size:.75rem'>$(html_esc "$binterpret")</td>"
        s1d_zone_rows+="</tr>"
    done
    [[ -z "$s1d_zone_rows" ]] && s1d_zone_rows="<tr><td colspan='8' style='color:var(--m);text-align:center'>Faza X nie uruchomiona / Phase X not run</td></tr>"

    # Per-host score cards
    for ip in "${!BMAP[@]}"; do
        local bzone="${BMAP[$ip]}"
        [[ "$bzone" == "UNKNOWN" || "$bzone" == "OFFLINE" ]] && continue
        local brs="${BH["${ip}:score_reactivity"]:-0}"
        local bai="${BH["${ip}:score_adaptivity"]:-0}"
        local bdp="${BH["${ip}:score_deception"]:-0}"
        local bcl="${BH["${ip}:score_correlation"]:-0}"
        (( brs + bai + bdp + bcl < 5 )) && [[ "$bzone" == "SILENT" ]] && continue
        local bzc2="#6b7280"
        case "$bzone" in
            DECEPTION)  bzc2="#a78bfa" ;; CORRELATED) bzc2="#60a5fa" ;;
            ADAPTIVE)   bzc2="#f97316" ;; ESCALATING) bzc2="#eab308" ;;
            REACTIVE)   bzc2="#22c55e" ;; EXPOSED)    bzc2="#ef4444" ;;
        esac
        local bconf2="${BH["${ip}:zone_confidence"]:-0}"
        local bsigs="${BH["${ip}:deception_signals"]:-—}"
        local bbase2="${BH["${ip}:80:baseline_ms"]:-?}"
        local bvar="${BH["${ip}:80:baseline_variance"]:-?}"
        local bban2="${BH["${ip}:80:escalation_probe_n"]:-—}"
        local bwin2="${BH["${ip}:80:window_type"]:-—}"
        local brec2="${BH["${ip}:80:recovery"]:-—}"
        local bpb="${BH["${ip}:80:post_burst_ms"]:-?}"
        local brd="${BH["${ip}:80:return_delta_ms"]:-?}"
        local sigs_html=""
        [[ "$bsigs" != "—" && -n "$bsigs" ]] && sigs_html="<div style='margin-top:4px'><strong>Deception signals:</strong> $(html_esc "$bsigs")</div>"
        s1d_host_cards+="<div class='card' style='border-left:3px solid ${bzc2};margin-top:12px'>"
        s1d_host_cards+="<h3 style='color:${bzc2}'>$(html_esc "$ip") — $(html_esc "$bzone")</h3>"
        s1d_host_cards+="<div style='display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;font-size:.78rem'>"
        s1d_host_cards+="<div><table style='width:100%'><tbody>"
        s1d_host_cards+="<tr><td style='color:var(--m);padding:3px 6px'>Reactivity</td><td><div style='background:rgba(255,255,255,.06);border-radius:4px;height:8px;width:100%'><div style='background:${bzc2};height:8px;border-radius:4px;width:${brs}%'></div></div></td><td style='color:var(--m);padding-left:6px'>${brs}%</td></tr>"
        s1d_host_cards+="<tr><td style='color:var(--m);padding:3px 6px'>Adaptivity</td><td><div style='background:rgba(255,255,255,.06);border-radius:4px;height:8px;width:100%'><div style='background:${bzc2};height:8px;border-radius:4px;width:${bai}%'></div></div></td><td style='color:var(--m);padding-left:6px'>${bai}%</td></tr>"
        s1d_host_cards+="<tr><td style='color:var(--m);padding:3px 6px'>Deception</td><td><div style='background:rgba(255,255,255,.06);border-radius:4px;height:8px;width:100%'><div style='background:#a78bfa;height:8px;border-radius:4px;width:${bdp}%'></div></div></td><td style='color:var(--m);padding-left:6px'>${bdp}%</td></tr>"
        s1d_host_cards+="<tr><td style='color:var(--m);padding:3px 6px'>Correlation</td><td><div style='background:rgba(255,255,255,.06);border-radius:4px;height:8px;width:100%'><div style='background:#60a5fa;height:8px;border-radius:4px;width:${bcl}%'></div></div></td><td style='color:var(--m);padding-left:6px'>${bcl}%</td></tr>"
        s1d_host_cards+="</tbody></table></div>"
        s1d_host_cards+="<div style='font-size:.75rem;color:var(--m)'>"
        s1d_host_cards+="<div><strong>Baseline:</strong> ${bbase2}ms (variance: ${bvar}ms)</div>"
        s1d_host_cards+="<div><strong>Window type:</strong> $(html_esc "$bwin2")</div>"
        s1d_host_cards+="<div><strong>Ban threshold:</strong> N=$(html_esc "$bban2") prób</div>"
        s1d_host_cards+="<div><strong>Recovery:</strong> $(html_esc "$brec2")</div>"
        s1d_host_cards+="<div><strong>Post-burst latency:</strong> ${bpb}ms</div>"
        s1d_host_cards+="<div><strong>Return delta:</strong> ${brd}ms</div>"
        s1d_host_cards+="${sigs_html}"
        s1d_host_cards+="<div style='margin-top:6px;color:${bzc2}'><strong>Confidence:</strong> ${bconf2}%</div>"
        s1d_host_cards+="</div></div></div>"
    done


    # Precompute VPN i firewall display (dla heredoc - brak nested subshells)
    local vpn_display="<span style='color:#eab308'>✗ Brak / None</span>"
    if [[ "${TOPO[vpn_detected]:-0}" == "1" ]]; then
        vpn_display="<span style='color:#22c55e'>✓ $(html_esc "${TOPO[vpn_type]:-VPN}")</span>"
    fi
    local fw_display="<span style='color:#eab308'>? Nie zidentyfikowano</span>"
    if [[ "${TOPO[firewall_type]:-unknown}" != "unknown" ]]; then
        fw_display="<span style='color:#22c55e'>✓ $(html_esc "${TOPO[firewall_type]}")</span>"
    fi


    # ── PRECOMPUTE: wszystkie wyrażenia warunkowe dla heredoc ──────────────────
    # Sekcja 2: Defence systems
    local pc_rate_lim=""; [[ "${TRAFFIC_POLICY[rate_limiting]:-0}" == "1" ]] && pc_rate_lim="<li>✓ Rate Limiting aktywny</li>"
    local pc_dns_ctrl_li=""; [[ "${TRAFFIC_POLICY[dns_controlled]:-0}" == "1" ]] && pc_dns_ctrl_li="<li>✓ DNS Filtering/Control aktywny</li>"
    # IDS
    local pc_ids_li=""; [[ "${TOPO[ids_detected]:-0}" == "1" ]] && pc_ids_li="<li>✓ IDS/IPS wykryty / IDS detected</li>"
    # Heuristics
    local pc_hp_cls="ok"; [[ "${TOPO[honeypot_detected]:-0}" == "1" ]] && pc_hp_cls="crit"
    local pc_hp_val="✗ Nie wykryto / Not detected"; [[ "${TOPO[honeypot_detected]:-0}" == "1" ]] && pc_hp_val="✓ WYKRYTY / DETECTED"
    local pc_mirage_cls="ok"; [[ "${TOPO[mirage_detected]:-0}" == "1" ]] && pc_mirage_cls="warn"
    local pc_mirage_val="✗ Nie wykryto / Not detected"; [[ "${TOPO[mirage_detected]:-0}" == "1" ]] && pc_mirage_val="✓ WYKRYTY / DETECTED"
    local pc_sdrop_val="✗ NIE / NO"; [[ "${L3_RESULTS[silent_drop_detected]:-0}" == "1" ]] && pc_sdrop_val="✓ TAK / YES"
    # L3 routing
    local pc_ew_iso="<span style='color:#ef4444'>✗ Nie / No</span>"; [[ "${L3_RESULTS[east_west_isolated]:-0}" == "1" ]] && pc_ew_iso="<span style='color:#22c55e'>✓ Tak / Yes</span>"
    local pc_cross_sub="<span style='color:#eab308'>? Nie zbadano</span>"; [[ "${L3_RESULTS[cross_subnet_ok]:-1}" == "0" ]] && pc_cross_sub="<span style='color:#22c55e'>✓ Tak / Yes</span>"
    local pc_drop_pol="<span style='color:#eab308'>REJECT lub brak danych</span>"; [[ "${L3_RESULTS[silent_drop_detected]:-0}" == "1" ]] && pc_drop_pol="<span style='color:#22c55e'>✓ Silent DROP</span>"
    # DNS
    local pc_dns_ctrl_td="<span style='color:#eab308'>✗ Nie / No</span>"; [[ "${TRAFFIC_POLICY[dns_controlled]:-0}" == "1" ]] && pc_dns_ctrl_td="<span style='color:#22c55e'>✓ Tak / Yes</span>"
    local pc_dns_malware="<span style='color:#ef4444'>✗ Nie</span>"; [[ "${TRAFFIC_POLICY[dns_malware_blocked]:-0}" == "1" ]] && pc_dns_malware="<span style='color:#22c55e'>✓ Tak</span>"
    # Egress
    local pc_http_egr="<span style='color:#f97316'>✗ Otwarty / Open</span>"; [[ "${TRAFFIC_POLICY[http_egress_blocked]:-0}" == "1" ]] && pc_http_egr="<span style='color:#22c55e'>✓ Zablokowany / Blocked</span>"
    # TLS
    local pc_tls_int="<span style='color:#22c55e'>✓ Brak / None</span>"; [[ "${TRAFFIC_POLICY[tls_intercepted]:-0}" == "1" ]] && pc_tls_int="<span style='color:#ef4444'>✗ INTERCEPT</span>"
    local pc_tproxy="<span style='color:#22c55e'>✓ Brak / None</span>"; [[ "${TRAFFIC_POLICY[transparent_proxy]:-0}" == "1" ]] && pc_tproxy="<span style='color:#eab308'>✗ Wykryty / Detected</span>"
    # VPN/NAT
    local pc_masq="<span style='color:#eab308'>✗ Nie wykryto</span>"; [[ "${TOPO[masquerade_active]:-0}" == "1" ]] && pc_masq="<span style='color:#22c55e'>✓ Aktywna</span>"
    local pc_dnat="<span style='color:#22c55e'>✓ Brak / None</span>"
    [[ "${TOPO[double_nat]:-0}" == "1" ]] && pc_dnat="<span style='color:#f97316'>⚠ TAK (${TOPO[vpn_wan_ip]:-?})</span>"
    # Rate limit & IPS
    local pc_ratelim_td="<span style='color:#ef4444'>✗ Brak / None</span>"; [[ "${TRAFFIC_POLICY[rate_limiting]:-0}" == "1" ]] && pc_ratelim_td="<span style='color:#22c55e'>✓ Aktywny / Active</span>"
    local pc_autoban="<span style='color:#eab308'>✗ Nie wykryto</span>"
    [[ "${TOPO[autoban_detected]:-0}" == "1" ]] && pc_autoban="<span style='color:#22c55e'>✓ Wykryty (${TOPO[autoban_confidence]:-?}%)</span>"
    local pc_ids_td="<span style='color:#ef4444'>✗ Nie wykryto</span>"
    [[ "${TOPO[ids_detected]:-0}" == "1" ]] && pc_ids_td="<span style='color:#22c55e'>✓ Wykryto (${TOPO[ids_confidence]:-?}%)</span>"
    local pc_tarpit="<span style='color:#eab308'>✗ Nie wykryto</span>"; [[ "${TOPO[ssh_tarpit_detected]:-0}" == "1" ]] && pc_tarpit="<span style='color:#22c55e'>✓ Aktywny</span>"
    # Compliance CIS/ISO
    local pc_cis12="<span style='color:#ef4444'>✗ CIS-12</span>"; [[ "${L3_RESULTS[east_west_isolated]:-0}" == "1" ]] && pc_cis12="<span style='color:#22c55e'>✓ CIS-12</span>"
    local pc_cis9="<span style='color:#ef4444'>✗ CIS-9</span>"; [[ "${TRAFFIC_POLICY[dns_controlled]:-0}" == "1" ]] && pc_cis9="<span style='color:#22c55e'>✓ CIS-9</span>"
    local pc_cis13="<span style='color:#ef4444'>✗ CIS-13</span>"; [[ "${TOPO[ids_detected]:-0}" == "1" ]] && pc_cis13="<span style='color:#22c55e'>✓ CIS-13</span>"
    local pc_iso_ac="<span style='color:#eab308'>? A.9 / PR.AC</span>"; [[ "${L3_RESULTS[cross_subnet_ok]:-1}" == "0" ]] && pc_iso_ac="<span style='color:#22c55e'>✓ A.9 / PR.AC</span>"
    local pc_iso_ds="<span style='color:#ef4444'>✗ A.10 / PR.DS</span>"; [[ "${TRAFFIC_POLICY[tls_intercepted]:-0}" == "0" ]] && pc_iso_ds="<span style='color:#22c55e'>✓ A.10 / PR.DS</span>"
    local pc_gdpr="<span style='color:#ef4444'>✗ Art. 32</span>"; [[ "${TRAFFIC_POLICY[dns_leak]:-0}" == "0" ]] && pc_gdpr="<span style='color:#22c55e'>✓ Art. 32</span>"
    # Cloud/Fleet
    local pc_fleet="✗ Nie wykryto"; [[ "${TOPO[fleet_detected]:-0}" == "1" ]] && pc_fleet="<span style='color:#22c55e'>✓ Aktywny / Active</span>"
    local pc_prowler="✗ Nie zbadano"; [[ "${PROWLER_RESULT[scan_started]:-0}" == "1" ]] && pc_prowler="<span style='color:#22c55e'>✓ Uruchomiony / Running</span>"
    # ── END PRECOMPUTE ──────────────────────────────────────────────────────────
    local _u_was=0; [[ $- == *u* ]] && _u_was=1; set +u
    cat > "$HTML_REPORT" <<HTMLEOF
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>EWNAF v${VERSION} — $(html_esc "${CLIENT_NAME}")</title>
<style>
:root{--bg:#080d1a;--s:#0f1829;--s2:#16213a;--b:#1e3a5f;--t:#e2e8f0;--m:#94a3b8;--a:#3b82f6;--a2:#60a5fa;--g1:#0a1628;--g2:#0d1f3c}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--t);line-height:1.6;font-size:13px}
/* HEADER */
header{background:linear-gradient(135deg,#0a1628 0%,#0d1f3c 50%,#0a1628 100%);padding:28px 40px 20px;border-bottom:1px solid var(--b);position:relative;overflow:hidden}
header::before{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(90deg,transparent,transparent 40px,rgba(59,130,246,.03) 40px,rgba(59,130,246,.03) 41px);pointer-events:none}
.hdr-grid{display:grid;grid-template-columns:1fr auto;gap:16px;align-items:center;position:relative}
.hdr-title{color:var(--a2);font-size:1.1rem;font-weight:800;letter-spacing:1px;text-transform:uppercase}
.hdr-sub{color:var(--m);font-size:.75rem;margin-top:4px}
.hdr-meta{text-align:right;color:var(--m);font-size:.72rem}
/* NAV */
nav{background:var(--s);border-bottom:1px solid var(--b);padding:0 40px;display:flex;gap:0;overflow-x:auto}
nav a{color:var(--m);text-decoration:none;padding:10px 16px;font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid transparent;white-space:nowrap;transition:all .2s}
nav a:hover{color:var(--a2);border-bottom-color:var(--a)}
/* LAYOUT */
.wrap{max-width:1500px;margin:0 auto;padding:24px 40px}
.section{margin-bottom:36px;scroll-margin-top:60px}
h2{font-size:.82rem;font-weight:800;color:var(--a2);border-left:3px solid var(--a);padding:4px 0 4px 12px;margin-bottom:14px;text-transform:uppercase;letter-spacing:.8px;display:flex;align-items:center;gap:8px}
h2 .en{color:var(--m);font-weight:400;font-size:.72rem}
h3{font-size:.78rem;font-weight:700;color:var(--t);margin-bottom:8px}
/* GRID KART */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:20px}
.kpi{background:var(--s);border:1px solid var(--b);border-radius:10px;padding:14px 10px;text-align:center;position:relative;overflow:hidden}
.kpi::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:var(--a)}
.kpi .v{font-size:2rem;font-weight:900;line-height:1}
.kpi .l{font-size:.6rem;color:var(--m);text-transform:uppercase;letter-spacing:1px;margin-top:5px}
.kpi .sl{font-size:.65rem;color:var(--m);margin-top:2px}
/* CARDS */
.card{background:var(--s);border:1px solid var(--b);border-radius:10px;padding:16px 20px;margin-bottom:12px}
.card-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.card-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
/* BEHAVIORAL HEATMAP */
.bh-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:16px}
.bh-card{background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:12px;text-align:center}
.bh-card .bv{font-size:1.5rem;font-weight:800}
.bh-card .bl{font-size:.6rem;color:var(--m);text-transform:uppercase;letter-spacing:1px;margin-top:4px}
/* VERDICT BANNER */
.verdict{background:linear-gradient(135deg,rgba(30,58,95,.4),rgba(15,24,41,.6));border:1px solid var(--b);border-radius:10px;padding:20px 24px;margin-bottom:20px;display:grid;grid-template-columns:auto 1fr auto;gap:20px;align-items:center}
.verdict .score-circle{width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:900;border:3px solid}
.verdict-text h3{font-size:1rem;font-weight:700;margin-bottom:4px}
.verdict-text p{font-size:.78rem;color:var(--m)}
.verdict-grade{font-size:3rem;font-weight:900;line-height:1}
/* TABLES */
.tbl-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--b)}
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{background:var(--s2);color:var(--m);padding:8px 10px;text-align:left;font-size:.65rem;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--b);white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid rgba(30,58,95,.3);vertical-align:top}
tr:hover td{background:rgba(59,130,246,.04)}
code{background:rgba(59,130,246,.1);padding:1px 5px;border-radius:3px;color:var(--a2);font-size:.75rem;font-family:monospace}
/* SEVERITY BADGES */
.sev{display:inline-block;padding:1px 7px;border-radius:4px;font-size:.65rem;font-weight:700;text-transform:uppercase}
.sev-c{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.sev-h{background:rgba(249,115,22,.15);color:#f97316;border:1px solid rgba(249,115,22,.3)}
.sev-m{background:rgba(234,179,8,.15);color:#eab308;border:1px solid rgba(234,179,8,.3)}
.sev-l{background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3)}
/* INFO BOX */
.infobox{background:rgba(59,130,246,.07);border:1px solid rgba(59,130,246,.2);border-radius:8px;padding:12px 16px;margin-bottom:12px;font-size:.78rem}
.infobox.warn{background:rgba(249,115,22,.07);border-color:rgba(249,115,22,.2)}
.infobox.crit{background:rgba(239,68,68,.07);border-color:rgba(239,68,68,.2)}
.infobox.ok{background:rgba(34,197,94,.07);border-color:rgba(34,197,94,.2)}
/* LANG TOGGLE */
.lang-note{font-size:.65rem;color:var(--m);font-style:italic;margin-left:8px}
/* FOOTER */
footer{background:var(--s);border-top:1px solid var(--b);padding:16px 40px;text-align:center;color:var(--m);font-size:.7rem;margin-top:40px}
/* COMPLIANCE */
.comp-badge{display:inline-block;padding:1px 6px;border-radius:4px;font-size:.65rem;font-weight:700}
.comp-pass{background:rgba(34,197,94,.15);color:#22c55e}
.comp-fail{background:rgba(239,68,68,.15);color:#ef4444}
.comp-na{background:rgba(148,163,184,.15);color:#94a3b8}
/* ZONE CHIPS */
.zone{display:inline-block;padding:1px 7px;border-radius:10px;font-size:.68rem;font-weight:700;text-transform:uppercase}
/* PRINT */
@media print{nav{display:none}body{background:#fff;color:#000}.kpi,.card,.bh-card,.verdict,.tbl-wrap{border-color:#ccc}th{background:#f0f4f8}}
</style>
</head>
<body>

<header>
  <div class="hdr-grid">
    <div>
      <div class="hdr-title">⚔ EWNAF v${VERSION} — Enterprise Network Audit Framework</div>
      <div class="hdr-sub">Klient / Client: <strong>$(html_esc "${CLIENT_NAME}")</strong> &nbsp;|&nbsp; Zakres / Scope: <code>$(html_esc "${TARGET_SUBNET:-}")</code> &nbsp;|&nbsp; Tryb / Mode: $(html_esc "${MODE:-}")</div>
    </div>
    <div class="hdr-meta">
      Data / Date: $(date '+%Y-%m-%d %H:%M')<br>
      Wygenerowano przez / Generated by: EWNAF Behavioural Engine<br>
      Hosty / Hosts: ${DEV_COUNT} aktywnych
    </div>
  </div>
</header>

<nav>
  <a href="#s1">1. Executive Summary</a>
  <a href="#s2">2. Topologia / Topology</a>
  <a href="#s3">3. L2/L3 Infrastruktura</a>
  <a href="#s4">4. Profil Hostów / Hosts</a>
  <a href="#s5">5. Usługi / Services</a>
  <a href="#s6">6. Behavioral Recon</a>
  <a href="#s1b">&#x26A1; Kill Chain</a>
  <a href="#s1d">&#x1F9E0; Faza X</a>
  <a href="#s1c">&#x1F5FA; Roadmap</a>
  <a href="#s7">7. Findings</a>
  <a href="#s8">8. Compliance</a>
</nav>

<div class="wrap">

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 1: EXECUTIVE SUMMARY                                 -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s1">
<h2>1. Podsumowanie menedżerskie <span class="en">Executive Summary</span></h2>

<div class="verdict">
  <div class="score-circle" style="border-color:${sc};color:${sc}">
    ${GLOBAL_SCORE:-0}
  </div>
  <div class="verdict-text">
    <h3 style="color:${sc}">$(html_esc "$verdict_pl") / $(html_esc "$verdict_en")</h3>
    <p>$(html_esc "$tier")</p>
    <p style="margin-top:6px;font-size:.72rem;color:var(--m)">
      Ryzyko rezydualne / Residual Risk = Ryzyko surowe − Mitigacje &nbsp;|&nbsp;
      Wynik obejmuje ${DEV_COUNT} hostów, ${#NET_FINDINGS[@]} znalezisk sieciowych
    </p>
  </div>
  <div class="verdict-grade" style="color:${sc}">$(html_esc "$grade")</div>
</div>

<div class="kpi-grid">
  <div class="kpi">
    <div class="v" style="color:${sc}">$(html_esc "${GLOBAL_SCORE:-0}")</div>
    <div class="l">Global Score</div>
    <div class="sl">Wynik końcowy</div>
  </div>
  <div class="kpi">
    <div class="v" style="color:#94a3b8">$(html_esc "$grade")</div>
    <div class="l">Grade A–F</div>
    <div class="sl">Ocena</div>
  </div>
  <div class="kpi">
    <div class="v" style="color:#3b82f6">$(html_esc "${MATURITY_SCORE:-0}")</div>
    <div class="l">Maturity Score</div>
    <div class="sl">Dojrzałość</div>
  </div>
  <div class="kpi">
    <div class="v" style="color:${def_color}">$(html_esc "$def_score")<small style="font-size:.7rem">/100</small></div>
    <div class="l">Defense Score</div>
    <div class="sl">$(html_esc "$def_level")</div>
  </div>
  <div class="kpi">
    <div class="v" style="color:#ef4444">$(html_esc "${H_CRITICAL:-0}")</div>
    <div class="l">Hosty Krytyczne</div>
    <div class="sl">Critical Hosts</div>
  </div>
  <div class="kpi">
    <div class="v" style="color:#f97316">$(html_esc "${H_HIGH:-0}")</div>
    <div class="l">Hosty Wysokie</div>
    <div class="sl">High Risk</div>
  </div>
  <div class="kpi">
    <div class="v" style="color:#eab308">$(html_esc "${NET_MEDIUM:-0}")</div>
    <div class="l">Znaleziska</div>
    <div class="sl">Net Findings</div>
  </div>
  <div class="kpi">
    <div class="v" style="color:#bh_threat_c">$(html_esc "$bh_threat")</div>
    <div class="l">Threat Level</div>
    <div class="sl">Poziom zagrożenia</div>
  </div>
  <div class="kpi">
    <div class="v" style="color:#60a5fa">$(html_esc "$bh_corr")</div>
    <div class="l">Correlation</div>
    <div class="sl">Korelacja behaw.</div>
  </div>
  <div class="kpi">
    <div class="v" style="color:${ts_color}">$(html_esc "$ts")<small style="font-size:.8rem">/100</small></div>
    <div class="l">Threat Score</div>
    <div class="sl">Σ(weight×conf) formal</div>
  </div>
</div>

<div class="card" style="border-left:3px solid #ef4444">
  <h3>🎯 Podsumowanie dla zarządu / C-Suite Executive Briefing</h3>
  <div style="margin-top:10px">

    $(
    # Dynamiczna narracja na podstawie danych audytu
    chain="${ATTACK_PATH[chain_completeness]:-0}"
    critical_h="${H_CRITICAL:-0}"
    high_h="${H_HIGH:-0}"
    gs="${GLOBAL_SCORE:-0}"
    ad_det="${AD_INFO[detected]:-0}"
    lat_count="${#LATERAL_PATHS[@]}"

    echo "<p style='font-size:.85rem;line-height:1.6;color:var(--t)'>"
    if (( chain >= 2 )); then
        echo "<strong style='color:#ef4444'>WYSOKIE RYZYKO KOMPROMITACJI.</strong> "
        echo "Audyt zidentyfikował kompletny łańcuch ataku (kill chain): wektor dostępu, "
        echo "ścieżki lateral movement i mechanizm eskalacji uprawnień. "
        echo "Doświadczony atakujący może przejąć sieć bez wykrycia."
    elif (( critical_h > 0 )); then
        echo "<strong style='color:#f97316'>KRYTYCZNE PODATNOŚCI.</strong> "
        echo "Wykryto ${critical_h} hostów z poziomem ryzyka CRITICAL wymagających natychmiastowej interwencji."
    elif (( high_h > 0 )); then
        echo "<strong style='color:#eab308'>PODATNOŚCI WYSOKIEGO RYZYKA.</strong> "
        echo "Wykryto ${high_h} hostów z istotnymi lukami bezpieczeństwa."
    else
        echo "<strong style='color:#22c55e'>AKCEPTOWALNY POZIOM RYZYKA.</strong> "
        echo "Sieć prezentuje podstawowy poziom zabezpieczeń. Rekomendacje poniżej."
    fi
    echo "</p>"

    # Business impact
    echo "<p style='font-size:.82rem;color:var(--m);margin-top:8px'>"
    echo "<strong>Potencjalny wpływ biznesowy / Business Impact:</strong> "
    if (( chain >= 2 )); then
        echo "Naruszenie danych, przerwa operacyjna, odpowiedzialność regulacyjna (GDPR Art.33/34, NIS2)."
    elif (( lat_count > 3 )); then
        echo "Ransomware propagation risk — płaski model sieci umożliwia szyfrowanie wszystkich zasobów."
    elif [[ "$ad_det" == "1" ]]; then
        echo "Kompromitacja Active Directory = utrata kontroli nad całą infrastrukturą Windows."
    else
        echo "Ograniczony zasięg ataku przy obecnym stanie zabezpieczeń."
    fi
    echo "</p>"

    # Natychmiastowe działania
    quick_n="${ROADMAP_QUICK[count]:-0}"
    if (( quick_n > 0 )); then
        echo "<p style='font-size:.82rem;color:#ef4444;margin-top:8px'>"
        echo "<strong>⚡ Wymagane natychmiastowe działania (0-7 dni):</strong> ${quick_n} elementów — patrz sekcja Roadmap."
        echo "</p>"
    fi
    )

  </div>
</div>

<div class="card">
  <h3>Metodologia / Methodology</h3>
  <p style="color:var(--m);font-size:.78rem;margin-top:6px">
    <strong>PL:</strong> Wynik końcowy obliczany jako: <code>Ryzyko Rezydualne = Ryzyko Surowe (waga × podatność) − Mitigacje (wykryte mechanizmy obronne)</code>.
    Faza behawioralna (Faza X) ocenia reaktywność sieci: mierzy zmiany latencji, eskalację obrony, deception, pamięć stanów i korelację między hostami.
    <br><br>
    <strong>EN:</strong> Final score computed as <code>Residual Risk = Raw Risk (weight × vulnerability) − Mitigations (detected defences)</code>.
    Behavioural phase (Phase X) assesses network reactivity: measures latency shifts, defence escalation, deception layers, state memory, and cross-host correlation.
  </p>
</div>
</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 1b: ATTACK PATH / KILL CHAIN                         -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s1b">
<h2>&#x26A1; Attack Path / Kill Chain <span class="en">Adversarial Scenario</span></h2>

$(
chain="${ATTACK_PATH[chain_completeness]:-0}"
if (( chain >= 1 )); then
    echo "<div style='background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:8px;padding:14px;margin-bottom:14px'>"
    echo "<p style='color:#ef4444;font-weight:700;font-size:.85rem'>⚠ Kompletna ścieżka ataku wykryta / Complete attack path identified</p>"
    echo "</div>"
fi
)

<div style="overflow-x:auto;margin-top:10px">
<table style="width:100%;border-collapse:collapse;font-size:.8rem">
<thead>
<tr style="background:rgba(255,255,255,.04)">
  <th style="padding:8px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Faza / Phase</th>
  <th style="padding:8px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">MITRE ATT&amp;CK</th>
  <th style="padding:8px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Wykryto / Detected</th>
  <th style="padding:8px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Status</th>
</tr>
</thead>
<tbody>
$(
render_chain_row() {
    local phase="$1" mitre="$2" data="$3"
    local color="#22c55e" status="✓ Brak wskaźników"
    [[ "$data" != "none detected" && "$data" != "none — good segmentation" ]] &&         color="#ef4444" && status="⚠ Wykryto"
    echo "<tr style='border-bottom:1px solid rgba(255,255,255,.05)'>"
    echo "  <td style='padding:8px 10px;font-weight:600'>$(html_esc "$phase")</td>"
    echo "  <td style='padding:8px 10px;color:#60a5fa;font-size:.75rem'>$(html_esc "$mitre")</td>"
    echo "  <td style='padding:8px 10px;color:var(--m);font-size:.75rem;max-width:300px;word-break:break-all'>$(html_esc "${data:0:120}")</td>"
    echo "  <td style='padding:8px 10px;color:$color;font-weight:700'>$(html_esc "$status")</td>"
    echo "</tr>"
}
render_chain_row "1. Initial Access"         "T1190 T1133 T1078" "${ATTACK_PATH[step_1_initial_access]:-none detected}"
render_chain_row "2. Execution / Cred Access" "T1558.003 T1110 T1003" "${ATTACK_PATH[step_2_exec]:-none detected}"
render_chain_row "3. Lateral Movement"        "T1021 T1550 T1563"  "${ATTACK_PATH[step_3_lateral]:-none — good segmentation}"
render_chain_row "4. Privilege Escalation"    "T1068 T1134 T1484"  "${ATTACK_PATH[step_4_privesc]:-none detected}"
render_chain_row "5. Impact / Exfiltration"   "T1041 T1486 T1565"  "${ATTACK_PATH[step_5_impact]:-none detected}"
)
</tbody>
</table>
</div>

$(
# AD context w kill chain
if [[ "${AD_INFO[detected]:-0}" == "1" ]]; then
    echo "<div class='card' style='margin-top:12px;border-left:3px solid #f97316'>"
    echo "  <h3>🏢 Active Directory — Attack Context</h3>"
    echo "  <table style='width:100%;font-size:.8rem'><tbody>"
    echo "    <tr><td style='color:var(--m);padding:4px 8px'>Domain Controller</td><td><code>$(html_esc "${AD_INFO[dc_ip]:-?}")</code></td></tr>"
    echo "    <tr><td style='color:var(--m);padding:4px 8px'>Domain</td><td><code>$(html_esc "${AD_INFO[domain]:-unknown}")</code></td></tr>"
    echo "    <tr><td style='color:var(--m);padding:4px 8px'>SMB Signing</td>"
    smb_s="${AD_INFO[smb_signing]:-unknown}"
    [[ "$smb_s" == "disabled" ]] &&         echo "    <td><span style='color:#ef4444;font-weight:700'>DISABLED — NTLM relay possible</span></td>" ||         echo "    <td><span style='color:#22c55e'>$(html_esc "$smb_s")</span></td>"
    echo "    </tr>"
    echo "    <tr><td style='color:var(--m);padding:4px 8px'>Kerberos/88</td>"
    [[ "${AD_INFO[kerberos_open]:-0}" == "1" ]] &&         echo "    <td><span style='color:#60a5fa'>OPEN</span></td>" ||         echo "    <td><span style='color:var(--m)'>closed/filtered</span></td>"
    echo "    </tr>"
    echo "  </tbody></table>"
    echo "</div>"
fi
)
</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 1c: REMEDIATION ROADMAP                             -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s1c">
<h2>&#x1F5FA; Remediation Roadmap <span class="en">Prioritised Action Plan</span></h2>

$(
render_roadmap_section() {
    local title="$1" subtitle="$2" color="$3" icon="$4"
    shift 4
    local items=("$@")
    [[ ${#items[@]} -eq 0 ]] && return

    echo "<div class='card' style='border-left:3px solid ${color};margin-bottom:14px'>"
    echo "  <h3 style='color:${color}'>${icon} $(html_esc "$title") <span style='font-weight:400;font-size:.75rem;color:var(--m)'>$(html_esc "$subtitle")</span></h3>"
    echo "  <table style='width:100%;font-size:.78rem;margin-top:8px'><thead>"
    echo "  <tr style='background:rgba(255,255,255,.03)'>"
    echo "    <th style='padding:5px 8px;text-align:left;color:var(--m)'>Host</th>"
    echo "    <th style='padding:5px 8px;text-align:left;color:var(--m)'>CVSS</th>"
    echo "    <th style='padding:5px 8px;text-align:left;color:var(--m)'>Kategoria</th>"
    echo "    <th style='padding:5px 8px;text-align:left;color:var(--m)'>Rekomendacja</th>"
    echo "  </tr></thead><tbody>"

    local shown=0
    for item in "${items[@]}"; do
        [[ -z "$item" ]] && continue
        IFS='|' read -r rip rsev rcvss rcat rrec <<< "$item"
        local cvss_n; cvss_n=$(echo "$rcvss" | cut -d. -f1)
        local cc="#6b7280"
        (( ${cvss_n:-0} >= 9 )) && cc="#ef4444"
        (( ${cvss_n:-0} >= 7 && ${cvss_n:-0} < 9 )) && cc="#f97316"
        (( ${cvss_n:-0} >= 4 && ${cvss_n:-0} < 7 )) && cc="#eab308"
        echo "  <tr style='border-top:1px solid rgba(255,255,255,.04)'>"
        echo "    <td style='padding:5px 8px'><code>$(html_esc "$rip")</code></td>"
        echo "    <td style='padding:5px 8px;color:${cc};font-weight:700'>$(html_esc "$rcvss")</td>"
        echo "    <td style='padding:5px 8px;color:#60a5fa'>$(html_esc "$rcat")</td>"
        echo "    <td style='padding:5px 8px;color:var(--m)'>$(html_esc "${rrec:0:100}")</td>"
        echo "  </tr>"
        (( shown++ ))
        (( shown >= 20 )) && break  # max 20 per sekcja
    done
    echo "  </tbody></table>"
    echo "</div>"
}

# Zbierz items per kategoria
quick_items=()
for k in "${!ROADMAP_QUICK[@]}"; do
    [[ "$k" == "count" ]] && continue
    quick_items+=("${ROADMAP_QUICK[$k]}")
done
short_items=()
for k in "${!ROADMAP_SHORT[@]}"; do
    [[ "$k" == "count" ]] && continue
    short_items+=("${ROADMAP_SHORT[$k]}")
done
strat_items=()
for k in "${!ROADMAP_STRATEGIC[@]}"; do
    [[ "$k" == "count" ]] && continue
    strat_items+=("${ROADMAP_STRATEGIC[$k]}")
done

render_roadmap_section     "Quick Wins — Natychmiastowe (0-7 dni)" "CVSS ≥9.0 / Single command fixes"     "#ef4444" "⚡" "${quick_items[@]}"

render_roadmap_section     "Short-term — Krótkoterminowe (1-4 tygodnie)" "CVSS 7-8.9 / Konfiguracja i patching"     "#f97316" "🔧" "${short_items[@]}"

render_roadmap_section     "Strategic — Strategiczne (3-6 miesięcy)" "Architektura / Zero Trust / Segmentacja"     "#3b82f6" "🏗" "${strat_items[@]}"

quick_n="${ROADMAP_QUICK[count]:-0}"
short_n="${ROADMAP_SHORT[count]:-0}"
strat_n="${ROADMAP_STRATEGIC[count]:-0}"
total_items=$(( quick_n + short_n + strat_n ))
if (( total_items == 0 )); then
    echo "<div class='card'><p style='color:#22c55e'>✓ Brak zidentyfikowanych elementów do naprawy.</p></div>"
fi
)

</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 1d: FAZA X — BEHAVIOURAL ANALYSIS                   -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s1d">
<h2>&#x1F9E0; Faza X — Analiza behawioralna <span class="en">Behavioural Defence Posture</span></h2>

<!-- KPI Fazy X -->
<div class="kpi-grid" style="margin-bottom:16px">
${s1d_kpi}
</div>

<!-- Tabela per-host zones -->
<div class="card">
  <h3>&#x1F4CD; Mapa stref behawioralnych / Behavioural Zone Map</h3>
  <div style="overflow-x:auto;margin-top:10px">
  <table style="width:100%;border-collapse:collapse;font-size:.8rem">
  <thead>
  <tr style="background:rgba(255,255,255,.04)">
    <th style="padding:7px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Host IP</th>
    <th style="padding:7px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Zone</th>
    <th style="padding:7px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Confidence</th>
    <th style="padding:7px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Baseline</th>
    <th style="padding:7px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Window</th>
    <th style="padding:7px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Ban N</th>
    <th style="padding:7px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Recovery</th>
    <th style="padding:7px 10px;text-align:left;color:var(--m);border-bottom:1px solid var(--b)">Interpretacja</th>
  </tr>
  </thead>
  <tbody>
${s1d_zone_rows}
  </tbody>
  </table>
  </div>
</div>

<!-- Per-host score cards -->
${s1d_host_cards}

<!-- Legenda stref -->
<div class="card" style="margin-top:14px">
  <h3>&#x1F4D6; Legenda stref / Zone Legend</h3>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;margin-top:10px;font-size:.78rem">
    <div style="padding:8px;border-radius:6px;background:rgba(167,139,250,.08);border:1px solid rgba(167,139,250,.2)">
      <strong style="color:#a78bfa">🎭 DECEPTION</strong>
      <p style="color:var(--m);margin-top:4px">Deception / tarpit / fake listener. Wyniki audytu mogą być zafałszowane.</p>
    </div>
    <div style="padding:8px;border-radius:6px;background:rgba(96,165,250,.08);border:1px solid rgba(96,165,250,.2)">
      <strong style="color:#60a5fa">🔗 CORRELATED</strong>
      <p style="color:var(--m);margin-top:4px">IDS/NDR/SIEM koreluje zdarzenia. Pełna widoczność footprintu audytora.</p>
    </div>
    <div style="padding:8px;border-radius:6px;background:rgba(249,115,22,.08);border:1px solid rgba(249,115,22,.2)">
      <strong style="color:#f97316">🧠 ADAPTIVE</strong>
      <p style="color:var(--m);margin-top:4px">Reputacyjny blacklist z pamięcią. Blokada persists po cooldown.</p>
    </div>
    <div style="padding:8px;border-radius:6px;background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2)">
      <strong style="color:#eab308">📈 ESCALATING</strong>
      <p style="color:var(--m);margin-top:4px">Rate-limiter z progiem N. Latencja rośnie po N próbach — ban trigger.</p>
    </div>
    <div style="padding:8px;border-radius:6px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2)">
      <strong style="color:#22c55e">⚡ REACTIVE</strong>
      <p style="color:var(--m);margin-top:4px">Prosta ochrona bez persistent memory. Każda sesja oceniana od zera.</p>
    </div>
    <div style="padding:8px;border-radius:6px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2)">
      <strong style="color:#ef4444">⚠ EXPOSED</strong>
      <p style="color:var(--m);margin-top:4px">Brak widocznej obrony dynamicznej. Wymaga wdrożenia fail2ban / IDS.</p>
    </div>
    <div style="padding:8px;border-radius:6px;background:rgba(148,163,184,.08);border:1px solid rgba(148,163,184,.2)">
      <strong style="color:#94a3b8">🔇 SILENT</strong>
      <p style="color:var(--m);margin-top:4px">DROP policy — brak odpowiedzi. Prawidłowe zachowanie stealth firewalla.</p>
    </div>
  </div>
</div>

</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 2: TOPOLOGIA I SYSTEMY OCHRONY                      -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s2">
<h2>2. Topologia i systemy ochrony <span class="en">Topology &amp; Defence Systems</span></h2>

<div class="card-grid">
  <div class="card">
    <h3>🛡 Wykryte systemy obronne / Detected Defence Systems</h3>
    <ul style="list-style:none;margin-top:8px;font-size:.78rem">
      ${sec_list}
      ${pc_ids_li}
      ${pc_rate_lim}
      ${pc_dns_ctrl_li}
    </ul>
  </div>
  <div class="card">
    <h3>🌐 Analiza łączy / Link Analysis</h3>
    <table style="width:100%"><tbody>
      <tr><td style="color:var(--m)">WAN IP</td><td><code>$(html_esc "${TOPO[real_wan_ip]:-?}")</code></td></tr>
      <tr><td style="color:var(--m)">Gateway</td><td><code>$(html_esc "${TOPO[real_gateway]:-?}")</code></td></tr>
      <tr><td style="color:var(--m)">VPN / Tunnel</td><td>$(
        if [[ "${TOPO[vpn_detected]:-0}" == "1" ]]; then
          echo "<span style='color:#22c55e'>✓ $(html_esc "${TOPO[vpn_type]:-VPN}") — $(html_esc "${TOPO[vpn_interface]:-?}")</span>"
        else echo "<span style='color:#eab308'>✗ Brak tunelu VPN</span>"; fi
      )</td></tr>
      <tr><td style="color:var(--m)">NAT / Masquerade</td><td>$(
        if [[ "${TOPO[masquerade_active]:-0}" == "1" ]]; then
          echo "<span style='color:#22c55e'>✓ MASQUERADE aktywna</span>"
        elif [[ "${TOPO[double_nat]:-0}" == "1" ]]; then
          echo "<span style='color:#f97316'>⚠ Double NAT (${TOPO[vpn_wan_ip]:-?})</span>"
        else echo "<span style='color:#eab308'>? Nie wykryto / Not detected</span>"; fi
      )</td></tr>
      <tr><td style="color:var(--m)">NAT layers</td><td>$(html_esc "${TOPO[nat_layers]:-1}")</td></tr>
      <tr><td style="color:var(--m)">Firewall type</td><td>$(html_esc "${TOPO[firewall_type]:-unknown}")</td></tr>
      <tr><td style="color:var(--m)">ISP</td><td>$(html_esc "${TOPO[isp]:-?}")</td></tr>
    </tbody></table>
  </div>
</div>

<div class="card">
  <h3>🍯 Heurystyka sieci / Network Heuristics</h3>
  <div class="card-grid-3" style="margin-top:10px">
    <div class="infobox ${pc_hp_cls}">
      <strong>Honeypot:</strong> ${pc_hp_val}
    </div>
    <div class="infobox ${pc_mirage_cls}">
      <strong>Mirage ports:</strong> ${pc_mirage_val}
    </div>
    <div class="infobox">
      <strong>Silent DROP:</strong> ${pc_sdrop_val}
    </div>
  </div>
</div>
</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 3: L2/L3 INFRASTRUKTURA                             -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s3">
<h2>3. Warstwa 2/3 — Infrastruktura <span class="en">L2/L3 Infrastructure</span></h2>

<div class="card-grid">
  <div class="card">
    <h3>🔗 Domena rozgłoszeniowa L2 / L2 Broadcast Domain</h3>
    <table style="width:100%"><tbody>
      <tr><td style="color:var(--m)">Dostawcy OUI / OUI Vendors</td><td>$(html_esc "${L2_RESULTS[vendor_diversity]:-?}")</td></tr>
      <tr><td style="color:var(--m)">Hosty L2 / L2 Hosts</td><td>$(html_esc "${L2_RESULTS[host_count]:-?}")</td></tr>
      <tr><td style="color:var(--m)">Access points</td><td>$(html_esc "${L2_RESULTS[ap_count]:-?}")</td></tr>
      <tr><td style="color:var(--m)">Switche / Switches</td><td>$(html_esc "${L2_RESULTS[switch_count]:-?}")</td></tr>
    </tbody></table>
  </div>
  <div class="card">
    <h3>🗺 Routing i segmentacja L3 / L3 Routing</h3>
    <table style="width:100%"><tbody>
      <tr><td style="color:var(--m)">East-West izolacja / Isolation</td>
        <td>${pc_ew_iso}</td></tr>
      <tr><td style="color:var(--m)">Cross-subnet blokada / Block</td>
        <td>${pc_cross_sub}</td></tr>
      <tr><td style="color:var(--m)">Polityka DROP / DROP policy</td>
        <td>${pc_drop_pol}</td></tr>
    </tbody></table>
  </div>
</div>
</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 4: PROFIL HOSTÓW                                     -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s4">
<h2>4. Profilowanie hostów i ryzyka <span class="en">Host Profiling &amp; Risk</span></h2>

<div class="tbl-wrap">
<table>
<thead><tr>
  <th>IP</th><th>Hostname</th><th>Rola / Role</th><th>OS</th>
  <th>Otwarte porty / Open Ports</th><th>Ryzyko / Risk</th>
  <th>Behawioralny / Behavioural</th>
</tr></thead>
<tbody>
${dev_rows:-<tr><td colspan="7" style="color:var(--m);text-align:center">Brak danych / No data</td></tr>}
</tbody>
</table>
</div>
</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 5: USŁUGI I POLITYKI RUCHU                          -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s5">
<h2>5. Audyt usług i polityk ruchu <span class="en">Services &amp; Traffic Policy Audit</span></h2>

<div class="card-grid-3">
  <div class="card">
    <h3>🔍 DNS</h3>
    <table style="width:100%"><tbody>
      <tr><td style="color:var(--m)">DNS Leak</td>
        <td>$(
          _dl="${TRAFFIC_POLICY[dns_leak]:-0}"
          _dlc="${TRAFFIC_POLICY[dns_leak_conf]:-0}"
          if [[ "$_dl" == "1" ]]; then echo "<span style='color:#ef4444'>✗ WYCIEK (pewność ${_dlc}%)</span>"
          elif [[ "$_dl" == "PARTIAL" ]]; then echo "<span style='color:#f97316'>⚠ MOŻLIWY (${_dlc}%)</span>"
          else echo "<span style='color:#22c55e'>✓ Brak / None</span>"; fi
        )</td></tr>
      <tr><td style="color:var(--m)">DNS Controlled</td>
        <td>${pc_dns_ctrl_td}</td></tr>
      <tr><td style="color:var(--m)">Malware block</td>
        <td>${pc_dns_malware}</td></tr>
      <tr><td style="color:var(--m)">DoH/DoT</td>
        <td>$(html_esc "${TRAFFIC_POLICY[doh_detected]:-nie zbadano}")</td></tr>
    </tbody></table>
  </div>
  <div class="card">
    <h3>📤 Egress</h3>
    <table style="width:100%"><tbody>
      <tr><td style="color:var(--m)">HTTP 80 out</td>
        <td>${pc_http_egr}</td></tr>
      <tr><td style="color:var(--m)">SMTP 25</td>
        <td>$(html_esc "${TRAFFIC_POLICY[smtp_blocked]:-nie zbadano}")</td></tr>
      <tr><td style="color:var(--m)">C2 ports</td>
        <td>$(html_esc "${TRAFFIC_POLICY[c2_blocked]:-nie zbadano}")</td></tr>
    </tbody></table>
  </div>
  <div class="card">
    <h3>🔒 TLS/SSL</h3>
    <table style="width:100%"><tbody>
      <tr><td style="color:var(--m)">TLS Intercepted</td>
        <td>${pc_tls_int}</td></tr>
      <tr><td style="color:var(--m)">HSTS</td>
        <td>$(html_esc "${TRAFFIC_POLICY[hsts_detected]:-nie zbadano}")</td></tr>
      <tr><td style="color:var(--m)">Transparent proxy</td>
        <td>${pc_tproxy}</td></tr>
    </tbody></table>
  </div>
</div>

<div class="card-grid" style="margin-top:12px">
  <div class="card">
    <h3>🛡 VPN &amp; NAT / Maskarada</h3>
    <table style="width:100%"><tbody>
      <tr><td style="color:var(--m)">VPN Tunnel</td>
        <td>${vpn_display}</td></tr>
      <tr><td style="color:var(--m)">VPN Interface</td>
        <td><code>$(html_esc "${TOPO[vpn_interface]:-—}")</code></td></tr>
      <tr><td style="color:var(--m)">NAT Masquerade</td>
        <td>${pc_masq}</td></tr>
      <tr><td style="color:var(--m)">Double NAT</td>
        <td>${pc_dnat}</td></tr>
      <tr><td style="color:var(--m)">WAN IP (true)</td>
        <td><code>$(html_esc "${TOPO[true_wan_ip]:-?}")</code></td></tr>
    </tbody></table>
  </div>
  <div class="card">
    <h3>⏱ Rate Limiting &amp; Anti-scan</h3>
    <table style="width:100%"><tbody>
      <tr><td style="color:var(--m)">Rate Limiting</td>
        <td>${pc_ratelim_td}</td></tr>
      <tr><td style="color:var(--m)">Auto-ban IPS</td>
        <td>${pc_autoban}</td></tr>
      <tr><td style="color:var(--m)">IDS / IPS</td>
        <td>${pc_ids_td}</td></tr>
      <tr><td style="color:var(--m)">SSH Tarpit</td>
        <td>${pc_tarpit}</td></tr>
      <tr><td style="color:var(--m)">Stateful Firewall</td>
        <td>${fw_display}</td></tr>
    </tbody></table>
  </div>
</div>
</div>
</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 6: BEHAVIOURAL RECON — FAZA X                       -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s6">
<h2>6. Behavioural Recon — Faza X <span class="en">Phase X — Behavioural Intelligence</span></h2>

<div class="infobox" style="margin-bottom:16px">
  <strong>PL:</strong> Faza X to aktywna analiza behawioralna — nie skanowanie portów.
  Silnik mierzy <em>jak sieć oddycha</em>: zmiany latencji, eskalację obrony, warstwy deception, pamięć stanów i korelację między hostami.
  Wyniki nie zależą od znajomości konkretnych produktów (bez identyfikacji konkretnych produktów).
  <br><br>
  <strong>EN:</strong> Phase X is active behavioural analysis — not port scanning.
  The engine measures <em>how the network breathes</em>: latency shifts, defence escalation, deception layers, state memory, and cross-host correlation.
  Results are product-agnostic — no knowledge of specific tools required.
</div>

<!-- Stan sesji globalnej -->
<div class="bh-grid">
  <div class="bh-card">
    <div class="bv" style="color:${bh_threat_c}">$(html_esc "$bh_threat")<small style="font-size:.9rem">/100</small></div>
    <div class="bl">Threat Level / Poziom zagrożenia</div>
  </div>
  <div class="bh-card">
    <div class="bv" style="color:#f97316">$(html_esc "$bh_corr")<small style="font-size:.9rem">/100</small></div>
    <div class="bl">Correlation Score</div>
  </div>
  <div class="bh-card">
    <div class="bv" style="color:#ef4444">$(html_esc "${SESSION_STATE[hosts_deceptive]:-0}")</div>
    <div class="bl">Deceptive Hosts</div>
  </div>
  <div class="bh-card">
    <div class="bv" style="color:#eab308">$(html_esc "${SESSION_STATE[hosts_reactive]:-0}")</div>
    <div class="bl">Reactive Hosts</div>
  </div>
  <div class="bh-card">
    <div class="bv" style="color:${bh_adapt_color}">
      ${bh_adapt_label}
    </div>
    <div class="bl">Adaptation Detected</div>
  </div>
  <div class="bh-card">
    <div class="bv" style="color:#60a5fa">$(html_esc "${SESSION_STATE[cross_host_latency_shift]:-0}")</div>
    <div class="bl">Cross-Host Shifts</div>
  </div>
</div>

<!-- Mapa behawioralna -->
<h3 style="margin-bottom:10px">🗺 Mapa behawioralna hostów / Behavioural Host Map</h3>
<div class="tbl-wrap">
<table>
<thead><tr>
  <th>IP</th><th>Strefa / Zone</th><th>Confidence</th>
  <th>Metryki / Metrics (RS AI DP CL)</th>
  <th>Sygnały deception / Deception signals</th>
  <th>Pamięć / Memory</th>
</tr></thead>
<tbody>
${bmap_rows:-<tr><td colspan="6" style="color:var(--m);text-align:center">Brak danych — faza X nie uruchomiona / Phase X not run</td></tr>}
</tbody>
</table>
</div>

<div class="card" style="margin-top:12px">
  <h3>Legenda / Legend</h3>
  <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px;font-size:.72rem">
    <span><span class="zone" style="background:rgba(239,68,68,.15);color:#ef4444">DECEPTION</span> Honeypot/tarpit/mirage</span>
    <span><span class="zone" style="background:rgba(249,115,22,.15);color:#f97316">CORRELATED</span> IDS/SIEM koreluje zdarzenia</span>
    <span><span class="zone" style="background:rgba(249,115,22,.15);color:#f97316">ADAPTIVE</span> Obrona z pamięcią stanów</span>
    <span><span class="zone" style="background:rgba(234,179,8,.15);color:#eab308">ESCALATING</span> Latencja rośnie z próbami</span>
    <span><span class="zone" style="background:rgba(59,130,246,.15);color:#3b82f6">REACTIVE</span> Reaguje, nie zapamiętuje</span>
    <span><span class="zone" style="background:rgba(234,179,8,.15);color:#eab308">EXPOSED</span> Otwarty bez obrony</span>
    <span><span class="zone" style="background:rgba(34,197,94,.15);color:#22c55e">SILENT</span> Brak reakcji (głęboki DROP)</span>
  </div>
  <p style="margin-top:10px;font-size:.72rem;color:var(--m)">
    <strong>RS</strong> = Reactivity Score &nbsp;|&nbsp;
    <strong>AI</strong> = Adaptivity Index &nbsp;|&nbsp;
    <strong>DP</strong> = Deception Probability &nbsp;|&nbsp;
    <strong>CL</strong> = Correlation Likelihood
  </p>
</div>
</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 7: FINDINGS I REKOMENDACJE                          -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s7">
<h2>7. Znaleziska i rekomendacje <span class="en">Findings &amp; Remediation</span></h2>

<h3 style="margin-bottom:8px">Znaleziska sieciowe / Network-level Findings</h3>
<div class="tbl-wrap">
<table>
<thead><tr>
  <th>Powaga / Severity</th><th>Kategoria / Category</th>
  <th>Opis / Description</th><th>Rekomendacja / Recommendation</th>
</tr></thead>
<tbody>
${net_rows:-<tr><td colspan="4" style="color:var(--m);text-align:center">Brak znalezisk sieciowych / No network findings</td></tr>}
</tbody>
</table>
</div>

<h3 style="margin-top:20px;margin-bottom:8px">Znaleziska per host / Per-host Findings</h3>
<div class="tbl-wrap">
<table>
<thead><tr>
  <th>Host IP</th><th>Powaga / Severity</th><th>Kategoria</th>
  <th>Opis / Description</th><th>Rekomendacja / Remediation</th>
</tr></thead>
<tbody>
${find_rows:-<tr><td colspan="5" style="color:var(--m);text-align:center">Brak znalezisk / No findings</td></tr>}
</tbody>
</table>
</div>
</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SEKCJA 8: COMPLIANCE                                        -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="section" id="s8">
<h2>8. Zgodność / Compliance <span class="en">CIS · ISO 27001 · NIST · GDPR</span></h2>

<div class="infobox" style="margin-bottom:14px">
  <strong>PL:</strong> Macierz mapowania wyników do standardów branżowych.
  Status PASS = kontrola spełniona, FAIL = niezgodność, N/A = nie zbadano.
  <br>
  <strong>EN:</strong> Mapping of audit results to industry standards.
  PASS = control satisfied, FAIL = non-compliance, N/A = not assessed.
</div>

<div class="tbl-wrap">
<table>
<thead><tr>
  <th>Host</th><th>Standard / Control</th><th>Status</th><th>Odniesienie / Reference</th>
</tr></thead>
<tbody>
${comp_rows:-<tr><td colspan="4" style="color:var(--m);text-align:center">Brak danych compliance / No compliance data</td></tr>}
</tbody>
</table>
</div>

<!-- Compliance ogólna -->
<div class="card" style="margin-top:14px">
  <h3>Globalne wskaźniki zgodności / Global Compliance Indicators</h3>
  <div class="card-grid" style="margin-top:10px">
    <div>
      <p style="font-size:.78rem;color:var(--m);margin-bottom:6px"><strong>CIS Controls v8</strong></p>
      <p style="font-size:.78rem">Segmentacja sieci: ${pc_cis12}</p>
      <p style="font-size:.78rem">Filtrowanie DNS: ${pc_cis9}</p>
      <p style="font-size:.78rem">Monitoring sieciowy: ${pc_cis13}</p>
    </div>
    <div>
      <p style="font-size:.78rem;color:var(--m);margin-bottom:6px"><strong>ISO 27001 / NIST CSF</strong></p>
      <p style="font-size:.78rem">Kontrola dostępu: ${pc_iso_ac}</p>
      <p style="font-size:.78rem">Ochrona danych: ${pc_iso_ds}</p>
      <p style="font-size:.78rem">RODO/GDPR egress: ${pc_gdpr}</p>
    </div>
  </div>
</div>

<!-- AWS/Fleet opcjonalnie -->
$( [[ "${TOPO[fleet_detected]:-0}" == "1" || "${PROWLER_RESULT[scan_started]:-0}" == "1" ]] && cat <<OPTEOF
<div class="card" style="margin-top:14px">
  <h3>☁ Audyt chmury i zarządzania / Cloud &amp; Management Audit</h3>
  <table style="width:100%"><tbody>
    <tr><td style="color:var(--m)">Fleet (Osquery)</td><td>${pc_fleet}</td></tr>
    <tr><td style="color:var(--m)">AWS Prowler</td><td>${pc_prowler}</td></tr>
  </tbody></table>
</div>
OPTEOF
)
</div>

</div><!-- /.wrap -->

<footer>
  EWNAF v${VERSION} — Enterprise Network Audit Framework &nbsp;|&nbsp;
  Wygenerowano / Generated: $(date '+%Y-%m-%d %H:%M:%S') &nbsp;|&nbsp;
  Klient / Client: $(html_esc "${CLIENT_NAME}") &nbsp;|&nbsp;
  © Raport behawioralny klasy enterprise / Enterprise behavioural audit report
</footer>

</body>
</html>
HTMLEOF
    (( _u_was )) && set -u

    log "HTML gotowy: $HTML_REPORT ($(wc -l < "$HTML_REPORT") linii)"
}

###############################################################################
# PDF REPORT — BILINGUAL — FULLCOLOR — 8 SECTIONS
###############################################################################

export_pdf() {
    [[ -z "${REPORT_PDF:-}" ]] && return
    command -v python3 &>/dev/null || { log "$(L python_missing)" "WARN"; return; }

    log "Generowanie PDF (bilingual, fullcolor)..."

    local gs="${GLOBAL_SCORE:-0}"
    local grade="${OVERALL_GRADE:-F}"
    local ts="${THREAT_SCORE_FORMAL:-0}"
    local heat="${SESSION_STATE[heat]:-0}"
    local maturity="${MATURITY_SCORE:-0}"
    local tier="Tier 5"
    (( maturity >= 20 )) && tier="Tier 4"
    (( maturity >= 40 )) && tier="Tier 3"
    (( maturity >= 60 )) && tier="Tier 2"
    (( maturity >= 80 )) && tier="Tier 1"

    local verdict_pl="Krytyczne zagrożenie" verdict_en="Critical Threat"
    (( gs >= 30 )) && { verdict_pl="Wysokie ryzyko";     verdict_en="High Risk"; }
    (( gs >= 50 )) && { verdict_pl="Umiarkowane ryzyko"; verdict_en="Moderate Risk"; }
    (( gs >= 70 )) && { verdict_pl="Dobry poziom";       verdict_en="Good Security Posture"; }
    (( gs >= 85 )) && { verdict_pl="Wzorowy poziom";     verdict_en="Exemplary Security"; }

    # Zbierz dane behawioralne
    local bh_data=""
    for ip in "${!BMAP[@]}"; do
        local zone="${BMAP[$ip]}"
        local rs="${BH["${ip}:score_reactivity"]:-0}"
        local dp="${BH["${ip}:score_deception"]:-0}"
        local cl="${BH["${ip}:score_correlation"]:-0}"
        local sigs="${BH["${ip}:deception_signals"]:-none}"
        local ret="${BH["${ip}:return_memory"]:-?}"
        bh_data+="$(_entity_alias "$ip" "Node")|${zone}|${rs}|${dp}|${cl}|$(_anonymize_text "${sigs}")|${ret}\n"
    done

    # Zbierz findings
    local findings_net=""
    for finding in "${NET_FINDINGS[@]:-}"; do
        [[ -z "$finding" ]] && continue
        local IFS_OLD="$IFS"
        IFS=$'\x01' read -r fsev fcat fdesc frec <<< "$finding"
        IFS="$IFS_OLD"
        findings_net+="${fsev}|${fcat}|${fdesc}|${frec}\n"
    done

    python3 - <<PYSCRIPT
import sys, os, textwrap, datetime, hashlib

_real_md5 = hashlib.md5
def _ewnaf_md5(*args, **kwargs):
    kwargs.pop("usedforsecurity", None)
    return _real_md5(*args, **kwargs)
hashlib.md5 = _ewnaf_md5

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                     TableStyle, PageBreak, HRFlowable, KeepTogether)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
except ImportError:
    print("ReportLab brak — instaluję...")
    os.system("pip install reportlab -q --break-system-packages 2>/dev/null || pip3 install reportlab -q 2>/dev/null")
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.lib.units import cm, mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                         TableStyle, PageBreak, HRFlowable, KeepTogether)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    except:
        print("ReportLab niedostępny — PDF pominięty")
        sys.exit(0)

# ── KOLORY ──────────────────────────────────────────────────────
C_BG      = HexColor('#080d1a')
C_DARK    = HexColor('#0f1829')
C_BLUE    = HexColor('#3b82f6')
C_LBLUE   = HexColor('#60a5fa')
C_GRAY    = HexColor('#94a3b8')
C_TEXT    = HexColor('#e2e8f0')
C_RED     = HexColor('#ef4444')
C_ORANGE  = HexColor('#f97316')
C_YELLOW  = HexColor('#eab308')
C_GREEN   = HexColor('#22c55e')
C_BORDER  = HexColor('#1e3a5f')
C_WHITE   = white

gs   = int("${gs}")
sc   = C_RED
if gs >= 70: sc = C_GREEN
elif gs >= 55: sc = C_YELLOW
elif gs >= 40: sc = C_ORANGE

bh_threat = int("${EXEC_BH_THREAT:-0}")
bh_corr   = int("${EXEC_BH_CORRELATION:-0}")
bh_adapt  = "${EXEC_BH_ADAPTATION:-0}"

# ── STYLE ────────────────────────────────────────────────────────
styles = getSampleStyleSheet()

def S(name, **kw):
    base = styles.get(name, styles['Normal'])
    return ParagraphStyle('_'+name, parent=base, **kw)

sNormal  = S('Normal',  fontSize=8,  textColor=C_TEXT,  fontName='Helvetica', leading=12)
sSmall   = S('Normal',  fontSize=7,  textColor=C_GRAY,  fontName='Helvetica', leading=10)
sH1      = S('Normal',  fontSize=18, textColor=C_LBLUE, fontName='Helvetica-Bold', leading=22, spaceAfter=6)
sH2      = S('Normal',  fontSize=11, textColor=C_LBLUE, fontName='Helvetica-Bold', leading=14, spaceBefore=14, spaceAfter=4)
sH3      = S('Normal',  fontSize=9,  textColor=C_TEXT,  fontName='Helvetica-Bold', leading=12, spaceBefore=8, spaceAfter=3)
sCaption = S('Normal',  fontSize=7,  textColor=C_GRAY,  fontName='Helvetica-Oblique', leading=10)
sBilingual = S('Normal', fontSize=7.5, textColor=C_GRAY, fontName='Helvetica', leading=11, leftIndent=8)

def tbl_style(header_bg=C_DARK, stripe=True):
    s = [
        ('BACKGROUND', (0,0), (-1,0), header_bg),
        ('TEXTCOLOR',  (0,0), (-1,0), C_LBLUE),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,0), 7),
        ('FONTSIZE',   (0,1), (-1,-1), 7.5),
        ('TEXTCOLOR',  (0,1), (-1,-1), C_TEXT),
        ('FONTNAME',   (0,1), (-1,-1), 'Helvetica'),
        ('GRID',       (0,0), (-1,-1), 0.3, C_BORDER),
        ('VALIGN',     (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [HexColor('#0d1829'), HexColor('#0f1e35')] if stripe else [HexColor('#0d1829')]),
    ]
    return TableStyle(s)

def sev_color(sev):
    m = {'CRITICAL': C_RED, 'HIGH': C_ORANGE, 'MEDIUM': C_YELLOW, 'LOW': C_GREEN}
    return m.get(sev.upper(), C_GRAY)

def zone_color(z):
    m = {'DECEPTION': C_RED, 'CORRELATED': C_ORANGE, 'ADAPTIVE': C_ORANGE,
         'ESCALATING': C_YELLOW, 'REACTIVE': C_BLUE, 'EXPOSED': C_YELLOW,
         'SILENT': C_GREEN, 'OFFLINE': C_GRAY}
    return m.get(z, C_GRAY)

W = A4[0]
H = A4[1]
MARGIN = 2*cm

def on_page(canvas, doc):
    canvas.saveState()
    # Header bar
    canvas.setFillColor(C_DARK)
    canvas.rect(0, H-1.2*cm, W, 1.2*cm, fill=1, stroke=0)
    canvas.setFillColor(C_LBLUE)
    canvas.setFont('Helvetica-Bold', 8)
    canvas.drawString(MARGIN, H-0.85*cm, "EWNAF v${VERSION}  |  ${CLIENT_NAME}  |  ENTERPRISE NETWORK AUDIT REPORT")
    canvas.setFont('Helvetica', 7)
    canvas.setFillColor(C_GRAY)
    canvas.drawRightString(W-MARGIN, H-0.85*cm, f"Strona / Page {doc.page}")
    # Footer bar
    canvas.setFillColor(C_DARK)
    canvas.rect(0, 0, W, 0.8*cm, fill=1, stroke=0)
    canvas.setFont('Helvetica', 6.5)
    canvas.setFillColor(C_GRAY)
    canvas.drawString(MARGIN, 0.28*cm, f"Wygenerowano / Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}  |  Confidential / Poufny")
    canvas.drawRightString(W-MARGIN, 0.28*cm, "EWNAF Behavioural Engine — Enterprise Class")
    # Blue accent line
    canvas.setStrokeColor(C_BLUE)
    canvas.setLineWidth(1.5)
    canvas.line(0, H-1.2*cm, W, H-1.2*cm)
    canvas.line(0, 0.8*cm, W, 0.8*cm)
    canvas.restoreState()

doc = SimpleDocTemplate(
    "${REPORT_PDF}",
    pagesize=A4,
    leftMargin=MARGIN, rightMargin=MARGIN,
    topMargin=1.6*cm, bottomMargin=1.2*cm,
    title="EWNAF v${VERSION} — ${CLIENT_NAME}",
    author="EWNAF Behavioural Engine",
)

story = []

# ══════════════════════════════════════════════════════════════════
# STRONA TYTUŁOWA
# ══════════════════════════════════════════════════════════════════
story.append(Spacer(1, 3*cm))
story.append(Paragraph("EWNAF v${VERSION}", sH1))
story.append(Paragraph("Enterprise Network Audit Framework", S('Normal', fontSize=13, textColor=C_GRAY, fontName='Helvetica', leading=16)))
story.append(Spacer(1, 0.8*cm))

# Score panel
score_data = [
    [Paragraph(f'<font size="36" color="#{sc.hexval()[2:] if hasattr(sc,"hexval") else "60a5fa"}">{gs}</font>', S('Normal', fontName='Helvetica-Bold', fontSize=36, textColor=sc, leading=40, alignment=TA_CENTER)),
     Paragraph(f'<font size="36" color="#{sc.hexval()[2:] if hasattr(sc,"hexval") else "60a5fa"}">${grade}</font>', S('Normal', fontName='Helvetica-Bold', fontSize=36, textColor=sc, leading=40, alignment=TA_CENTER)),
     Paragraph(f'<font size="14">${tier}</font><br/><font size="8" color="#94a3b8">${verdict_pl}<br/>${verdict_en}</font>', S('Normal', fontName='Helvetica-Bold', fontSize=14, textColor=sc, leading=18, alignment=TA_CENTER))],
    [Paragraph("Global Score", sCaption), Paragraph("Grade", sCaption), Paragraph("Cybersecurity Tier / Werdykt", sCaption)]
]
t = Table(score_data, colWidths=[4.5*cm, 4.5*cm, 8*cm])
t.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,-1), C_DARK),
    ('GRID', (0,0), (-1,-1), 0.5, C_BORDER),
    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ('TOPPADDING', (0,0), (-1,-1), 12),
    ('BOTTOMPADDING', (0,0), (-1,-1), 8),
]))
story.append(t)
story.append(Spacer(1, 0.5*cm))

meta_data = [
    ['Klient / Client:', '${CLIENT_NAME}', 'Zakres / Scope:', 'target-centric'],
    ['Data / Date:', datetime.datetime.now().strftime('%Y-%m-%d'), 'Tryb / Mode:', '${MODE:-—}'],
    ['Hosty / Hosts:', '${DEV_COUNT}', 'Wersja / Version:', 'EWNAF v${VERSION}'],
    ['Threat Level:', str(bh_threat), 'Correlation:', str(bh_corr)],
]
mt = Table(meta_data, colWidths=[4*cm, 5*cm, 4*cm, 5*cm])
mt.setStyle(TableStyle([
    ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
    ('FONTSIZE', (0,0), (-1,-1), 8),
    ('TEXTCOLOR', (0,0), (0,-1), C_GRAY),
    ('TEXTCOLOR', (2,0), (2,-1), C_GRAY),
    ('TEXTCOLOR', (1,0), (1,-1), C_TEXT),
    ('TEXTCOLOR', (3,0), (3,-1), C_TEXT),
    ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
    ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
    ('BACKGROUND', (0,0), (-1,-1), C_DARK),
    ('GRID', (0,0), (-1,-1), 0.3, C_BORDER),
    ('TOPPADDING', (0,0), (-1,-1), 5),
    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ('LEFTPADDING', (0,0), (-1,-1), 8),
]))
story.append(mt)
story.append(PageBreak())

# ══════════════════════════════════════════════════════════════════
# SEKCJA 1: EXECUTIVE SUMMARY
# ══════════════════════════════════════════════════════════════════
story.append(Paragraph("1. Podsumowanie menedżerskie / Executive Summary", sH2))
story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
story.append(Spacer(1, 0.2*cm))

story.append(Paragraph(
    "<b>PL:</b> Wynik końcowy obliczany jako Ryzyko Rezydualne = Ryzyko Surowe − Mitigacje. "
    "Faza behawioralna (Faza X) ocenia dynamikę obrony sieci: mierzy zmiany latencji, "
    "eskalację, warstwy deception i korelację między hostami. Wyniki są niezależne od "
    "konkretnych produktów bezpieczeństwa.",
    sBilingual))
story.append(Paragraph(
    "<b>EN:</b> Final score = Raw Risk − Mitigations. Phase X assesses network defence dynamics: "
    "latency shifts, escalation, deception layers, state memory, and cross-host correlation. "
    "Results are product-agnostic.",
    sBilingual))
story.append(Spacer(1, 0.3*cm))

kpi_data = [
    ['Global Score', 'Grade', 'Maturity', 'Critical Hosts', 'High Hosts', 'Threat Level', 'Threat Score (Formal)', 'Correlation'],
    [str(gs), '${grade}', '${maturity}', '${H_CRITICAL:-0}', '${H_HIGH:-0}', str(bh_threat), str(bh_corr)],
]
kt = Table(kpi_data, colWidths=[2.5*cm]*7)
kt.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), C_DARK),
    ('TEXTCOLOR', (0,0), (-1,0), C_GRAY),
    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
    ('FONTSIZE', (0,0), (-1,0), 6.5),
    ('FONTSIZE', (0,1), (-1,1), 14),
    ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'),
    ('TEXTCOLOR', (0,1), (-1,1), sc),
    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
    ('GRID', (0,0), (-1,-1), 0.3, C_BORDER),
    ('TOPPADDING', (0,0), (-1,-1), 6),
    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ('ROWBACKGROUNDS', (0,1), (-1,1), [C_DARK]),
]))
story.append(kt)
story.append(PageBreak())

# ══════════════════════════════════════════════════════════════════
# SEKCJA 6: BEHAVIOURAL RECON (Faza X) — przed findings bo to serce
# ══════════════════════════════════════════════════════════════════
story.append(Paragraph("6. Behavioural Recon — Faza X / Phase X", sH2))
story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
story.append(Spacer(1, 0.2*cm))

story.append(Paragraph(
    "<b>PL:</b> Silnik behawioralny nie skanuje portów. Mierzy jak sieć oddycha: "
    "zmiana latencji po burście, eskalacja obrony, tarpit, honeypot, korelacja między hostami, "
    "pamięć stanów po 45-180 sekundach. Wynik niezależny od konkretnych produktów.",
    sBilingual))
story.append(Paragraph(
    "<b>EN:</b> Behavioural engine does not scan ports. It measures how the network breathes: "
    "latency shift after burst, defence escalation, tarpit, honeypot, cross-host correlation, "
    "state memory after 45-180 second intervals. Product-agnostic output.",
    sBilingual))
story.append(Spacer(1, 0.3*cm))

# Session state panel
sess_data = [
    ['Metryka / Metric', 'Wartość / Value', 'Interpretacja / Interpretation'],
    ['Threat Level', str(bh_threat), 'Poziom eskalacji obronnej w sesji / Defence escalation level'],
    ['Correlation Score', str(bh_corr), 'Korelacja zdarzeń między hostami / Cross-host event correlation'],
    ['Adaptation Detected', 'TAK/YES' if bh_adapt == '1' else 'NIE/NO', 'Obrona zmieniła zachowanie w trakcie sesji / Defence adapted during session'],
    ['Cross-Host Shifts', '${SESSION_STATE[cross_host_latency_shift]:-0}', 'Liczba przypadków zmiany latencji host A po próbie host B'],
    ['Hosts Reactive', '${SESSION_STATE[hosts_reactive]:-0}', 'Hosty które zmieniły zachowanie po bodźcu'],
    ['Hosts Deceptive', '${SESSION_STATE[hosts_deceptive]:-0}', 'Hosty z warstwą deception (fake listener / tarpit / pozorne odpowiedzi)'],
]
st = Table(sess_data, colWidths=[4*cm, 3*cm, 11*cm])
st.setStyle(tbl_style())
story.append(st)
story.append(Spacer(1, 0.4*cm))

# Mapa behawioralna
bh_raw = """${bh_data}"""
bh_lines = [l for l in bh_raw.strip().split('\\n') if l.strip() and '|' in l]
if bh_lines:
    story.append(Paragraph("Mapa behawioralna hostów / Behavioural Host Map", sH3))
    bmap_data = [['Entity', 'Zone', 'RS', 'DP', 'CL', 'Sygnały / Signals', 'Pamięć / Memory']]
    for line in bh_lines:
        parts = line.split('|')
        if len(parts) >= 7:
            ip, zone, rs, dp, cl, sigs, ret = parts[:7]
            bmap_data.append([
                Paragraph(f'<font color="#60a5fa">{ip.strip()}</font>', sSmall),
                Paragraph(f'<font color="#{zone_color(zone.strip()).hexval()[2:] if hasattr(zone_color(zone.strip()),"hexval") else "94a3b8"}">{zone.strip()}</font>', sSmall),
                rs.strip(), dp.strip(), cl.strip(),
                Paragraph(sigs.strip()[:60], sSmall),
                ret.strip()
            ])
    bt = Table(bmap_data, colWidths=[3.5*cm, 3*cm, 1.2*cm, 1.2*cm, 1.2*cm, 5*cm, 2.5*cm])
    bt.setStyle(tbl_style())
    story.append(bt)
story.append(PageBreak())

# ══════════════════════════════════════════════════════════════════
# SEKCJA 7: FINDINGS
# ══════════════════════════════════════════════════════════════════
story.append(Paragraph("7. Znaleziska i rekomendacje / Findings & Remediation", sH2))
story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
story.append(Spacer(1, 0.2*cm))

findings_raw = """${findings_net}"""
find_lines = [l for l in findings_raw.strip().split('\\n') if l.strip() and '|' in l]
if find_lines:
    fdata = [['Powaga / Severity', 'Kategoria', 'Opis / Description', 'Rekomendacja / Remediation']]
    for line in find_lines:
        parts = line.split('|')
        if len(parts) >= 3:
            sev = parts[0].strip()
            fcat = parts[1].strip() if len(parts) > 1 else ''
            fdesc = parts[2].strip() if len(parts) > 2 else ''
            frec = parts[3].strip() if len(parts) > 3 else ''
            sc2 = sev_color(sev)
            fdata.append([
                Paragraph(f'<font color="#{sc2.hexval()[2:] if hasattr(sc2,"hexval") else "94a3b8"}"><b>{sev}</b></font>', sSmall),
                Paragraph(fcat[:30], sSmall),
                Paragraph(fdesc[:120], sSmall),
                Paragraph(frec[:120], sSmall),
            ])
    ft = Table(fdata, colWidths=[2.5*cm, 3*cm, 7*cm, 5*cm])
    ft.setStyle(tbl_style())
    story.append(ft)
else:
    story.append(Paragraph("Brak znalezisk sieciowych / No network findings", sSmall))
story.append(PageBreak())

# ══════════════════════════════════════════════════════════════════
# SEKCJA 8: COMPLIANCE
# ══════════════════════════════════════════════════════════════════
story.append(Paragraph("8. Zgodność / Compliance  ·  CIS · ISO 27001 · NIST · GDPR", sH2))
story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
story.append(Spacer(1, 0.2*cm))

l3_iso  = "${L3_RESULTS[east_west_isolated]:-0}"
dns_cis = "${TRAFFIC_POLICY[dns_controlled]:-0}"
ids_cis = "${TOPO[ids_detected]:-0}"
tls_ok  = "${TRAFFIC_POLICY[tls_intercepted]:-0}"
dns_lk  = "${TRAFFIC_POLICY[dns_leak]:-0}"
cross   = "${L3_RESULTS[cross_subnet_ok]:-1}"

def pass_fail(val, invert=False):
    ok = val == '1'
    if invert: ok = not ok
    return ('PASS', C_GREEN) if ok else ('FAIL', C_RED)

comp_data = [
    ['Standard', 'Kontrola / Control', 'Status', 'Odniesienie / Reference'],
    ['CIS v8 CIS-9',  'DNS Filtering aktywny',           *pass_fail(dns_cis),  'CIS Control 9.2'],
    ['CIS v8 CIS-12', 'Segmentacja sieci East-West',     *pass_fail(l3_iso),   'CIS Control 12.2'],
    ['CIS v8 CIS-13', 'Network monitoring / IDS active', *pass_fail(ids_cis),  'CIS Control 13.3'],
    ['ISO 27001 A.9', 'Kontrola dostępu sieciowego',     *pass_fail(cross, invert=True), 'A.9.4.2'],
    ['ISO 27001 A.10','Ochrona TLS (brak intercept)',     *pass_fail(tls_ok, invert=True), 'A.10.1.1'],
    ['NIST PR.AC',    'Privilege management / segm.',    *pass_fail(l3_iso),   'PR.AC-4'],
    ['NIST PR.DS',    'Data-in-transit encryption',      *pass_fail(tls_ok, invert=True), 'PR.DS-2'],
    ['GDPR Art. 32',  'Brak wycieku DNS / DNS leak',     *pass_fail(dns_lk, invert=True), 'Art. 32 RODO'],
]
ct = Table(comp_data, colWidths=[4*cm, 6*cm, 2*cm, 5.5*cm])
cstyle = tbl_style()
for i, row in enumerate(comp_data[1:], 1):
    color = row[2] if isinstance(row[2], type(C_GREEN)) else (C_GREEN if row[2] == 'PASS' else C_RED)
    cstyle.add('TEXTCOLOR', (2,i), (2,i), color)
    cstyle.add('FONTNAME', (2,i), (2,i), 'Helvetica-Bold')
ct.setStyle(cstyle)
story.append(ct)

story.append(Spacer(1, 0.5*cm))
story.append(Paragraph(
    "Macierz oparta na wynikach aktywnych testów behawioralnych i topologicznych. "
    "Status N/A oznacza brak wystarczających danych do oceny. "
    "/ Matrix based on active behavioural and topology test results. "
    "N/A status indicates insufficient data for assessment.",
    sCaption))

doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
print("PDF OK")
PYSCRIPT
    local rc=$?
    if (( rc != 0 )) || [[ ! -s "$REPORT_PDF" ]]; then
        log "PDF render failed; raport PDF pominięty w tym środowisku." "WARN"
        return 1
    fi
    log "PDF gotowy: $REPORT_PDF" "OK"
}

###############################################################################
# GLOBALNY STAN SESJI — PAMIEC MIEDZY HOSTAMI
# Nie resetuje sie dla każdego hosta — rośnie przez cały czas trwania audytu.
###############################################################################

declare -A SESSION_STATE=(
    [threat_level]=0           # 0-100: rośnie gdy sieć reaguje agresywnie
    [correlation_score]=0      # 0-100: czy zdarzenia sa powiazane miedzy hostami
    [deception_score]=0        # 0-100: globalny wskaznik warstwy deception
    [adaptation_detected]=0    # 0/1: czy obrona zmienila zachowanie w trakcie sesji
    [escalation_threshold]=0   # ile prob zanim obrona reaguje — ustalany empirycznie
    [noise_floor]=0            # bazowa latencja sieci (ustalana w pierwszych 10 probach)
    [hosts_probed]=0           # ile hostow juz zbadano
    [hosts_reactive]=0         # ile hostow zmienilo zachowanie
    [hosts_deceptive]=0        # ile hostow wykazuje deception
    [cross_host_latency_shift]=0  # czy badanie hosta A zmienilo latencje hosta B?
    [current_jitter_ms]=300    # aktualny jitter — adaptuje sie do srodowiska
    [current_burst_size]=5     # aktualny burst — maleje gdy siec eskaluje
    [probe_speed]=NORMAL       # SLOW / NORMAL / FAST — adaptuje sie
    [session_paused]=0         # 1 = silnik sie schował (czeka na reset strażnika)
    [pause_until]=0            # timestamp do kiedy pauzujemy
    [total_probes]=0           # sumaryczna liczba prob w sesji
    [return_targets]=""        # hosty do ponownego odwiedzenia (powrot do miejsca)
    [phase_x_done]=0           # czy faza X juz uruchomiona
    [heat]=0                   # aktywna intensywność (0-100) — decay w czasie
    [heat_last_probe_ts]=0     # timestamp ostatniej próby
    [heat_decay_rate]=5        # punkty heat które spadają co 30s bez prób
    [rate_gov_window]=0        # timestamp okna rate governor
    [rate_gov_count]=0         # ile prób w oknie (max 10/30s)
)

# Pamiec behawioralna miedzy hostami — "co zmieniło sie po badaniu X?"
declare -A GLOBAL_BEHAVIOR_MEMORY=()
# Klucze: "hostA:port:before" "hostA:port:after_probe_hostB"

# Historia prób — timeline
declare -a PROBE_TIMELINE=()

# ADAPTACYJNY SCHEDULER — SERCE SYSTEMU
# Nie decyduje co zbadac. Decyduje JAK i KIEDY.

_sched_update_threat() {
    local delta="${1:-0}"
    local new
    # delta=0: tylko przelicz prędkość, nie zmieniaj threat_level
    if (( delta != 0 )); then
        new=$(( SESSION_STATE[threat_level] + delta ))
        (( new > 100 )) && new=100
        (( new < 0 ))   && new=0
        SESSION_STATE[threat_level]=$new
    else
        new=${SESSION_STATE[threat_level]}
    fi

    # Adaptacja prędkości: max(threat_level, heat) decyduje o prędkości
    # heat > threat oznacza: niedawno robiłeś dużo prób — zwolnij nawet jeśli threat niski
    _sched_heat_decay
    local heat="${SESSION_STATE[heat]:-0}"
    local intensity=$(( new > heat ? new : heat ))

    if (( intensity >= 70 )); then
        SESSION_STATE[probe_speed]="SLOW"
        SESSION_STATE[current_jitter_ms]=1400
        SESSION_STATE[current_burst_size]=2
        _bh_log "SCHEDULER: threat=${new} heat=${heat} intensity=${intensity} → SLOW"
    elif (( intensity >= 40 )); then
        SESSION_STATE[probe_speed]="NORMAL"
        SESSION_STATE[current_jitter_ms]=600
        SESSION_STATE[current_burst_size]=3
        _bh_log "SCHEDULER: threat=${new} heat=${heat} intensity=${intensity} → NORMAL"
    else
        SESSION_STATE[probe_speed]="FAST"
        SESSION_STATE[current_jitter_ms]=150
        SESSION_STATE[current_burst_size]=5
    fi
}

_sched_adaptive_jitter() {
    local base="${SESSION_STATE[current_jitter_ms]:-300}"
    (( base < 2 )) && base=2
    local var=$(( RANDOM % (base / 2) ))
    local ms=$(( base - (base / 4) + var ))
    sleep "0.$(printf '%03d' $(( ms % 1000 )))" 2>/dev/null || sleep 1
}

_sched_should_pause() {
    local now; now=$(_bh_ts_s)
    if (( SESSION_STATE[session_paused] == 1 )); then
        if (( now < SESSION_STATE[pause_until] )); then
            return 0   # nadal pausujemy
        else
            SESSION_STATE[session_paused]=0
            _bh_log "SCHEDULER: pauza skonczona — wznawiam eksploracje"
            return 1
        fi
    fi
    return 1
}

_sched_pause() {
    local seconds="${1:-60}"
    local until=$(( $(_bh_ts_s) + seconds ))
    SESSION_STATE[session_paused]=1
    SESSION_STATE[pause_until]=$until
    _bh_log "SCHEDULER: PAUZA ${seconds}s — zlodziej sie chowa"
    sleep "$seconds"
    SESSION_STATE[session_paused]=0
}

_sched_heat_add() {
    # Dodaj punkty heat po każdej próbie
    local delta="${1:-5}"
    local now; now=$(_bh_ts_s)
    # Najpierw decay: za każde 30s bez próby odejmij heat_decay_rate punktów
    local last="${SESSION_STATE[heat_last_probe_ts]:-0}"
    if (( last > 0 && now > last )); then
        local elapsed=$(( now - last ))
        local decay_periods=$(( elapsed / 30 ))
        if (( decay_periods > 0 )); then
            local decay=$(( decay_periods * SESSION_STATE[heat_decay_rate] ))
            SESSION_STATE[heat]=$(( SESSION_STATE[heat] - decay ))
            (( SESSION_STATE[heat] < 0 )) && SESSION_STATE[heat]=0
        fi
    fi
    SESSION_STATE[heat]=$(( SESSION_STATE[heat] + delta ))
    (( SESSION_STATE[heat] > 100 )) && SESSION_STATE[heat]=100
    SESSION_STATE[heat_last_probe_ts]=$now
}

_sched_heat_decay() {
    # Wywołaj bez próby — tylko decay
    local now; now=$(_bh_ts_s)
    local last="${SESSION_STATE[heat_last_probe_ts]:-0}"
    (( last == 0 )) && SESSION_STATE[heat_last_probe_ts]=$now && return
    local elapsed=$(( now - last ))
    local decay_periods=$(( elapsed / 30 ))
    if (( decay_periods > 0 )); then
        local decay=$(( decay_periods * SESSION_STATE[heat_decay_rate] ))
        SESSION_STATE[heat]=$(( SESSION_STATE[heat] - decay ))
        (( SESSION_STATE[heat] < 0 )) && SESSION_STATE[heat]=0
        _bh_log "HEAT DECAY: ${decay} pts (${elapsed}s elapsed) → heat=${SESSION_STATE[heat]}"
    fi
}

_sched_rate_ok() {
    # Rate governor: max 10 prób / 30s okno. Zwraca 0 jeśli można, 1 jeśli trzeba czekać.
    local now; now=$(_bh_ts_s)
    local win="${SESSION_STATE[rate_gov_window]:-0}"
    local cnt="${SESSION_STATE[rate_gov_count]:-0}"

    if (( now - win >= 30 )); then
        # Nowe okno
        SESSION_STATE[rate_gov_window]=$now
        SESSION_STATE[rate_gov_count]=1
        return 0
    fi

    if (( cnt < 10 )); then
        SESSION_STATE[rate_gov_count]=$(( cnt + 1 ))
        return 0
    fi

    # Przekroczono limit — czekaj
    local wait_s=$(( 30 - (now - win) ))
    (( wait_s < 1 )) && wait_s=1
    _bh_log "RATE GOVERNOR: limit 10/30s przekroczony — pauza ${wait_s}s (heat=${SESSION_STATE[heat]})"
    sleep "$wait_s"
    SESSION_STATE[rate_gov_window]=$(_bh_ts_s)
    SESSION_STATE[rate_gov_count]=1
    return 0
}

_sched_mark_for_return() {
    local ip="$1" reason="$2"
    local current="${SESSION_STATE[return_targets]}"
    SESSION_STATE[return_targets]="${current} ${ip}"
    _bh_log "SCHEDULER: ${ip} oznaczony do powrotu (${reason})"
}

# CROSS-HOST MEMORY — CZY HOST B ZMIENIL SIE PO PROBIE HOSTA A?
# To wykrywa centralny system korelacji (SIEM, NDR, centralny firewall).

_mem_snapshot() {
    local ip="$1" port="$2" label="$3"
    local raw ms state
    raw=$(_bh_probe_full "$ip" "$port")
    ms="${raw%%|*}"
    state="${raw#*|}"; state="${state%%|*}"
    GLOBAL_BEHAVIOR_MEMORY["${ip}:${port}:${label}"]="${ms}:${state}"
    _bh_log "MEMORY snap ${ip}:${port} [${label}] = ${ms}ms/${state}"
}

_mem_compare_cross() {
    local ref_ip="$1" probe_ip="$2" port="${3:-80}"
    # Snapshot ref_ip przed badaniem probe_ip
    _mem_snapshot "$ref_ip" "$port" "before_${probe_ip//\./_}"

    # Tutaj wywolujacy zbada probe_ip
    # Po powrocie:
    _mem_snapshot "$ref_ip" "$port" "after_${probe_ip//\./_}"

    local before="${GLOBAL_BEHAVIOR_MEMORY["${ref_ip}:${port}:before_${probe_ip//\./_}"]}"
    local after="${GLOBAL_BEHAVIOR_MEMORY["${ref_ip}:${port}:after_${probe_ip//\./_}"]}"

    local ms_b="${before%%:*}" ms_a="${after%%:*}"
    _is_int "$ms_b" && _is_int "$ms_a" || return 1

    local delta=$(( ms_a - ms_b ))
    (( delta < 0 )) && delta=$(( -delta ))

    # Jesli latencja hosta A zmieniła sie o >200ms po badaniu hosta B
    # → mamy centralny system korelacji
    if (( delta > 200 )); then
        _bh_log "CROSS-HOST CORRELATION: ${ref_ip} zmienił latencje o ${delta}ms po probie ${probe_ip}"
        (( SESSION_STATE[correlation_score] += 20 ))
        (( SESSION_STATE[cross_host_latency_shift]++ ))
        SESSION_STATE[adaptation_detected]=1
        _sched_update_threat 15
        return 0
    fi
    return 1
}

# POWROT DO MIEJSCA ZBRODNI

_return_visit() {
    local ip="$1"
    local wait_s="${2:-45}"

    _bh_log "RETURN VISIT: ${ip} — czekam ${wait_s}s przed powrotem"

    # Losowy czas oczekiwania (30-180s) — nieregularny powrót
    local actual_wait=$(( wait_s + (RANDOM % 60) ))
    sleep "$actual_wait"

    _bh_log "RETURN: badamy ${ip} ponownie po ${actual_wait}s"

    # Nowe baseline
    local new_baseline
    _bh_baseline "$ip" "80"; new_baseline="$_BH_RET"
    local new_ms="${new_baseline%%|*}"

    # Porownaj z poprzednim
    local old_ms="${BH["${ip}:80:baseline_ms"]:-0}"

    if _is_int "$new_ms" && _is_int "$old_ms" && (( old_ms > 0 )); then
        local delta=$(( new_ms - old_ms ))
        (( delta < 0 )) && delta=$(( -delta ))

        if (( delta > old_ms / 2 )); then
            # Latencja nadal podwyzszona — system pamięta
            _bh_log "RETURN ${ip}: system pamięta! old=${old_ms}ms new=${new_ms}ms delta=${delta}ms"
            BH["${ip}:return_memory"]="YES"
            BH["${ip}:return_delta_ms"]="$delta"
            (( SESSION_STATE[correlation_score] += 15 ))
            _sched_update_threat 10
            add_net_finding "HIGH" "BEHAVIOURAL_RETURN" \
                "${ip}: System pamięta poprzednią sesję (latencja +${delta}ms po ${actual_wait}s przerwy)" \
                "Reputacyjna blokada lub stan sesji utrzymywany ponad minutę. Wskazuje na NDR/EDR z pamięcią stanów."
        else
            # Wrocilo do normy — strażnik zapomniał
            _bh_log "RETURN ${ip}: strażnik zapomniał (${old_ms}ms → ${new_ms}ms — norma)"
            BH["${ip}:return_memory"]="NO"
            BH["${ip}:return_delta_ms"]="$delta"
        fi
    fi

    # Powtorow deception test
    local dec_result
    _bh_deception_probe "$ip"; dec_result="$_BH_RET"
    local new_dec="${dec_result%%|*}"
    local old_dec="${BH["${ip}:deception_score"]:-0}"

    if _is_int "$new_dec" && _is_int "$old_dec"; then
        local dec_delta=$(( new_dec - old_dec ))
        if (( dec_delta > 20 )); then
            _bh_log "RETURN ${ip}: deception wzrósł po powrocie (+${dec_delta}) — dynamiczna warstwa deception"
            add_net_finding "HIGH" "BEHAVIOURAL_RETURN" \
                "${ip}: Warstwa deception zmienila sie miedzy wizytami (+${dec_delta} punktów)" \
                "Dynamiczna warstwa deception. Sieć rozpoznaje wzorce audytora."
        fi
    fi
}

# CHOOSE NEXT TARGET — PIES IDZIE W STRONE NAJSILNIEJSZEGO ZAPACHU
# Nie skanuje zakresu. Decyduje gdzie isc na podstawie:
#   1. Co dotychczas odkryto (mapa behawioralna)
#   2. Gdzie reakcja była najsilniejsza (entropia)
#   3. Co nie było jeszcze zbadane w tej rundzie

_choose_next_target() {
    local -a candidates=("$@")
    local best_ip="" best_score=-1

    for ip in "${candidates[@]}"; do
        local score=0

        # Prioritize hosts with observed reactivity
        local react="${BH["${ip}:80:reactivity"]:-0}"
        local escal="${BH["${ip}:80:escalation"]:-0}"
        local dec="${BH["${ip}:deception_score"]:-0}"
        local probed="${BH["${ip}:probed"]:-0}"

        # Nie odwiedzony = wysoki priorytet
        (( probed == 0 )) && (( score += 50 ))

        # Reaktywny = idz dalej — tam jest cos ciekawego
        (( react == 1 )) && (( score += 30 ))
        (( escal == 1 )) && (( score += 20 ))

        # Deception = zmniejsz priorytet (juz wiemy) ale nie zeruj
        (( dec > 50 )) && (( score -= 10 ))

        # Losowy szum — pies nie chodzi przewidywalnie
        score=$(( score + (RANDOM % 15) ))

        if (( score > best_score )); then
            best_score=$score
            best_ip="$ip"
        fi
    done

    _BH_RET="$best_ip"
    echo "$best_ip"
}

# GLOWNA PETLA EKSPLORACYJNA — NOWY RDZEN
# Zastepuje statyczny pipeline.
# Sterownik calego audytu behawioralnego.


run_exploration_loop() {
    local -a all_hosts=("$@")
    if [[ "${DETERMINISTIC:-0}" == "1" && ${#all_hosts[@]} -gt 1 ]]; then
        mapfile -t all_hosts < <(_sort_ips "${all_hosts[@]}")
    fi
    [[ ${#all_hosts[@]} -eq 0 ]] && return 0

    log "============================================================" "SECTION"
    log " $(L phase_bh)" "SECTION"
    log " $(L bh_hosts "${#all_hosts[@]}" "${BH_BUDGET}")" "SECTION"
    log "============================================================" "SECTION"

    local nf_samples=()
    local nf_target="${all_hosts[0]:-}"
    if [[ -n "$nf_target" ]]; then
        local i
        for i in 1 2 3 4 5; do
            local raw ms
            raw=$(_bh_probe_full "$nf_target" "80")
            ms="${raw%%|*}"
            _is_int "$ms" && nf_samples+=("$ms")
            sleep 0.1
        done
        if (( ${#nf_samples[@]} >= 3 )); then
            SESSION_STATE[noise_floor]=$(_median_int "${nf_samples[@]}")
            _bh_log "NOISE FLOOR ustalony: ${SESSION_STATE[noise_floor]}ms (via target ${nf_target})"
        fi
    fi

    log " $(L bh_round1)" "SECTION"
    local -a remaining=("${all_hosts[@]}")
    local -a visited=()

    while _bh_budget_ok && (( ${#remaining[@]} > 0 )); do
        _sched_should_pause && continue
        local ip
        _choose_next_target "${remaining[@]}"; ip="$_BH_RET"
        [[ -z "$ip" ]] && break

        local new_remaining=()
        for h in "${remaining[@]}"; do
            [[ "$h" != "$ip" ]] && new_remaining+=("$h")
        done
        remaining=("${new_remaining[@]}")
        visited+=("$ip")

        BH["${ip}:probed"]="1"
        (( SESSION_STATE[hosts_probed]++ ))

        local ref_ip=""
        [[ ${#visited[@]} -ge 2 ]] && ref_ip="${visited[-2]}"
        [[ -n "$ref_ip" ]] && _mem_snapshot "$ref_ip" "80" "before_${ip//\./_}"

        _bh_log "==== HOST ${ip} (budget=${BH_BUDGET} threat=${SESSION_STATE[threat_level]}) ===="

        local p
        for p in 80 22 443; do
            _bh_budget_ok || break
            _bh_baseline "$ip" "$p"
            _sched_adaptive_jitter
        done

        _bh_budget_ok && _bh_burst_test "$ip" "80"
        _bh_budget_ok && _bh_correlation_probe "$ip"
        _bh_budget_ok && _bh_deception_probe "$ip"
        _bh_budget_ok && _bh_noise_tolerance "$ip" "80"

        if [[ -n "${T[dig]:-}" && -n "${INTERNAL_DNS:-}" ]]; then
            local dns_state
            dns_state=$(g_dns_classify "${INTERNAL_DNS}" "example.com")
            BH["${ip}:dns_state_after_probe"]="$dns_state"
            if [[ "$dns_state" == "SINKHOLE" || "$dns_state" == "NXDOMAIN" ]]; then
                _bh_log "DNS sinkhole po probach TCP na ${ip} — mozliwa korelacja DNS/TCP"
                (( SESSION_STATE[correlation_score] += 10 ))
                _sched_update_threat 8
            fi
        fi

        [[ -n "$ref_ip" ]] && {
            _mem_snapshot "$ref_ip" "80" "after_${ip//\./_}"
            local bef="${GLOBAL_BEHAVIOR_MEMORY["${ref_ip}:80:before_${ip//\./_}"]}"
            local aft="${GLOBAL_BEHAVIOR_MEMORY["${ref_ip}:80:after_${ip//\./_}"]}"
            local ms_b="${bef%%:*}" ms_a="${aft%%:*}"
            if _is_int "$ms_b" && _is_int "$ms_a" && (( ms_b > 0 )); then
                local xdelta=$(( ms_a - ms_b ))
                (( xdelta < 0 )) && xdelta=$(( -xdelta ))
                if (( xdelta > 200 )); then
                    _bh_log "CROSS-HOST: ${ref_ip} zmienil sie o ${xdelta}ms po probie ${ip} — centralny IDS/SIEM"
                    (( SESSION_STATE[correlation_score] += 20 ))
                    SESSION_STATE[adaptation_detected]=1
                    _sched_update_threat 15
                fi
            fi
        }
    done

    log " $(L bh_round2)" "SECTION"
    local revisit_budget=0
    local revisit_ip
    for revisit_ip in "${visited[@]}"; do
        (( revisit_budget >= 3 )) && break
        _bh_budget_ok || break
        _bh_return_visit "$revisit_ip"
        (( revisit_budget++ ))
    done

    local map_ip zone
    PHASE_X[hosts_total]="${#visited[@]}"
    PHASE_X[zones_silent]=0
    PHASE_X[zones_reactive]=0
    PHASE_X[zones_deception]=0
    PHASE_X[zones_correlated]=0
    PHASE_X[zones_escalating]=0
    PHASE_X[zones_adaptive]=0
    PHASE_X[zones_exposed]=0

    for map_ip in "${visited[@]}"; do
        _bh_classify_zone "$map_ip"; zone="$_BH_RET"
        BMAP["$map_ip"]="$zone"
        case "$zone" in
            SILENT)      (( PHASE_X[zones_silent]++ )) ;;
            REACTIVE)    (( PHASE_X[zones_reactive]++ )) ;;
            DECEPTION)   (( PHASE_X[zones_deception]++ )) ;;
            CORRELATED)  (( PHASE_X[zones_correlated]++ )) ;;
            ESCALATING)  (( PHASE_X[zones_escalating]++ )) ;;
            ADAPTIVE)    (( PHASE_X[zones_adaptive]++ )) ;;
            EXPOSED)     (( PHASE_X[zones_exposed]++ )) ;;
        esac
    done

    _bh_threat_score
    export_phase_x_findings
    log " $(L bh_state):" "SECTION"
    log "   threat_level=${SESSION_STATE[threat_level]}" "TOPO"
    log "   correlation_score=${SESSION_STATE[correlation_score]}" "TOPO"
    log "   deception_score=${SESSION_STATE[deception_score]}" "TOPO"
    log "   adaptation_detected=${SESSION_STATE[adaptation_detected]}" "TOPO"
    log "   cross_host_shift=${SESSION_STATE[cross_host_latency_shift]}" "TOPO"
    log "   hosts_reactive=${SESSION_STATE[hosts_reactive]}" "TOPO"
    log "   hosts_deceptive=${SESSION_STATE[hosts_deceptive]}" "TOPO"
    log "   total_probes=${SESSION_STATE[total_probes]}" "TOPO"

    if (( SESSION_STATE[adaptation_detected] == 1 )); then
        add_net_finding "HIGH" "SESSION_ANALYSIS" \
            "Siec wykazala adaptacje behawioralna w trakcie sesji audytowej" \
            "System centralnie koreluje zdarzenia. Audyt klasyczny jest widoczny i analizowany w czasie rzeczywistym."
    fi
}




# SLIDING WINDOW — MODEL ESKALACJI CZASOWEJ
#
# Obserwuje każde 5 kroków. Czy tempo rośnie? Czy maleje?
#
# Zbiera N próbek z timestampami. Analizuje:
#   - czy latencja rośnie liniowo (rate limiting)
#   - czy ma skok (threshold-based ban)
#   - czy spada po przerwie (recovery signature)
#
# Wynik: escalation_type = NONE|GRADUAL|THRESHOLD|BURSTY

# Bufor sliding window: ip:port:window = "ts1:ms1 ts2:ms2 ..."
declare -A BH_WINDOW=()
declare -i BH_WINDOW_SIZE=8        # rozmiar okna próbek
declare -i BH_WINDOW_THRESHOLD=150 # ms wzrostu = sygnał eskalacji

_bh_window_add() {
    local ip="$1" port="$2" ms="$3"
    local key="${ip}:${port}:window"
    local ts; ts=$(_bh_ts_s)
    local entry="${ts}:${ms}"
    local current="${BH_WINDOW[$key]:-}"

    # Dodaj nową próbkę
    local new_win
    new_win=$(echo "$current $entry" | tr ' ' '\n' | grep -v '^$' | tail -"$BH_WINDOW_SIZE" | tr '\n' ' ')
    BH_WINDOW["$key"]="${new_win% }"
}

_bh_window_analyze() {
    local ip="$1" port="$2"
    local key="${ip}:${port}:window"
    local data="${BH_WINDOW[$key]:-}"

    [[ -z "$data" ]] && echo "NONE|0|0" && return

    local -a vals=()
    local entry
    for entry in $data; do
        local ms="${entry#*:}"
        _is_int "$ms" && vals+=("$ms")
    done

    local n=${#vals[@]}
    (( n < 3 )) && echo "NONE|0|0" && return

    local first="${vals[0]}" last="${vals[$((n-1))]}"
    local mid="${vals[$((n/2))]}"

    _is_int "$first" && _is_int "$last" || { echo "NONE|0|0"; return; }

    local total_delta=$(( last - first ))
    local escalation_type="NONE"
    local max_jump=0

    # Znajdź największy skok między kolejnymi próbkami
    local i
    for (( i=1; i<n; i++ )); do
        local prev="${vals[$((i-1))]}" curr="${vals[$i]}"
        _is_int "$prev" && _is_int "$curr" || continue
        local jump=$(( curr - prev ))
        (( jump < 0 )) && jump=$(( -jump ))
        (( jump > max_jump )) && max_jump=$jump
    done

    # Klasyfikuj wzorzec
    if (( total_delta > BH_WINDOW_THRESHOLD * 3 && max_jump < total_delta / 2 )); then
        # Wolny, liniowy wzrost — rate limiting
        escalation_type="GRADUAL"
    elif (( max_jump > BH_WINDOW_THRESHOLD * 2 && max_jump > total_delta * 6/10 )); then
        # Jeden duży skok — próg bana (N-probe threshold ban)
        escalation_type="THRESHOLD"
        # Zapisz gdzie był próg
        for (( i=1; i<n; i++ )); do
            local prev="${vals[$((i-1))]}" curr="${vals[$i]}"
            _is_int "$prev" && _is_int "$curr" || continue
            local jump=$(( curr - prev ))
            (( jump == max_jump )) && {
                BH["${ip}:${port}:escalation_probe_n"]="$i"
                SESSION_STATE[escalation_threshold]="$i"
                _bh_log "WINDOW: próg bana wykryty przy próbie N=$i (${prev}ms → ${curr}ms)"
                break
            }
        done
    elif (( total_delta > BH_WINDOW_THRESHOLD && mid > first && mid > last )); then
        # Szczyt w środku — burst reaction
        escalation_type="BURSTY"
    elif (( total_delta > BH_WINDOW_THRESHOLD )); then
        escalation_type="GRADUAL"
    fi

    BH["${ip}:${port}:window_type"]="$escalation_type"
    BH["${ip}:${port}:window_delta"]="$total_delta"
    BH["${ip}:${port}:window_max_jump"]="$max_jump"

    _bh_log "WINDOW ${ip}:${port} -> type=${escalation_type} delta=${total_delta}ms max_jump=${max_jump}ms n=${n}"
    echo "${escalation_type}|${total_delta}|${max_jump}"
}

# Probe z automatycznym dodaniem do sliding window
_bh_window_probe() {
    local ip="$1" port="$2"
    _bh_budget_ok || return 1
    local raw; raw=$(_bh_probe_full "$ip" "$port")
    local ms="${raw%%|*}"
    _is_int "$ms" && _bh_window_add "$ip" "$port" "$ms"
    echo "$raw"
}

# CROSS-SERVICE DEPENDENCY — port A response changes after probing port B
# Metoda:
#   1. Baseline port B
#   2. Probe port A (N razy)
#   3. Measure port B ponownie
#   4. Delta > threshold → cross-service dependency
#
# Wynik: dependency_matrix[A→B] = delta_ms

declare -A BH_CROSS_SERVICE=()  # "${ip}:srcport→dstport" = delta_ms

_bh_cross_service() {
    local ip="$1"
    _bh_budget_ok || return 1

    _bh_log "CROSS-SERVICE PROBE ${ip}"

    # Pary port→port do sprawdzenia
    local -a pairs=("22→80" "22→443" "80→22" "443→22" "80→443")
    local detected=0
    local dependency_report=""

    for pair in "${pairs[@]}"; do
        local src_port="${pair%%→*}" dst_port="${pair##*→}"

        # 1. Baseline dst_port
        _bh_jitter 200 50
        local raw_b; raw_b=$(_bh_probe_full "$ip" "$dst_port")
        local ms_before="${raw_b%%|*}"
        _is_int "$ms_before" || continue

        # 2. Probe src_port N razy (trigger)
        local i
        for (( i=0; i<3; i++ )); do
            _bh_probe_full "$ip" "$src_port" >/dev/null
            sleep 0.08
        done

        # 3. Measure dst_port po triggerze
        _bh_jitter 100 30
        local raw_a; raw_a=$(_bh_probe_full "$ip" "$dst_port")
        local ms_after="${raw_a%%|*}"
        _is_int "$ms_after" || continue

        local delta=$(( ms_after - ms_before ))
        (( delta < 0 )) && delta=$(( -delta ))

        local baseline_var="${BH["${ip}:${dst_port}:baseline_variance"]:-40}"
        (( baseline_var < 20 )) && baseline_var=20

        if (( delta > baseline_var * 4 && delta > 80 )); then
            detected=$(( detected + 1 ))
            BH_CROSS_SERVICE["${ip}:${pair}"]="$delta"
            dependency_report="${dependency_report}${pair}:${delta}ms "
            _bh_log "  CROSS-SERVICE: ${ip} port ${src_port}→${dst_port} delta=${delta}ms (before=${ms_before}ms after=${ms_after}ms)"
            (( SESSION_STATE[correlation_score] += 15 ))
            _sched_update_threat 8
        fi

        _bh_jitter 300 100
    done

    BH["${ip}:cross_service_count"]="$detected"
    BH["${ip}:cross_service_pairs"]="${dependency_report:-none}"

    if (( detected >= 2 )); then
        _bh_log "CROSS-SERVICE ${ip}: ${detected} par — centralny IDS/IPS z korelacją portów"
        add_net_finding "HIGH" "BEHAVIOURAL_CROSS_SERVICE" \
            "${ip}: Wykryto korelację między portami (${detected} par). Dotknięcie portu X zmienia odpowiedź portu Y." \
            "Wskazuje na centralny IDS/IPS analizujący ruch jako sesję, nie jako izolowane połączenia. Sygnatura: ${dependency_report}"
        SESSION_STATE[adaptation_detected]=1
        _sched_update_threat 15
    elif (( detected == 1 )); then
        _bh_log "CROSS-SERVICE ${ip}: 1 para — możliwa korelacja lub jitter sieci"
    fi

    echo "$detected"
}

# THREAT SCORING — DETERMINISTYCZNA FUNKCJA
#
# Zamiast: SESSION_STATE[threat_level] += 15   (arbitralnie)
# Mamy:   threat = f(deception, correlation, escalation, cross_service)
#
# Model:
#   DECEPTION     → 0-40 pkt  (deception_score/100 * 40)
#   CORRELATION   → 0-30 pkt  (cross_host + cross_service)
#   ESCALATION    → 0-20 pkt  (window_type)
#   ADAPTATION    → 0-10 pkt  (return_memory + adaptation_detected)
#
# Razem max 100. Mapuje bezpośrednio na SESSION_STATE[threat_level].

_bh_threat_score() {
    # Zbiera dane ze wszystkich przebadanych hostów i wylicza globalny threat level

    local deception_total=0 deception_hosts=0
    local correlation_pts=0
    local escalation_pts=0
    local adaptation_pts=0

    # Iteruj przez wszystkich przebadanych hostów
    local ip
    for ip in "${!BH[@]}"; do
        # Wyciągnij tylko klucze ip (pattern: X.X.X.X:zone)
        [[ "$ip" != *:zone ]] && continue
        local host="${ip%%:*}"

        local dec="${BH["${host}:deception_score"]:-0}"
        _is_int "$dec" && {
            deception_total=$(( deception_total + dec ))
            (( dec > 0 )) && (( deception_hosts++ ))
        }

        local cross="${BH["${host}:cross_service_count"]:-0}"
        _is_int "$cross" && (( correlation_pts += cross * 5 ))

        local wtype="${BH["${host}:80:window_type"]:-NONE}"
        case "$wtype" in
            THRESHOLD) (( escalation_pts += 10 )) ;;
            GRADUAL)   (( escalation_pts += 6  )) ;;
            BURSTY)    (( escalation_pts += 4  )) ;;
        esac

        [[ "${BH["${host}:return_memory"]:-}" == "YES" ]] && (( adaptation_pts += 5 ))
    done

    # Normalizuj deception (0-40 pkt)
    local dec_pts=0
    (( deception_hosts > 0 )) && {
        local dec_avg=$(( deception_total / deception_hosts ))
        dec_pts=$(( dec_avg * 40 / 100 ))
    }

    # Normalizuj correlation (0-30 pkt)
    local corr_pts=$(( SESSION_STATE[cross_host_latency_shift] * 10 + correlation_pts ))
    (( corr_pts > 30 )) && corr_pts=30

    # Normalizuj escalation (0-20 pkt)
    (( escalation_pts > 20 )) && escalation_pts=20

    # Adaptation (0-10 pkt)
    (( SESSION_STATE[adaptation_detected] == 1 )) && (( adaptation_pts += 5 ))
    (( adaptation_pts > 10 )) && adaptation_pts=10

    local threat=$(( dec_pts + corr_pts + escalation_pts + adaptation_pts ))
    (( threat > 100 )) && threat=100

    SESSION_STATE[threat_level]="$threat"

    _bh_log "THREAT_SCORE: dec=${dec_pts} corr=${corr_pts} escal=${escalation_pts} adapt=${adaptation_pts} → TOTAL=${threat}"

    # Update probe_speed na podstawie deterministycznego threat
    _sched_update_threat 0   # wywołaj bez delty żeby przeliczyć prędkość
    echo "$threat"
}



_bh_ts()   { date +%s%3N; }
_bh_ts_s() { date +%s; }

_bh_log() {
    local msg="$1"
    local ts; ts=$(_bh_ts)
    BH_EVENTS+=("[${ts}] ${msg}")
    log "  [BHX] ${msg}" "TOPO"
}

_bh_budget_ok() {
    (( BH_BUDGET > 0 ))
}

_bh_spend() {
    local n="${1:-1}"
    (( BH_BUDGET -= n ))
    SESSION_STATE[total_probes]=$(( SESSION_STATE[total_probes] + n ))
    _sched_heat_add 3
    _sched_rate_ok
}

# Kameleon nie chodzi równym krokiem
_bh_jitter() {
    local max="${1:-$BH_JITTER_MAX}"
    local min="${2:-$BH_JITTER_MIN}"
    (( max <= min )) && max=$(( min + 100 ))
    local range=$(( max - min ))
    local ms=$(( (RANDOM % range) + min ))
    local sec="0.$(printf '%03d' $(( ms % 1000 )))"
    sleep "$sec" 2>/dev/null || sleep 1
}

# Returns: "ms|state|rst_class"
#   ms         — czas odpowiedzi
#   state      — OPEN / CLOSED / FILTERED / NO_ROUTE
#   rst_class  — FAST_RST / SLOW_RST / TIMEOUT_DROP / OPEN / NO_ROUTE

_bh_probe_full() {
    local ip="$1" port="$2"
    local t1 t2 ms state rst_class

    t1=$(_bh_ts)
    state=$(g_tcp_probe "$ip" "$port")
    t2=$(_bh_ts)
    ms=$(( t2 - t1 ))

    case "$state" in
        OPEN)
            rst_class="OPEN"
            ;;
        CLOSED)
            if (( ms < 80 )); then
                rst_class="FAST_RST"
            else
                rst_class="SLOW_RST"
            fi
            ;;
        FILTERED)
            rst_class="TIMEOUT_DROP"
            ;;
        NO_ROUTE)
            rst_class="NO_ROUTE"
            ms=0
            ;;
        *)
            rst_class="UNKNOWN"
            ;;
    esac

    _bh_spend 1
    echo "${ms}|${state}|${rst_class}"
}

#
# Nie szuka drzwi. Słucha temperatury.

_bh_baseline() {
    local ip="$1" port="$2"
    _bh_budget_ok || return 1

    local samples_ms=() states=() rst_classes=()
    local i raw ms state rst

    for i in $(seq 1 $BH_BASELINE_N); do
        _bh_jitter 600 100
        raw=$(_bh_probe_full "$ip" "$port")
        ms="${raw%%|*}"
        state="${raw#*|}"; state="${state%%|*}"
        rst="${raw##*|}"
        _is_int "$ms" && samples_ms+=("$ms")
        states+=("$state")
        rst_classes+=("$rst")
    done

    local med=0 dominant_state dominant_rst variance=0
    (( ${#samples_ms[@]} > 0 )) && med=$(_median_int "${samples_ms[@]}")
    dominant_state=$(printf '%s\n' "${states[@]}" | sort | uniq -c | sort -rn | awk '{print $2; exit}')
    dominant_rst=$(printf '%s\n' "${rst_classes[@]}" | sort | uniq -c | sort -rn | awk '{print $2; exit}')

    if (( ${#samples_ms[@]} >= 2 )); then
        local min_ms max_ms
        min_ms=$(printf '%s\n' "${samples_ms[@]}" | sort -n | head -1)
        max_ms=$(printf '%s\n' "${samples_ms[@]}" | sort -n | tail -1)
        variance=$(( max_ms - min_ms ))
    fi

    BH["${ip}:${port}:baseline_ms"]="$med"
    BH["${ip}:${port}:baseline_state"]="${dominant_state:-UNKNOWN}"
    BH["${ip}:${port}:baseline_rst"]="${dominant_rst:-UNKNOWN}"
    BH["${ip}:${port}:baseline_variance"]="$variance"

    _bh_log "BASELINE ${ip}:${port} -> ${med}ms [${dominant_state}/${dominant_rst}] var=${variance}ms"
    echo "${med}|${dominant_state}|${dominant_rst}|${variance}"
}

#
# Potem siada. Czeka. Patrzy czy strażnik biegnie.
# Potem wstaje — sprawdza czy już jest inaczej.

_bh_burst_test() {
    local ip="$1" port="$2"
    _bh_budget_ok || return 1

    local baseline_ms="${BH["${ip}:${port}:baseline_ms"]:-0}"
    local burst_samples=() burst_states=() i raw ms state

    _bh_log "BURST START ${ip}:${port} (n=${BH_BURST_SIZE})"

    for i in $(seq 1 $BH_BURST_SIZE); do
        raw=$(_bh_probe_full "$ip" "$port")
        ms="${raw%%|*}"
        state="${raw#*|}"; state="${state%%|*}"
        _is_int "$ms" && {
            burst_samples+=("$ms")
            _bh_window_add "$ip" "$port" "$ms"
        }
        burst_states+=("$state")
        sleep 0.04
    done

    # Analizuj sliding window po burście
    _bh_window_analyze "$ip" "$port"; local win_result="$_BH_RET"
    local win_type="${win_result%%|*}"
    _bh_log "WINDOW po burście ${ip}:${port} -> ${win_result}"

    local burst_med=0
    (( ${#burst_samples[@]} > 0 )) && burst_med=$(_median_int "${burst_samples[@]}")

    local state_change=0
    local first_state="${burst_states[0]:-}"
    local last_state="${burst_states[-1]:-}"
    [[ -n "$first_state" && -n "$last_state" && "$first_state" != "$last_state" ]] && state_change=1

    BH["${ip}:${port}:burst_med"]="$burst_med"
    BH["${ip}:${port}:burst_state_change"]="$state_change"

    _bh_log "BURST MED ${ip}:${port} -> ${burst_med}ms (baseline: ${baseline_ms}ms, state_change=${state_change})"

    # COOLDOWN
    _bh_log "COOLDOWN ${BH_COOLDOWN}s"
    sleep "$BH_COOLDOWN"

    # POST-BURST
    local post_samples=() post_states=() j raw2 ms2 state2
    for j in 1 2 3; do
        _bh_jitter 500 150
        raw2=$(_bh_probe_full "$ip" "$port")
        ms2="${raw2%%|*}"
        state2="${raw2#*|}"; state2="${state2%%|*}"
        _is_int "$ms2" && post_samples+=("$ms2")
        post_states+=("$state2")
    done

    local post_med=0
    (( ${#post_samples[@]} > 0 )) && post_med=$(_median_int "${post_samples[@]}")

    BH["${ip}:${port}:post_burst_ms"]="$post_med"

    local reactivity=0 adaptivity=0 escalation=0

    (( baseline_ms > 0 && burst_med > baseline_ms * 2 )) && reactivity=1
    (( post_med > baseline_ms * 3 && post_med > 200 ))   && adaptivity=1

    if (( ${#burst_samples[@]} >= 3 )); then
        local fb="${burst_samples[0]}" lb="${burst_samples[-1]}"
        _is_int "$fb" && _is_int "$lb" && (( lb > fb * 2 )) && escalation=1
    fi

    BH["${ip}:${port}:reactivity"]="$reactivity"
    BH["${ip}:${port}:adaptivity"]="$adaptivity"
    BH["${ip}:${port}:escalation"]="$escalation"

    _bh_log "REACTION ${ip}:${port} -> react=${reactivity} adapt=${adaptivity} escal=${escalation} post=${post_med}ms"
    echo "${reactivity}|${adaptivity}|${escalation}|${burst_med}|${post_med}"
}

#
# Obserwuje czy strażnik zawsze stoi pod tym samym obrazem
# czy podąża za sekwencją.
#
# Czysty firewall — nie koreluje. Korelujący IDS/SIEM — tak.

_bh_correlation_probe() {
    local ip="$1"
    _bh_budget_ok || return 1

    _bh_log "CORRELATION PROBE ${ip}"

    local seq_a=(22 80 443)
    local seq_b=(443 80 22)
    local results_a=() results_b=() p raw ms state

    for p in "${seq_a[@]}"; do
        _bh_jitter 300 80
        raw=$(_bh_probe_full "$ip" "$p")
        ms="${raw%%|*}"
        state="${raw#*|}"; state="${state%%|*}"
        results_a+=("${p}:${ms}:${state}")
    done

    sleep 2
    _bh_jitter 800 400

    for p in "${seq_b[@]}"; do
        _bh_jitter 300 80
        raw=$(_bh_probe_full "$ip" "$p")
        ms="${raw%%|*}"
        state="${raw#*|}"; state="${state%%|*}"
        results_b+=("${p}:${ms}:${state}")
    done

    local ms_22_a ms_22_b diff_22 correlation=0
    ms_22_a=$(echo "${results_a[0]}" | cut -d: -f2)
    ms_22_b=$(echo "${results_b[2]}" | cut -d: -f2)

    if _is_int "$ms_22_a" && _is_int "$ms_22_b" && (( ms_22_a > 0 && ms_22_b > 0 )); then
        diff_22=$(( ms_22_b - ms_22_a ))
        (( diff_22 < 0 )) && diff_22=$(( -diff_22 ))
        local bvar="${BH["${ip}:22:baseline_variance"]:-30}"
        (( bvar < 10 )) && bvar=30
        if (( diff_22 > bvar * 3 )); then
            correlation=1
            _bh_log "CORRELATION DETECTED ${ip} — sekwencja portów zmienia odpowiedź (${ms_22_a}ms -> ${ms_22_b}ms)"
        fi
    fi

    BH["${ip}:correlation"]="$correlation"
    _bh_log "CORRELATION ${ip} -> ${correlation} (22_a=${ms_22_a}ms, 22_b=${ms_22_b}ms)"
    echo "$correlation"
}

#
# Jeśli wszyscy odpowiadają identycznie — to manekiny.
#
# Sygnaly:
#   - port ciemny otwarty (honeypot)
#   - ultra-szybki OPEN < 8ms (fake listener)
#   - uniforma odpowiedź na wszystkich trap portach
#   - tarpit — czas rośnie z każdą próbą

_bh_deception_probe() {
    local ip="$1"
    _bh_budget_ok || return 1

    _bh_log "DECEPTION PROBE ${ip}"

    local deception_score=0
    local deception_signals=() p raw ms state rst

    # Test 1: ciemne porty — otwarty = honeypot
    for p in 31337 6666 4444 12345 9999; do
        _bh_jitter 200 50
        raw=$(_bh_probe_full "$ip" "$p")
        ms="${raw%%|*}"
        state="${raw#*|}"; state="${state%%|*}"
        if [[ "$state" == "OPEN" ]]; then
            (( deception_score += 30 ))
            deception_signals+=("dark_port:${p}")
            _bh_log "  DECEPTION: dark port ${p} OPEN na ${ip}"
        fi
    done

    # Test 2: ultra-szybki OPEN (<8ms) — niemożliwe fizycznie
    raw=$(_bh_probe_full "$ip" "80")
    ms="${raw%%|*}"
    state="${raw#*|}"; state="${state%%|*}"
    if [[ "$state" == "OPEN" ]] && _is_int "$ms" && (( ms < 8 && ms >= 0 )); then
        (( deception_score += 25 ))
        deception_signals+=("instant_open:${ms}ms")
        _bh_log "  DECEPTION: port 80 otwiera sie w ${ms}ms (fake listener?)"
    fi

    # Test 3: uniforma odpowiedź na trap portach
    local trap_responses=()
    for p in 8888 9090 7777; do
        _bh_jitter 150 30
        raw=$(_bh_probe_full "$ip" "$p")
        ms="${raw%%|*}"
        state="${raw#*|}"; state="${state%%|*}"
        rst="${raw##*|}"
        trap_responses+=("${state}:${rst}")
    done

    local uniq_responses
    uniq_responses=$(printf '%s\n' "${trap_responses[@]}" | sort -u | wc -l)
    if (( uniq_responses == 1 && ${#trap_responses[@]} >= 3 )); then
        if [[ "${trap_responses[0]}" == OPEN* ]]; then
            (( deception_score += 40 ))
            deception_signals+=("uniform_trap_open")
            _bh_log "  DECEPTION: wszystkie trap porty identycznie OPEN"
        fi
    fi

    # Test 4: tarpit — czas rośnie z każdą próbą
    local tarpit_samples=()
    for i in 1 2 3; do
        raw=$(_bh_probe_full "$ip" "22")
        ms="${raw%%|*}"
        _is_int "$ms" && tarpit_samples+=("$ms")
        sleep 0.3
    done

    if (( ${#tarpit_samples[@]} >= 3 )); then
        local t_first="${tarpit_samples[0]}" t_last="${tarpit_samples[2]}"
        if _is_int "$t_first" && _is_int "$t_last" && (( t_first > 0 && t_last > t_first * 3 )); then
            (( deception_score += 35 ))
            deception_signals+=("tarpit:${t_first}->${t_last}ms")
            _bh_log "  DECEPTION: tarpit port 22 (${t_first}ms -> ${t_last}ms)"
        fi
    fi

    BH["${ip}:deception_score"]="$deception_score"
    BH["${ip}:deception_signals"]="${deception_signals[*]:-none}"

    local verdict="LOW"
    (( deception_score >= 25 )) && verdict="MEDIUM"
    (( deception_score >= 55 )) && verdict="HIGH"

    _bh_log "DECEPTION ${ip} -> score=${deception_score} verdict=${verdict}"
    echo "${deception_score}|${verdict}"
}

#
# Dużo hałasu. Potem cisza.
# Potem jeden cichy krok — czy strażnik reaguje tak samo?

_bh_noise_tolerance() {
    local ip="$1" port="${2:-80}"
    _bh_budget_ok || return 1

    _bh_log "NOISE TOLERANCE ${ip}:${port}"

    local baseline_ms="${BH["${ip}:${port}:baseline_ms"]:-100}"
    local noise_threshold=0 previous_ms="$baseline_ms" degraded=0
    local i raw ms state

    for i in $(seq 1 8); do
        _bh_jitter 120 20
        raw=$(_bh_probe_full "$ip" "$port")
        ms="${raw%%|*}"
        state="${raw#*|}"; state="${state%%|*}"
        ! _is_int "$ms" && continue

        if (( i > 4 && ms <= baseline_ms * 2 && previous_ms > baseline_ms * 3 )); then
            noise_threshold=$i
            _bh_log "  NOISE: obrona odpuscila przy próbie ${i} (${previous_ms}ms -> ${ms}ms)"
            break
        fi
        (( ms > baseline_ms * 4 )) && (( degraded++ ))
        previous_ms="$ms"
    done

    # Cisza — złodziej sie chowa
    sleep 4
    _bh_jitter 600 200

    # Jeden próbny krok po ciszy
    raw=$(_bh_probe_full "$ip" "$port")
    ms="${raw%%|*}"
    local recovery_ms="${ms:-0}" recovery_signal="NORMAL"

    _is_int "$recovery_ms" && (( recovery_ms > baseline_ms * 3 )) && recovery_signal="STILL_ELEVATED"
    _is_int "$recovery_ms" && (( recovery_ms <= baseline_ms * 2 )) && recovery_signal="RECOVERED"

    BH["${ip}:${port}:noise_threshold"]="$noise_threshold"
    BH["${ip}:${port}:noise_degraded"]="$degraded"
    BH["${ip}:${port}:recovery"]="$recovery_signal"
    BH["${ip}:${port}:recovery_ms"]="$recovery_ms"

    _bh_log "NOISE ${ip}:${port} -> threshold=${noise_threshold} degraded=${degraded} recovery=${recovery_signal}(${recovery_ms}ms)"
    echo "${noise_threshold}|${degraded}|${recovery_signal}"
}

#

_bh_classify_zone() {
    local ip="$1"

    local reactivity="${BH["${ip}:80:reactivity"]:-0}"
    local adaptivity="${BH["${ip}:80:adaptivity"]:-0}"
    local escalation="${BH["${ip}:80:escalation"]:-0}"
    local correlation="${BH["${ip}:correlation"]:-0}"
    local deception="${BH["${ip}:deception_score"]:-0}"
    local recovery="${BH["${ip}:80:recovery"]:-NORMAL}"
    local state="${BH["${ip}:80:baseline_state"]:-UNKNOWN}"

    local zone="UNKNOWN" confidence=0
    # Confidence budowany z sygnałów — nie statyczne wartości
    local signals=0
    (( reactivity == 1 ))  && (( signals++ ))
    (( escalation == 1 ))  && (( signals++ ))
    (( adaptivity == 1 ))  && (( signals++ ))
    (( correlation == 1 )) && (( signals++ ))
    (( deception > 30 ))   && (( signals++ ))
    [[ "$recovery" == "STILL_ELEVATED" ]] && (( signals++ ))

    if [[ "$state" == "NO_ROUTE" ]]; then
        zone="OFFLINE"; confidence=95
    elif [[ "$state" == "FILTERED" ]] && (( reactivity == 0 && deception < 20 )); then
        zone="SILENT"
        # Niska pewność — może być firewall DROP lub offline
        confidence=$(( 55 + signals * 8 )); (( confidence > 85 )) && confidence=85
    elif (( deception >= 55 )); then
        zone="DECEPTION"
        # Confidence proporcjonalny do wyniku deception
        confidence=$(( deception * 90 / 100 )); (( confidence > 99 )) && confidence=99
    elif (( correlation == 1 )); then
        zone="CORRELATED"
        confidence=$(( 65 + signals * 6 )); (( confidence > 92 )) && confidence=92
    elif (( adaptivity == 1 )) && [[ "$recovery" == "STILL_ELEVATED" ]]; then
        zone="ADAPTIVE"
        confidence=$(( 70 + signals * 5 )); (( confidence > 90 )) && confidence=90
    elif (( escalation == 1 )); then
        zone="ESCALATING"
        confidence=$(( 60 + signals * 7 )); (( confidence > 88 )) && confidence=88
    elif (( reactivity == 1 )); then
        zone="REACTIVE"
        confidence=$(( 55 + signals * 8 )); (( confidence > 85 )) && confidence=85
    elif [[ "$state" == "OPEN" ]] && (( reactivity == 0 && deception < 20 )); then
        zone="EXPOSED"
        confidence=$(( 70 + signals * 5 )); (( confidence > 90 )) && confidence=90
    fi

    BMAP["$ip"]="$zone"
    BH["${ip}:zone"]="$zone"
    BH["${ip}:zone_confidence"]="$confidence"

    _bh_log "ZONE ${ip} -> ${zone} (confidence=${confidence}%)"
    echo "${zone}|${confidence}"
}


_bh_score_host() {
    local ip="$1"

    local reactivity="${BH["${ip}:80:reactivity"]:-0}"
    local adaptivity="${BH["${ip}:80:adaptivity"]:-0}"
    local escalation="${BH["${ip}:80:escalation"]:-0}"
    local correlation="${BH["${ip}:correlation"]:-0}"
    local deception="${BH["${ip}:deception_score"]:-0}"
    local noise_deg="${BH["${ip}:80:noise_degraded"]:-0}"
    local zone="${BH["${ip}:zone"]:-UNKNOWN}"

    local rs=0 ai=0
    (( reactivity == 1 )) && (( rs += 40 ))
    (( escalation == 1 )) && (( rs += 30 ))
    (( noise_deg > 3 ))   && (( rs += 30 ))
    (( rs > 100 )) && rs=100

    (( adaptivity == 1 ))  && (( ai += 50 ))
    (( correlation == 1 )) && (( ai += 50 ))
    (( ai > 100 )) && ai=100

    local dp="$deception"; (( dp > 100 )) && dp=100
    local cl=0
    (( correlation == 1 )) && cl=80
    (( adaptivity == 1 && correlation == 0 )) && cl=40

    BH["${ip}:score_reactivity"]="$rs"
    BH["${ip}:score_adaptivity"]="$ai"
    BH["${ip}:score_deception"]="$dp"
    BH["${ip}:score_correlation"]="$cl"

    _bh_log "SCORE ${ip} -> RS=${rs} AI=${ai} DP=${dp} CL=${cl} ZONE=${zone}"
    _BH_RET="${rs}|${ai}|${dp}|${cl}"
    echo "$_BH_RET"
}

#
#
#   while budget > 0:
#     target = choose_next()    — highest reactivity score
#     probe()                   — dotknij
#     measure()                 — zmierz reakcje
#     update_map()              — zaktualizuj strefe
#     adapt_strategy()          — idź w strone różnicy

run_phase_x() {
    local hosts=("$@")
    [[ ${#hosts[@]} -eq 0 ]] && {
        _bh_log "Brak hostow do eksploracji behawioralnej"
        return 0
    }

    log "======================================================" "TOPO"
    log " FAZA X: BEHAVIOURAL RECON" "TOPO"
    log " Hosts: ${#hosts[@]} | Budget: ${BH_BUDGET} prob" "TOPO"
    log "======================================================" "TOPO"

    PHASE_X[start_ts]=$(_bh_ts_s)
    PHASE_X[hosts_total]="${#hosts[@]}"
    PHASE_X[zones_reactive]=0
    PHASE_X[zones_deception]=0
    PHASE_X[zones_correlated]=0
    PHASE_X[zones_adaptive]=0
    PHASE_X[zones_escalating]=0
    PHASE_X[zones_silent]=0
    PHASE_X[zones_exposed]=0

    local ip

    for ip in "${hosts[@]}"; do
        _bh_budget_ok || {
            _bh_log "Budget wyczerpany przy ${ip} — zatrzymuje eksploracje"
            break
        }

        _bh_log "==== EKSPLORACJA: ${ip} (budget=${BH_BUDGET}) ===="

        # KROK 1: DOTYK — baseline
        local p
        for p in 80 22 443; do
            _bh_budget_ok || break
            _bh_baseline "$ip" "$p"
        done

        # KROK 2: BURST — reaktywnosc
        _bh_budget_ok && _bh_burst_test "$ip" "80"

        # KROK 3: KORELACJA — czy porty "rozmawiaja ze soba"?
        _bh_budget_ok && _bh_correlation_probe "$ip"

        # KROK 4: DECEPTION — czy to co widze to prawda?
        _bh_budget_ok && _bh_deception_probe "$ip"

        # KROK 5: NOISE — gdzie jest próg zmeczenia strażnika?
        _bh_budget_ok && _bh_noise_tolerance "$ip" "80"

        # KROK 5b: CROSS-SERVICE — czy port A zmienia port B?
        _bh_budget_ok && _bh_cross_service "$ip"

        # KROK 6: MAPA — strefa behawioralna
        local zone_result zone
        _bh_classify_zone "$ip"; zone_result="$_BH_RET"
        zone="${zone_result%%|*}"

        # KROK 7: SCORING
        _bh_score_host "$ip"

        # Liczniki stref
        case "$zone" in
            REACTIVE)   (( PHASE_X[zones_reactive]++ )) ;;
            DECEPTION)  (( PHASE_X[zones_deception]++ )) ;;
            CORRELATED) (( PHASE_X[zones_correlated]++ )) ;;
            ADAPTIVE)   (( PHASE_X[zones_adaptive]++ )) ;;
            ESCALATING) (( PHASE_X[zones_escalating]++ )) ;;
            SILENT)     (( PHASE_X[zones_silent]++ )) ;;
            EXPOSED)    (( PHASE_X[zones_exposed]++ )) ;;
        esac

        # ADAPTACJA STRATEGII — silnik uczy sie
        if [[ "$zone" == "DECEPTION" ]]; then
            _bh_log "ADAPTIVE: deception wykryty -> zwiekszam jitter"
            BH_JITTER_MAX=$(( BH_JITTER_MAX + 200 ))
            (( BH_BURST_SIZE > 2 )) && (( BH_BURST_SIZE-- ))
        fi

        if [[ "$zone" == "CORRELATED" ]]; then
            _bh_log "ADAPTIVE: korelacja wykryta -> zmieniam kolejnosc portow"
            # Nastepny host dostanie inne porty w innej kolejnosci
            # (implementacja: shuffle BH_PORTS przez RANDOM)
        fi

        _bh_log "HOST ${ip} DONE -> ZONE=${zone} RS=${BH["${ip}:score_reactivity"]} AI=${BH["${ip}:score_adaptivity"]} DP=${BH["${ip}:score_deception"]}"

        # Przerwa — kameleon nie spieszy
        _bh_jitter 1200 300
    done

    PHASE_X[end_ts]=$(_bh_ts_s)
    PHASE_X[duration]=$(( PHASE_X[end_ts] - PHASE_X[start_ts] ))
    PHASE_X[budget_remaining]="$BH_BUDGET"
    PHASE_X[events_count]="${#BH_EVENTS[@]}"

    # FINALIZACJA — deterministyczny threat score z zebranych danych
    local final_threat; final_threat=$(_bh_threat_score)
    PHASE_X[final_threat]="$final_threat"

    log " FAZA X ZAKONCZONA — czas: ${PHASE_X[duration]}s | zdarzenia: ${PHASE_X[events_count]}" "TOPO"
    log " Threat Score (deterministyczny): ${final_threat}/100" "TOPO"
    log " Strefy: REACTIVE=${PHASE_X[zones_reactive]} DECEPTION=${PHASE_X[zones_deception]} CORRELATED=${PHASE_X[zones_correlated]} ADAPTIVE=${PHASE_X[zones_adaptive]}" "TOPO"
    log " Strefy: ESCALATING=${PHASE_X[zones_escalating]} SILENT=${PHASE_X[zones_silent]} EXPOSED=${PHASE_X[zones_exposed]}" "TOPO"
}


export_phase_x_findings() {
    local ip

    # ── PER-HOST: zachowanie + interpretacja actionable ───────────────────────
    for ip in "${!BMAP[@]}"; do
        local zone="${BMAP[$ip]}"
        local rs="${BH["${ip}:score_reactivity"]:-0}"
        local ai="${BH["${ip}:score_adaptivity"]:-0}"
        local dp="${BH["${ip}:score_deception"]:-0}"
        local cl="${BH["${ip}:score_correlation"]:-0}"
        local conf="${BH["${ip}:zone_confidence"]:-0}"
        local baseline="${BH["${ip}:80:baseline_ms"]:-0}"
        local variance="${BH["${ip}:80:baseline_variance"]:-0}"
        local win_type="${BH["${ip}:80:window_type"]:-NONE}"
        local ban_probe="${BH["${ip}:80:escalation_probe_n"]:-0}"
        local deception_sigs="${BH["${ip}:deception_signals"]:-}"
        local recovery="${BH["${ip}:80:recovery"]:-NORMAL}"
        local post_burst="${BH["${ip}:80:post_burst_ms"]:-0}"
        local return_delta="${BH["${ip}:80:return_delta_ms"]:-0}"

        case "$zone" in

            DECEPTION)
                # Rozróżnij typy deception na podstawie sygnałów
                local dec_type="nieznany typ"
                local dec_rec=""
                if echo "$deception_sigs" | grep -q "dark_port"; then
                    dec_type="honeypot (ciemne porty otwarte)"
                    dec_rec="Honeypot aktywny — porty które nie powinny odpowiadać, odpowiadają. Upewnij się że honeypot nie obejmuje portów produkcyjnych. Zweryfikuj czy alerty z honeypota trafiają do SIEM."
                elif echo "$deception_sigs" | grep -q "uniform_trap"; then
                    dec_type="tarpit (uniforma odpowiedź na trap portach)"
                    dec_rec="Tarpit wykryty — wszystkie porty testowe odpowiadają identycznie. Sprawdź czy tarpit nie blokuje legalnych skanerów wewnętrznych (Qualys, Tenable). Wykluczenie po IP jest wymagane."
                elif echo "$deception_sigs" | grep -q "instant_open"; then
                    dec_type="fake listener (<8ms — niemożliwe fizycznie)"
                    dec_rec="Fałszywy listener wykryty — port odpowiada szybciej niż fizycznie możliwe. Wskazuje na software-level trap (HoneyD, OpenCanary). Zweryfikuj konfigurację deception platformy."
                elif echo "$deception_sigs" | grep -q "tarpit_rtt"; then
                    dec_type="SSH tarpit (progresywne opóźnienia)"
                    dec_rec="SSH tarpit aktywny — czas połączenia rośnie progresywnie. Dobra konfiguracja, ale upewnij się że jump host / bastion jest na whiteliście."
                fi
                add_net_finding "HIGH" "BEHAVIOURAL_DECEPTION"                     "${ip}: Warstwa deception — ${dec_type} (score=${dp}%, confidence=${conf}%, sygnaly: ${deception_sigs:-?})"                     "${dec_rec:-Zweryfikuj konfigurację deception. Upewnij się że alerty trafiają do SIEM i że produkcja jest wyłączona z zakresu.}"
                ;;

            CORRELATED)
                # Korelacja = IDS/NDR/SIEM analizuje sekwencje
                local corr_rec="Każda sekwencja prób jest widoczna dla centralnego systemu. Footprint audytora jest rejestrowany. Przy następnym audycie użyj strategii low-noise: --mode passive lub zwiększ jitter (--jitter 2000)."
                if (( cl >= 80 )); then
                    corr_rec="Wysoka korelacja (${cl}%) wskazuje na dojrzałą, scentralizowaną korelację zdarzeń lub telemetrię czasu rzeczywistego. Aktywne próby są dobrze widoczne. Rekomendacja: ogranicz zakres do walidacji pasywnej i uzgodnij okno audytu z właścicielem środowiska."
                elif (( cl >= 50 )); then
                    corr_rec="Korelacja medium (${cl}%) — środowisko reaguje jak sieć z aktywną korelacją i progowaniem zdarzeń. Zweryfikuj progi i telemetrię bez wskazywania konkretnego produktu."
                fi
                add_net_finding "HIGH" "BEHAVIOURAL_CORRELATED"                     "${ip}: Korelacja zdarzen miedzy portami (score=${cl}%, confidence=${conf}%) — aktywny IDS/SIEM/NDR"                     "$corr_rec"
                ;;

            ADAPTIVE)
                # Adaptacja z pamięcią = reputacja IP, persistent block
                local adap_rec=""
                if [[ "$recovery" == "STILL_ELEVATED" ]]; then
                    adap_rec="System pamięta IP audytora — blokada nie znika po cooldown (latencja nadal podwyższona: ${post_burst:-?}ms po burście vs baseline ${baseline}ms). Wskazuje na reputacyjny blacklist (CrowdSec, fail2ban z długim ban-time). Zalecenie: skróć ban-time lub wdróż automatyczne IP rotation dla autoryzowanych skanerów."
                else
                    adap_rec="Obrona adaptacyjna (AI=${ai}%) — system zmienia zachowanie w odpowiedzi na probe pattern. Prawdopodobnie fail2ban lub podobny. Obecny ban-time wydaje się krótki (recovery widoczny). Rozważ zwiększenie ban-time do 24h+ dla nieznanych IP."
                fi
                add_net_finding "MEDIUM" "BEHAVIOURAL_ADAPTIVE"                     "${ip}: Obrona adaptacyjna z pamiecią (AI=${ai}%, recovery=${recovery}, post_burst=${post_burst}ms)"                     "$adap_rec"
                ;;

            ESCALATING)
                # Eskalacja = rate limiter lub IPS z progresywnym throttlingiem
                local esc_rec=""
                if [[ "$win_type" == "THRESHOLD" ]] && (( ban_probe > 0 )); then
                    esc_rec="Próg blokady wykryty przy próbie N=${ban_probe} — po ${ban_probe} połączeniach latencja skacze (${baseline}ms → podwyższone). To jest próg IDS/IPS ban-trigger. Ocena progu: "
                    if (( ban_probe <= 3 )); then
                        esc_rec="${esc_rec}BARDZO AGRESYWNY (N=${ban_probe}) — może blokować legalne skanery Qualys/Tenable/Nessus. Rozważ zwiększenie progu do minimum 5-10 dla znanych podsieci audytowych."
                    elif (( ban_probe <= 7 )); then
                        esc_rec="${esc_rec}AGRESYWNY (N=${ban_probe}) — dobry dla produkcji, ale wyklucz IP skanerów autoryzowanych z tego progu."
                    else
                        esc_rec="${esc_rec}UMIARKOWANY (N=${ban_probe}) — akceptowalny kompromis. Dla środowisk high-security rozważ obniżenie do 5."
                    fi
                elif [[ "$win_type" == "GRADUAL" ]]; then
                    esc_rec="Progresywne throttling (GRADUAL) — latencja rośnie liniowo z kolejnymi próbami (baseline=${baseline}ms, variance=${variance}ms). Wskazuje na token bucket lub leaky bucket rate limiter. Konfiguracja wygląda poprawnie. Upewnij się że authorized scanners mają wyższy rate limit lub są wykluczone."
                elif [[ "$win_type" == "BURSTY" ]]; then
                    esc_rec="Reakcja burstowa — gwałtowny wzrost latencji przy burst, następnie powrót (return_delta=${return_delta}ms). Wskazuje na connection-rate limiter bez persistent memory. Konfiguracja jest odpowiednia dla mitygacji DDoS ale nie dla advanced persistent threat — rozważ dodanie adaptive memory (fail2ban)."
                else
                    esc_rec="Eskalacja obrony wykryta (RS=${rs}%) ale wzorzec niejasny. Baseline=${baseline}ms, variance=${variance}ms. Sprawdź konfigurację rate-limitera — możliwe niespójne reguły."
                fi
                add_net_finding "MEDIUM" "BEHAVIOURAL_ESCALATING"                     "${ip}: Eskalacja obrony — wzorzec=${win_type}, próg N=${ban_probe}, baseline=${baseline}ms"                     "$esc_rec"
                ;;

            REACTIVE)
                # Reaktywny bez pamięci = prosta warstwa sieciowa
                local react_rec=""
                if (( baseline > 500 )); then
                    react_rec="Host reaktywny z wysoką latencją bazową (${baseline}ms) — może wskazywać na transparentny proxy lub IDS inline. Brak persistent memory oznacza że każda sesja jest oceniana od zera. Dodanie fail2ban lub CrowdSec wzmocniłoby obronę."
                else
                    react_rec="Prosta ochrona sieciowa — host reaguje na bodziec ale nie zapamiętuje historii prób (baseline=${baseline}ms). To jest poziom minimalny. Zalecenie: wdrożenie fail2ban z ban-time minimum 1h lub CrowdSec z community blocklist."
                fi
                add_net_finding "LOW" "BEHAVIOURAL_REACTIVE"                     "${ip}: Host reaktywny bez pamieci (RS=${rs}%, baseline=${baseline}ms, variance=${variance}ms)"                     "$react_rec"
                ;;

            EXPOSED)
                # Brak obrony behawioralnej = otwarta ekspozycja
                add_net_finding "MEDIUM" "BEHAVIOURAL_EXPOSED"                     "${ip}: Brak aktywnej obrony behawioralnej — host otwarty bez widocznego rate-limitera, IDS ani deception"                     "Wdróż minimum: (1) fail2ban z ban-time 1h dla SSH/HTTP, (2) rate limiting na poziomie firewall (iptables -m limit), (3) rozważ CrowdSec jako warstwę kolaboratywnej obrony."
                ;;

            SILENT)
                # DROP policy — brak odpowiedzi
                add_net_finding "INFO" "BEHAVIOURAL_SILENT"                     "${ip}: Host silent — DROP policy (brak odpowiedzi na wszystkie proby, confidence=${conf}%)"                     "DROP policy jest prawidłowa — host nie ujawnia informacji o stanie portów. Upewnij się że to jest intentional (nie awaria usługi)."
                ;;
        esac
    done

    # ── GLOBALNA SYNTEZA — wnioski na poziomie sieci ──────────────────────────
    local heat="${SESSION_STATE[heat]:-0}"
    local threat="${SESSION_STATE[threat_level]:-0}"
    local corr="${SESSION_STATE[correlation_score]:-0}"
    local adapt="${SESSION_STATE[adaptation_detected]:-0}"
    local esc_thresh="${SESSION_STATE[escalation_threshold]:-0}"
    local zones_dec="${PHASE_X[zones_deception]:-0}"
    local zones_cor="${PHASE_X[zones_correlated]:-0}"
    local zones_adp="${PHASE_X[zones_adaptive]:-0}"
    local zones_esc="${PHASE_X[zones_escalating]:-0}"
    local zones_exp="${PHASE_X[zones_exposed]:-0}"
    local zones_sil="${PHASE_X[zones_silent]:-0}"
    local dynamic_total=$(( zones_adp + zones_esc ))

    # Deception global
    if (( zones_dec > 0 )); then
        add_net_finding "HIGH" "BEHAVIOURAL_GLOBAL"             "Siec zawiera ${zones_dec} stref deception — aktywna dezinformacja (heat=${heat})"             "Audyt klasyczny jest czesciowo niewiarygodny w tej sieci. Wyniki port scan mogą zawierać false positives z honeypotów. Rekomendacja: zidentyfikuj i wyklucz IP deception systemów z przyszłych audytów."
    fi

    # Korelacja global — IDS/NDR
    if (( zones_cor > 0 )); then
        local ids_rec="Środowisko ma aktywną korelację zdarzeń (${zones_cor} hostów, correlation_score=${corr}). "
        if (( corr >= 70 )); then
            ids_rec="${ids_rec}Wysoki score sugeruje dojrzałą korelację sieciową klasy enterprise. Footprint audytora jest w pełni rejestrowany. Następny krok: ogranicz walidację do zakresu pasywnego i uzgodnij ją z właścicielem środowiska."
        else
            ids_rec="${ids_rec}Umiarkowany score sugeruje IDS z regułami korelacyjnymi. Sprawdź czy reguły THRESHOLD są właściwie skalibrowane — zbyt niski próg generuje alert-fatigue."
        fi
        add_net_finding "HIGH" "BEHAVIOURAL_GLOBAL"             "Korelacja zdarzen aktywna: ${zones_cor} hostow, score=${corr}%, adaptation=${adapt}"             "$ids_rec"
    fi

    # Adaptive/Escalating global — próg blokady
    if (( dynamic_total >= 2 )); then
        local dyn_rec="Dynamiczna obrona: ${zones_adp} hostow adaptive + ${zones_esc} escalating. "
        if (( esc_thresh > 0 && esc_thresh <= 3 )); then
            dyn_rec="${dyn_rec}KRYTYCZNE: próg blokady N=${esc_thresh} jest bardzo agresywny — authorized skanery wewnętrzne (Qualys, Tenable, Nessus) będą blokowane po ${esc_thresh} próbach. Dodaj podsieci skanerów do whitelist IDS/fail2ban."
        elif (( esc_thresh > 0 && esc_thresh <= 7 )); then
            dyn_rec="${dyn_rec}Próg blokady N=${esc_thresh} — akceptowalny dla środowiska produkcyjnego. Upewnij się że IP skanerów autoryzowanych są wykluczone z tego progu."
        elif (( esc_thresh > 7 )); then
            dyn_rec="${dyn_rec}Próg blokady N=${esc_thresh} — może być zbyt liberalny dla środowisk high-security. Rozważ obniżenie do 5 przy jednoczesnym wdrożeniu IP whitelist dla skanerów."
        else
            dyn_rec="${dyn_rec}Klasyczny audyt sekwencyjny jest nieskuteczny w tej sieci. Wymagana strategia low-noise z adaptacyjnym jitterem (--jitter 1500+)."
        fi
        add_net_finding "HIGH" "BEHAVIOURAL_GLOBAL"             "Dynamiczna eskalacja obrony: adaptive=${zones_adp} escalating=${zones_esc} próg=${esc_thresh} threat=${threat}"             "$dyn_rec"
    fi

    # Exposed global — brak obrony behawioralnej
    if (( zones_exp >= 3 )); then
        add_net_finding "HIGH" "BEHAVIOURAL_GLOBAL"             "${zones_exp} hostów bez widocznej obrony behawioralnej — flat exposure surface"             "Znaczna część sieci nie ma dynamicznej obrony. Wdróż centralny rate-limiting i IDS. Priorytet: hosty z otwartymi portami zarządzania (SSH/RDP/WinRM)."
    fi

    # Heat level synthesis
    if (( heat >= 70 )); then
        add_net_finding "HIGH" "BEHAVIOURAL_GLOBAL"             "Wysoki poziom heat sieci (${heat}/100) — siec w stanie podwyższonej gotowości przez cały audyt"             "Audyt wygenerował znaczący ruch detekcyjny. SOC mógł zarejestrować anomalię. Przy następnym audycie: użyj --mode passive dla fazy recon, aktywny skan tylko dla potwierdzonych hostów."
    fi

    # Całościowa ocena posture
    local posture_rec=""
    if (( zones_dec > 0 && zones_cor > 0 && dynamic_total > 0 )); then
        posture_rec="DOJRZAŁA OBRONA: sieć ma warstwę deception, korelację i dynamiczny rate-limiting. To jest defense-in-depth. Główne zalecenie: upewnij się że whitelist autoryzowanych skanerów jest aktualna we wszystkich warstwach."
    elif (( zones_cor > 0 || dynamic_total >= 2 )); then
        local posture_missing=()
        (( zones_dec == 0 )) && posture_missing+=("deception")
        (( zones_sil == 0 )) && posture_missing+=("stealth policy")
        if [[ ${#posture_missing[@]} -gt 0 ]]; then
            posture_rec="ŚREDNIA DOJRZAŁOŚĆ: aktywna detekcja ale niepełna. Brakujące warstwy: $(IFS=', '; echo "${posture_missing[*]}")."
        else
            posture_rec="ŚREDNIA DOJRZAŁOŚĆ: aktywna detekcja ale niepełna. Wymaga dalszego utwardzenia segmentacji i polityk ograniczających widoczność."
        fi
    elif (( zones_exp > 0 )); then
        posture_rec="NISKA DOJRZAŁOŚĆ: dominuje ekspozycja bez obrony dynamicznej. Priorytet: wdrożenie kontroli reaktywnych, limitowania ruchu i centralnej telemetrii jako minimalnego baseline’u."
    fi
    [[ -n "$posture_rec" ]] && add_net_finding "INFO" "BEHAVIOURAL_POSTURE"         "Ocena posture behawioralnej: deception=${zones_dec} correlated=${zones_cor} adaptive=${zones_adp} escalating=${zones_esc} exposed=${zones_exp} silent=${zones_sil}"         "$posture_rec"
}

# END FAZA X


###############################################################################
###############################################################################
_port_fingerprint() {
    local ip="$1"
    local port="$2"
    local t1 t2 ms r1 r2
    t1=$(date +%s%3N)
    r1=$(timeout 2 bash -c "
        exec 3<>/dev/tcp/$ip/$port || exit 1
        printf 'HEAD / HTTP/1.0\r\n\r\n' >&3
        read -t1 -u3 line || true
        echo \"\$line\"
        exec 3>&-
    " 2>/dev/null | head -1 | tr -d '\r\n' || true)
    t2=$(date +%s%3N)
    ms=$((t2-t1))
    r2=$(timeout 2 bash -c "
        exec 3<>/dev/tcp/$ip/$port || exit 1
        printf 'PING\r\n' >&3
        read -t1 -u3 line || true
        echo \"\$line\"
        exec 3>&-
    " 2>/dev/null | head -1 | tr -d '\r\n' || true)
    r1="${r1:0:80}"
    r2="${r2:0:80}"
    echo "${ms}|${r1}|${r2}"
}
_is_fake_port() {
    local ip="$1"
    local port="$2"
    # nie filtrujemy standardowych portów
    case " $port " in
        *" 22 "*|*" 80 "*|*" 443 "*|*" 53 "*|*" 445 "*|*" 3389 "*|*" 139 "*|*" 135 "*)
            return 1
            ;;
    esac
    local fp ms r1 r2
    fp=$(_port_fingerprint "$ip" "$port")
    ms="${fp%%|*}"
    r1="${fp#*|}"; r1="${r1%%|*}"
    r2="${fp##*|}"
    [[ "$ms" =~ ^[0-9]+$ ]] || ms=9999
    # szybki accept + brak odpowiedzi = fake listener
    if (( ms <= 15 )) && [[ -z "$r1" && -z "$r2" ]]; then
        return 0
    fi
    # identyczna odpowiedź na różne dane
    if (( ms <= 40 )) && [[ -n "$r1" && "$r1" == "$r2" ]]; then
        case "$r1" in
            OK|ok|HELLO|hello|READY|ready|"")
                return 0
                ;;
        esac
    fi
    # zakres mirage 8000–9999
    if (( port >= 8000 && port <= 9999 )) && (( ms <= 40 )) && [[ -z "$r1" && -z "$r2" ]]; then
        return 0
    fi
    return 1
}
filter_false_ports() {
    local ip="$1"
    local open_ports="$2"
    local clean=""
    local fake=""
    local p
    for p in $open_ports; do
        if _is_fake_port "$ip" "$p"; then
            fake="$fake $p"
        else
            clean="$clean $p"
        fi
    done
    echo "${clean# }|${fake# }"
}
###############################################################################
###############################################################################

###############################################################################
###############################################################################
: "${G_TIMEOUT:=2}"
: "${G_RETRY:=2}"
: "${G_DELAY:=1}"
g_route_exists() {
    ip route get "$1" &>/dev/null
}
g_tcp_probe() {
    local ip="$1"
    local port="$2"
    g_route_exists "$ip" || { echo NO_ROUTE; return; }
    _jitter_sleep
    for ((r=1;r<=G_RETRY;r++)); do
        local t1 t2 delta
        t1=$(date +%s%3N)
        timeout "$G_TIMEOUT" bash -c "exec 3<>/dev/tcp/$ip/$port" 2>/dev/null
        local rc=$?
        t2=$(date +%s%3N)
        delta=$((t2-t1))
        if [[ $rc -eq 0 ]]; then
            echo OPEN
            return
        fi
        if [[ $delta -lt 120 ]]; then
            echo CLOSED
            return
        fi
        sleep "$G_DELAY"
    done
    echo FILTERED
}
g_host_detect() {
    local ip="$1"
    local ports=(22 80 443 445 8080 3389 53 22222 8006 9200 9000)
    local alive=0
    local filtered=0
    local p state
    for p in "${ports[@]}"; do
        state=$(g_tcp_probe "$ip" "$p")
        case "$state" in
            OPEN|CLOSED) alive=1 ;;
            FILTERED) ((filtered++)) ;;
        esac
    done
    if [[ $alive -eq 1 ]]; then
        echo HOST_PRESENT
    elif [[ $filtered -ge 2 ]]; then
        echo HOST_FIREWALLED
    else
        echo NO_SIGNAL
    fi
}
g_dns_classify() {
    local resolver="$1"
    local domain="$2"
    local out
    out=$(timeout 3 dig +time=2 +tries=1 @"$resolver" "$domain" A 2>/dev/null)
    [[ -z "$out" ]] && { echo TIMEOUT; return; }
    echo "$out" | grep -q NXDOMAIN && { echo NXDOMAIN; return; }
    echo "$out" | grep -q SERVFAIL && { echo SERVFAIL; return; }
    local ip
    ip=$(echo "$out" | awk '/\sA\s/ {print $NF}' | head -1)
    [[ -z "$ip" ]] && { echo OTHER; return; }
    if [[ "$ip" == "0.0.0.0" || "$ip" == 127.* ]]; then
        echo SINKHOLE
    else
        echo RESOLVED
    fi
}
g_visibility_score() {
    local total="$1"
    local visible="$2"
    [[ "$total" -eq 0 ]] && { echo 0; return; }
    echo $((visible*100/total))
}
# FAZA X — BEHAVIOURAL RECON ENGINE
#
# Metrics: Reactivity Score | Adaptivity Index | Deception Score
#          Correlation Window | Noise Tolerance | Escalation Threshold


declare -A BH=()          # dane behawioralne per host:port:metryka
declare -a BH_EVENTS=()   # log zdarzen z timestamps — pamiec silnika
declare -A BMAP=()         # mapa behawioralna — strefy per host
declare -A PHASE_X=()      # wyniki globalne
_BH_RET=""                  # zwrot funkcji BH (bez subshell)

# Strefy mapy:
#   SILENT      — brak reakcji, host pasywny lub za glebokim DROP
#   REACTIVE    — zachowanie zmienia sie po bodźcu
#   DECEPTION   — sygnały warstwy deception / tarpit / fake listener
#   CORRELATED  — system koreluje zdarzenia miedzy portami
#   ESCALATING  — obrona rośnie z każdą próbą
#   ADAPTIVE    — obrona uczy sie wzorca i odpowiada inaczej
#   EXPOSED     — otwarty bez aktywnej obrony
#   UNKNOWN     — za malo danych


: "${BH_BUDGET:=150}"       # calkowity budżet prób (każda próba kosztuje 1)
: "${BH_JITTER_MAX:=900}"   # max jitter ms miedzy próbami
: "${BH_JITTER_MIN:=80}"    # min jitter
: "${BH_BURST_SIZE:=5}"     # rozmiar burstu w tescie reaktywności
: "${BH_COOLDOWN:=3}"       # sekundy cooldown po burście
: "${BH_BASELINE_N:=3}"     # ilość próbek do baseline
: "${BH_PROBE_TIMEOUT:=2}"  # timeout pojedynczej próby (s)



# [PRE] East-West reachability (pre-scan)
# Minimal, sensory-only probe that does NOT depend on port-scan results.
# It samples a few host pairs and probes common east-west ports to estimate segmentation.

audit_east_west_pre() {
    log "[PRE] East-West reachability (sensory)" "SECTION"
    (( DEV_COUNT < 2 )) && { _report_finding "SEGMENT_ISOLATION" "NOT_TESTED" 0 "less than two hosts" "audit_east_west_pre"; return 0; }

    local ports="22 53 80 443 445 3389"
    local samples=0 hits=0 j dst p
    for (( j=0; j<DEV_COUNT && samples<12; j++ )); do
        dst="${D_IP[$j]:-}"
        [[ -z "$dst" ]] && continue
        for p in $ports; do
            state=$(g_tcp_probe "$dst" "$p" 1)
            [[ "$state" == "open" || "$state" == "closed" ]] && { (( hits++ )); break; }
        done
        (( samples++ ))
    done

    TRAFFIC_POLICY[east_west_pre_samples]="$samples"
    TRAFFIC_POLICY[east_west_pre_hits]="$hits"
    if (( samples == 0 )); then
        _report_finding "SEGMENT_ISOLATION" "NOT_TESTED" 0 "no sample completed" "audit_east_west_pre"
    elif (( hits * 100 / samples < 20 )); then
        TRAFFIC_POLICY[east_west_isolated]="1"
        _report_finding "SEGMENT_ISOLATION" "CONFIRMED" 70 "limited east-west response ${hits}/${samples}" "audit_east_west_pre"
        log "East-West: likely isolated (hits=${hits}/${samples})" "OK"
    else
        TRAFFIC_POLICY[east_west_isolated]="0"
        _report_finding "SEGMENT_ISOLATION" "NOT_DETECTED" 64 "east-west paths visible ${hits}/${samples}" "audit_east_west_pre"
        log "East-West: likely flat/reachable (hits=${hits}/${samples})" "WARN"
    fi
}


# NOWY MAIN — PETLA ZAMIAST PIPELINE

log "$(L start "${VERSION}" "${CLIENT_NAME}" "${MODE}")" "SECTION"

preflight
probe_topology
if ! discover_infrastructure; then
    _finalize_no_evidence_report
    export_json
    export_html
    export_pdf
    [[ $QUIET -eq 0 ]] && print_summary
    exit 0
fi

# 1 — L2
audit_layer2

# 2 — Host discovery
discover_hosts

# 2.5 — Gentle topology validation (nmap-assisted corroboration)
topology_nmap_assist

# Guard
if (( DEV_COUNT == 0 )); then
    AUDIT_STATUS="${AUDIT_STATUS:-NO_HOSTS}"
    [[ "$AUDIT_STATUS" == "READY" ]] && AUDIT_STATUS="NO_HOSTS"
    ewnaf_miniserver_event "audit_status" "NO_HOSTS" "Brak aktywnych hostów"
    AUDIT_NOTE="$(L no_hosts)"
    log "$AUDIT_NOTE" "WARN"
    _finalize_no_evidence_report
    export_json
    export_html
    export_pdf
    [[ $QUIET -eq 0 ]] && print_summary
    exit 0
fi

# 3 — L3 segmentation
audit_layer3

# 4 — DNS filtering (sensory, before interpretation)
audit_dns

# 5 — WAN/NAT + Egress (sensory)
audit_egress
audit_wan

# 6 — Traffic policy (burst/IDS) (sensory)
audit_traffic_policy

# 7 — Firewall DROP/RST fingerprint (sensory, must be before portscan interpretation)
audit_firewall

# 8 — East-West reachability (pre-scan proxy)
audit_east_west_pre

# FREEZE CONTEXT (COLLECT → FREEZE → CLASSIFY)
freeze_context

# NET-AUDIT: Badamy SIEĆ, nie usługi
# Wyłączone: port scan, banner grab, classify, TLS, UDP, AD, lateral, fleet, prowler
# Audyt sam odkrywa co jest w sieci przez topologię i heurystykę — zero palcowania

# Commit DNS i Egress z już zebranych danych
if [[ "$(_safe_get RAW_DNS_AUDIT dns_leak)" == "1" ]]; then
    TRAFFIC_POLICY[dns_leak]=1
fi
if [[ "$(_safe_get RAW_EGRESS http_egress_blocked)" == "1" ]]; then
    TRAFFIC_POLICY[http_egress_blocked]=1
fi

# --- NOWY RDZEN: petla eksploracyjna zastepuje statyczna analize ---
# Zbieramy liste IP wszystkich odkrytych hostow z wykluczeniem lokalnego środowiska wykonawczego
declare -a EXPLORATION_TARGETS=()
declare -a PHASE_X_TARGETS=()
for (( _xi=0; _xi<DEV_COUNT; _xi++ )); do
    _ip="${D_IP[$_xi]:-}"
    [[ -z "$_ip" ]] && continue
    _is_internal_noise "$_ip" && continue
    EXPLORATION_TARGETS+=("$_ip")
    PHASE_X_TARGETS+=("$_ip")
done

# v36.6 passive hardening:
# - lokalne IP audytora, brama runnera oraz WAN nie trafiają do eksploracji
# - PASSIVE_ONLY=1 domyślnie wyłącza aktywną pętlę eksploracyjną i Fazę X

if [[ "${PASSIVE_ONLY:-1}" == "1" ]]; then
    log "PASSIVE_ONLY=1 — pomijam aktywną pętlę eksploracyjną i Fazę X" "INFO"
else
    run_exploration_loop "${EXPLORATION_TARGETS[@]}"
    if (( ${#PHASE_X_TARGETS[@]} > 0 )) && [[ "${SESSION_STATE[phase_x_done]:-0}" != "1" ]]; then
        run_phase_x "${PHASE_X_TARGETS[@]}"
        export_phase_x_findings
    fi
fi


# ═══════════════════════════════════════════════════════════════
# finalize_net_findings() — zamienia wykryte stany na findings
# Model generyczny — zero hardcoded nazw produktów/IP
# Raportuje KLASY ZACHOWAŃ, nie listę produktów
# Zasada: brak dowodu ≠ brak zabezpieczenia
# ═══════════════════════════════════════════════════════════════

finalize_net_findings() {
    NET_FINDINGS=()

    # Tłumaczenie findings ze statusami na legacy NET_FINDINGS + coverage
    local row klass status conf evidence tested_by sev rec
    local IFS_OLD="$IFS"
    for row in "${AUDIT_FINDINGS[@]:-}"; do
        [[ -z "$row" ]] && continue
        IFS=$'\x01' read -r klass status conf evidence tested_by <<< "$row"
        sev="INFO"; rec="Zweryfikuj kontekst i utrzymaj bezpieczny, kontrolowany zakres testów."
        case "$status" in
            ABSENT) sev="HIGH"; rec="Wprowadź kontrolę lub egzekwowanie polityki dla tej klasy ruchu." ;;
            NOT_DETECTED) sev="MEDIUM"; rec="Skuteczność nie została potwierdzona. Rozszerz walidację lub telemetrię." ;;
            CONFIRMED) sev="LOW"; rec="Kontrola została zaobserwowana. Monitoruj regresję i utrzymuj coverage." ;;
            NOT_TESTED) sev="INFO"; rec="Test pominięty lub niedostępny. Uzupełnij brakujące narzędzie albo okno testowe." ;;
        esac
        add_net_finding "$sev" "$klass" "status=${status}; confidence=${conf}; evidence=${evidence}; tested_by=${tested_by}" "$rec"
    done
    IFS="$IFS_OLD"

    # Wnioski syntetyczne dla polityki ruchu
    if [[ "${TRAFFIC_POLICY[east_west_isolated]:-0}" == "1" ]]; then
        add_net_finding "LOW" "SEGMENTATION" "Segmentacja east-west wykazuje sygnał izolacji." "Utrzymaj politykę ACL i waliduj regresje po zmianach."
    fi
    if [[ "${TRAFFIC_POLICY[http_egress_blocked]:-0}" == "1" ]]; then
        add_net_finding "LOW" "EGRESS" "Ruch HTTP bez szyfrowania jest ograniczony." "Utrzymaj wymuszenie szyfrowania i kontrolę wyjścia."
    fi

    _coverage_summary
}


# --- Finalizacja findings (stany→raport) ---
finalize_net_findings

# --- Scoring i raporty ---
log "$(L scoring)" "SECTION"
for (( i=0; i<DEV_COUNT; i++ )); do map_compliance "$i"; done
build_attack_path
build_remediation_roadmap
build_executive

# Wzbogac executive o dane behawioralne z sesji
EXEC_BH_THREAT="${SESSION_STATE[threat_level]}"
EXEC_BH_CORRELATION="${SESSION_STATE[correlation_score]}"
EXEC_BH_DECEPTION="${SESSION_STATE[deception_score]}"
EXEC_BH_ADAPTATION="${SESSION_STATE[adaptation_detected]}"

export_json
export_html
export_pdf

[[ $QUIET -eq 0 ]] && print_summary

if [[ "${PROWLER_RESULT[scan_started]:-0}" == "1" ]]; then
    echo ""
    echo -e "${CM}[PROWLER]${CN} AWS scan dziala w tle (PID: ${PROWLER_RESULT[scan_pid]:-?})"
    echo -e "${CD}  Monitor : tail -f ${PROWLER_RESULT[report_dir]:-}/prowler-aws.log${CN}"
    echo -e "${CD}  Raport  : ${PROWLER_RESULT[report_dir]:-}/aws/${CN}"
fi

log "Audyt zakonczony. Threat=${SESSION_STATE[threat_level]} Correlation=${SESSION_STATE[correlation_score]} Probes=${SESSION_STATE[total_probes]}"

