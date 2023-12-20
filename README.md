#WAZUH SPJ
**Anggota Kelompok 09:**

| Nim | NAMA |
| ------ | ------ |
| 22.83.0767 | Rodif Zainul Isro'i|
| 22.83.0786 | Muh Fiki Saefulloh |
| 22.83.0789 | Muhammad Saiful Aji |
| 22.83.0799 | Putri Rahmawati |
| 22.83.0803 | Ridho Fathoni Muqorrobin |
| 22.83.0815 | Zaimy Cakra Andika |

**Kelompok kami membuat monitoring log menggunakan WAZUH SIEM**

Instalasi Wazuh

1. Langkah pertama mengetikkan perintah seperrti dibawah untuk melakukan downloading packet.

```sh
curl -sO https://packages.wazuh.com/4.7/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
```
2. Edit ./config.yml dengan perintah dibawah:

```sh
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: node-1
      ip: "<indexer-node-ip>"
    #- name: node-2
    #  ip: "<indexer-node-ip>"
    #- name: node-3
    #  ip: "<indexer-node-ip>"

  # Wazuh server nodes
  # If there is more than one Wazuh server
  # node, each one must have a node_type
  server:
    - name: wazuh-1
      ip: "<wazuh-manager-ip>"
    #  node_type: master
    #- name: wazuh-2
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker
    #- name: wazuh-3
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker

  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "<dashboard-node-ip>"
```
3.Run ./wazuh-certs-tool.sh. untuk membuat certificate.

```sh
bash ./wazuh-certs-tool.sh -A
```
4.Compress ke format tar.

```sh
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
rm -rf ./wazuh-certificates
```
5.Install packet Node

Installasi Node

1. install paket berikut:
```sh
apt-get install gnupg apt-transport-https
```
2. tambahkan repository wazuh
   1. install packet
```sh
apt-get install gnupg apt-transport-https
```
 2. install kunci GPG
```sh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
```
 3. tambahkan repositori
```sh
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
```
 4. Update Repositori
```sh
apt-get update
```
Installasi pengindeks Wazuh
1. install packet pengindeks wazuh
 ```sh
apt-get -y install wazuh-indexer
```
   
Konfigurasi pengindeks Wazuh
1. edit file konfigurasi /etc/wazuh-indexer/opensearch.yml lalu ganti dengan nilai berikut:
  1. network.host
     gunakan alamat node yang sama config.yml
  2. node.name.config.yml. Misalnya, node-1
  3. cluster.initial_master_nodes Anda., ubah nama, atau tambahkan        baris lain, sesuai dengan definisi dan config.yml. Hapus             komentar pada baris node-2node-3config.yml
 ```sh
cluster.initial_master_nodes:
- "node-1"
- "node-2"
- "node-3"
```
4. discovery.seed_hosts: daftar alamat node
 ```sh
discovery.seed_hosts:
  - "10.0.0.1"
  - "10.0.0.2"
  - "10.0.0.3"
```
5. plugins.security.nodes_dn Anda. dan ubah nama umum (CN) serta nilai sesuai dengan pengaturan dan definisi node-2 dan node-3config.yml
 ```sh
plugins.security.nodes_dn:
- "CN=node-1,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=node-2,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=node-3,OU=Wazuh,O=Wazuh,L=California,C=US"
```
6. Deploy Certificate. Ubah kata ($NODE_NAME) menjadi nama node sesuai config.yml. Misal: node-1
```sh
mkdir /etc/wazuh-indexer/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
```
7. Start wazuh-indexer
```sh
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer
```

Wazuh Manager
Langkah-langkahnya meliputi:
1. install wazuh manager
```sh
apt-get -y install wazuh-manager
```
2. Enable wazuh manager
```sh
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```
3. Cek status wazuh manager 
```sh
systemctl status wazuh-manager
```
4. Install filebeat
```sh
apt-get -y install filebeat
```
5. Downloading filebeat config
```sh
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.7/tpl/wazuh/filebeat/filebeat.yml
```
6. Edit file /etc/filebeat/filebeat.yml. Ubah host sesuai alamat IP Wazuh.
![image](https://github.com/rodipisroi/LinuxServer/assets/104636035/dd432954-b221-4faf-ae05-58998344f3f1)

8. Create filebeat keystore
```sh
filebeat keystore create
```
8. Tambahkan username dan password default
```sh
echo admin | filebeat keystore add username --stdin --force
echo admin | filebeat keystore add password --stdin --force
```
9. Download alert template untuk wazuh indexer
```sh
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.7.0/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
```
10. install wazuh module filebeat
```sh
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.3.tar.gz | tar -xvz -C /usr/share/filebeat/module
```
11. Deploy certificate. Ubah kata ($NODE_NAME) menjadi nama node sesuai config.yml. Misal: node-1
```sh
mkdir /etc/filebeat/certs
tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
mv -n /etc/filebeat/certs/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
mv -n /etc/filebeat/certs/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*
chown -R root:root /etc/filebeat/certs
```
12. Start filebeat
```sh
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat
```
13. Cek apakah konfigurasi filebeat berhasil
```sh
filebeat test output
```

Wazuh Dashboard
Langkah-langkah nya meliputi:

1. Install packet required
```sh
apt-get install debhelper tar curl libcap2-bin #debhelper version 9 or later
```
2. Install wazuh dashboard
```sh
apt-get -y install wazuh-dashboard
```   
3. Edit file /etc/wazuh-dashboard/open_dashboard.yml. Ganti opensearch_host sesuai IP Wazuh
![image](https://github.com/rodipisroi/LinuxServer/assets/104636035/2cdd629c-ceeb-47fd-a1f3-4484bad37274)

4. eploy certificate. Ubah kata ($NODE_NAME) menjadi nama node sesuai config.yml. Misal: node-1
```sh
mkdir /etc/wazuh-dashboard/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
mv -n /etc/wazuh-dashboard/certs/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
mv -n /etc/wazuh-dashboard/certs/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
```
5. Start wazuh dashboard
```sh
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
```
6. Akses dashboard wazuh dengan https://ip-wazuh. Default password admin:admin
![image](https://github.com/rodipisroi/LinuxServer/assets/104636035/e9573887-ce10-4cf1-bdf8-aaeddb5e645d)


Install Wazuh Agent pada Linux

1. Install GPG-Key
```sh
 curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
```
2. Menambahkan Repositori
```sh
 echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
```
3. Update Repositori
```sh
 apt-get update
```
4.Install Wazuh Agent. Sesuaikan IP Address dengan IP Wazuh Server.
```sh
 WAZUH_MANAGER="10.0.0.2" apt-get install wazuh-agent
```
5. Cek Wazuh agent di wazuh Dasboard
   ![image](https://github.com/rodipisroi/LinuxServer/assets/104636035/5c3c1197-1346-44af-9fea-a4456d69489f)


**Memblokir serangan brute force SSH dengan respons aktif**

1. Buka file /var/essec/etc/ossec.conf dan verifikasi
```sh
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
```
-Blok <command> berisi informasi tentang tindakan yang akan dijalankan pada agen wazuh.
1. <name> menetapkan untuk perintah.
2. <executable> menentukan skrip respons aktif atau yang dapat dieksekusi yang harus dijalankan pada pemicu.
3. <timeout> mengizinkan batas waktu setelah jangka waktu tertentu.

 2. Menambahkan blok <active-response> dibawah ini ke file konfigurasi server wazuh /var/ossec/etc/ossec.conf
```sh
<ossec_config>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763</rules_id>
    <timeout>180</timeout>
  </active-response>
</ossec_config>
```
- <command> menentukan perintah untuk konfigurasi
- <location> menentukan dimana perintah dijalankan
- <rules_id> modul respons aktif menjalankan perintah jika ID atauran diaktifkan
- <timeout> menentukan berapa lama tindakan respons aktif harus berlangsung

3. memulai ulang layanan manager wazuh
```sh
sudo systemctl restart wazuh-manager
```

UJI KONFIGURASI
1. Ping titik akhir RHEL dari titik akhir ubuntu untuk mengkonfirmasi adanya jaringan antara titil akhir penyerang dan korban
```sh
ping <RHEL_IP>
```
Output
```sh
PING <RHEL_IP> (<RHEL_IP>) 56(84) bytes of data.
64 bytes from <RHEL_IP>: icmp_seq=1 ttl=64 time=0.602 ms
64 bytes from <RHEL_IP>: icmp_seq=2 ttl=64 time=0.774 ms
```
2. Dititk akhir ubuntu,install Hydra.
```sh
sudo apt update && sudo apt install -y hydra
```
3. dititik akhir ubuntu,buat file teks dengan 10 kata sandi acak
4. jalankan Hydra dari titik akhir ubuntu untuk menjalankan serangan brute force.Ganti <RHEL_USERNAME>dengan nama pengguna titik akhir RHEL, <PASSWD_LIST.txt>dengan jalur ke file kata sandi yang dibuat pada langkah sebelumnya, dan <RHEL_IP>dengan alamat IP titik akhir RHEL
```sh
sudo hydra -t 4 -l <RHEL_USERNAME> -P <PASSWD_LIST.txt> <RHEL_IP> ssh
```
setelah serangan berakhir anda dapat melihat dari dashboard wazuh bahwa 5763 diaktifkan.
5. ping titik akhir korban dari penyerang dalam waktu 3 menit setelah eksekusi serangan
```sh
ping <RHEL_IP>
```
OUTPUT
```sh
PING 10.0.0.5 (10.0.0.5) 56(84) bytes of data.
^C
--- 10.0.0.5 ping statistics ---
12 packets transmitted, 0 received, 100% packet loss, time 11000ms
```

Menghasilkan peringatan ketika respons diaktifkan
titik terakhir linux yang dipantau memiliki file log tempat /var/ossec/logs/active-responses.logWazuh mendaftarkan aktivitas respons aktif. Anda dapat menemukan bagian yang relevan di /var/ossec/etc/ossec.conffile konfigurasi server Wazuh seperti yang ditunjukkan di bawah ini
```sh
<localfile>
  <log_format>syslog</log_format>
  <location>/var/ossec/logs/active-responses.log</location>
</localfile>
```
saat respon aktif terpicu,peringatan terkait akan muncul di dashboard wazuh.
peringatan tersebut muncul karena ID aturan 651 merupakan bagian dari /var/ossec/ruleset/rules/0015-ossec_rules.xml


