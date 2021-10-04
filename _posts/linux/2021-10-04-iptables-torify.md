---
layout: post
title:  Пускаем весь трафик через сеть TOR с помощью iptables
date:   2021-09-04 22:44:22 +0700
categories: linux
---
Перенаправляем весь трафик через **TOR** с помощью **iptables**.

Сам способ нашёл на ЛОРе.

Правила взял отсюда https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy 

Сделал фильтр по пользователям (убрал всю не OUTPUT цепочку к оставшимся правилам добавил фильтр по GID или UID на выбор) 

## Получившийся скрипт:

```bash
#!/bin/bash

dns_port=9053
tor_port=9040
virt_addr="10.192.0.0/10"
non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 0.0.0.0/8 100.64.0.0/10 169.254.0.0/16 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3"

RED='\033[0;31m'
NC='\033[0m'

if [[ "$UID" != "0" ]]; then
    echo -e "${RED}Нужен root!${NC}"
    exit 1
fi

if [[ "$1" == "add" ]]; then
    op="-A"
elif [[ "$1" == "del" ]]; then
    op="-D"
else
    echo -e "${RED}Неизвестная операция '$1'${NC}"
    exit 1
fi

if [[ "$2" == "uid" ]]; then
    if [[ ! "$3" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Неверный UID '$3'${NC}"
        exit 1
    fi
    filter="--uid-owner"
    owner="$3"
elif [[ "$2" == "gid" ]]; then
    if [[ ! "$3" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Неверный GID '$3'${NC}"
        exit 1
    fi
    filter="--gid-owner"
    owner="$3"
elif [[ "$2" == "user" ]]; then
    owner=`id -u "$3" 2>/dev/null`
    if [[ ! "$owner" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Пользователь '$3' не существует${NC}"
        exit 1
    fi
    filter="--uid-owner"
elif [[ "$2" == "group" ]]; then
    owner=`id -g "$3" 2>/dev/null`
    if [[ ! "$owner" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Пользователь '$3' не существует${NC}"
        exit 1
    fi
    filter="--gid-owner"
else
    echo -e "${RED}Неизвестный фильтр '$2'${NC}"
    exit 1
fi

iptables -t nat "$op" OUTPUT -d "$virt_addr" -p tcp -m tcp -m owner "$filter" "$owner" --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports "$tor_port"
iptables -t nat "$op" OUTPUT -p udp -m udp -m owner "$filter" "$owner" --dport 53 -j REDIRECT --to-ports "$dns_port"
for lan in $non_tor; do
    iptables -t nat "$op" OUTPUT -m owner "$filter" "$owner" -d "$lan" -j RETURN
done
iptables -t nat "$op" OUTPUT -m owner "$filter" "$owner" -o lo -j RETURN
iptables -t nat "$op" OUTPUT -p tcp -m tcp -m owner "$filter" "$owner" --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports "$tor_port"

iptables "$op" OUTPUT -m owner "$filter" "$owner" -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT
for lan in $non_tor; do
    iptables "$op" OUTPUT -m owner "$filter" "$owner" -d "$lan" -j ACCEPT
done
iptables "$op" OUTPUT -m owner "$filter" "$owner" -d 127.0.0.1/32 -o lo -j ACCEPT
iptables "$op" OUTPUT -m owner "$filter" "$owner" -d 127.0.0.1/32 -p tcp -m tcp --dport "$tor_port" --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT
iptables "$op" OUTPUT -m owner "$filter" "$owner" -d 127.0.0.1/32 -p udp -m udp --dport "$dns_port" -j ACCEPT
iptables "$op" OUTPUT -m owner "$filter" "$owner" -j DROP
```

Скрипт нужно поместить в директорию из **PATH** и дать **права на выполнение**

Например `sudo iptables_torify add group torify` перенаправит трафик всех пользователей с **основной** группой **torify** на **tor**

`sudo iptables_torify add user myname` весь трафик пользователя **myname** на **tor**

```
#/etc/tor/torrc

VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
DNSPort 9053
```

Настраиваем пользователя torify

```bash
su
useradd torify -m
iptables_torify add group torify
iptables-save >> "/etc/iptables/iptables.rules"
systemctl enable iptables.service
systemctl enable tor
reboot
```

Залогинившись torify'ем весь наш трафик идет через тор и мы этому (без root) не можем воспрепятствовать (уже хорошо), но хотелось бы без лишних нажатий на клавиатуру

Пишем небольшой SUID скрипт на C меняющий GID текущего пользователя на GID пользователя «torify» и запускающий что ему сказали (по аналогии с sudo)

```cpp
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <cstring>
#include <cassert>
#include <cstdio>

using namespace std;

string e(const char *s) {
    string res;
    for (size_t i = 0, l = strlen(s); i < l; ++i) {
        if(s[i] == '\'') res += "'\\''";
        else res.push_back(s[i]);
    }
    return res;
}

uint32_t id(const char *s) {
    FILE *p = popen(s, "r");
    assert(p);
    char ch;
    uint32_t i = 0;
    do {
        ch = fgetc(p);
        if (ch >= '0' && ch <= '9') i = i * 10 + (ch - '0');
    } while(ch != EOF);
    pclose(p);
    assert(i != 0);
    return i;
}

int main(int argc, const char *argv[]) {
    string s;
    for (int i = 1; i < argc; ++i) {
        s.push_back('\'');
        s += e(argv[i]);
        s.push_back('\'');
        if (i + 1 < argc) s.push_back(' ');
    }tor
    uint32_t torify_gid = id("id -g torify");
    setgid(torify_gid);
    setuid(getuid());
    if (getgid() == torify_gid)
        return system(s.c_str());
    else
        printf("setgid_torify: failed to setgid\n");
    return 1;
}
```

```bash
g++ setgid_torify.cpp -o setgid_torify -O2 -Wall
sudo chown root:root setgid_torify
sudo chmod 4755 setgid_torify
# Если кто не умеет
```

Итог (теория) `setgid_torify chromium --incognito` запускает chromium весь tcp и dns трафик которого идет через tor, весь остальной «дропается» 

Итог (практика) заходим на browserleaks.com несмотря на то что flash полностью рабочий, «flash leak» не определяет наш настоящий ip (пишет торовский), webrtc leak аналогично
