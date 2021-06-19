#!/bin/bash

domain=$1
wordlist="root/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
resolvers="/root/tools/resolvers.txt"

domain_enum(){

mkdir -p $domain $domain/recon $domain/recon/nuclei $domain/recon/wayback $domain/recon/gf

subfinder -d $domain -o $domain/recon/subfinder.txt
assetfinder -subs-only $domain | tee $domain/recon/assetfinder.txt
amass enum -passive -d $domain -o $domain/recon/amass.txt
shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/recon/shuffledns.txt

cat $domain/recon/*.txt > $domain/recon/all.txt
}
domain_enum

resolving_domains(){
shuffledns -d $domain -list $domain/recon/all.txt -o $domain/domain.txt -r $resolvers
}
resolving_domains

http_prob(){
cat $domain/domain.txt | httpx -threads 200 -o $domain/recon/httpx.txt
}
http-prob

scanner(){
cat $domain/recon/httpx.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o $domain/recon/nuclei/cves.txt
cat $domain/recon/httpx.txt | nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o $domain/recon/nuclei/vulnerabilities.txt
cat $domain/recon/httpx.txt | nuclei -t /root/nuclei-templates/technologies/ -c 50 -o $domain/recon/nuclei/technologies
cat $domain/recon/httpx.txt | nuclei -t /root/nuclei-templates/takeovers/ -c 50 -o $domain/recon/nuclei/takeovers
}
scanner

wayback_data(){
cat $domain/domain.txt | waybackurls | tee $domain/recon/wayback/url.txt
cat $domain/recon/wayback/url.txt | egrap -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.jpg|\.css|\.ico" | sed 's/:80//g;s/:443//g' | sort -u >$domain/recon/wayback/validurl.txt
rm $domain/recon/wayback/url.txt
}
wayback_data

valid_urls(){
ffuf -c -u 'FUZZ' -w $domain/recon/wayback/validurl.txt -of csv -o $domain/recon/wayback/ffufurl.txt
cat $domain/recon/wayback/ffufurl.txt | grep http | awk -f "," '{print $1}' >> goodurl.txt
rm $domain/recon/wayback/ffufurl.txt
}
valid_urls


gf_patterns(){
gf xss $domain/recon/wayback/goodurl.txt | tee $domain/recon/gf/xss.txt
gf sqlicd
 $domain/recon/wayback/goodurl.txt | tee $domain/recon/gf/sql.txt
gf lfi $domain/recon/wayback/goodurl.txt | tee $domain/recon/gf/lfi.txt
}
gf_patterns
