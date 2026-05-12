#!/bin/bash

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: ./scan.sh <domain>"
    exit 1
fi

OUTDIR="output/$(echo $DOMAIN | tr '.' '_')"
mkdir -p $OUTDIR

echo "================================================"
echo " Subdomain Takeover Scanner"
echo " Target: $DOMAIN"
echo "================================================"
echo ""

echo "[*] Running subfinder..."
subfinder -d $DOMAIN -silent -o $OUTDIR/subfinder.txt > /dev/null 2>&1
echo "[+] Found $(wc -l < $OUTDIR/subfinder.txt) subdomains"
echo ""


echo "[*] Resolving DNS records with dnsx..."
dnsx -l $OUTDIR/subfinder.txt -cname -a -resp -silent -o $OUTDIR/dns_full.txt > /dev/null 2>&1


sed -i 's/\x1b\[[0-9;]*m//g' $OUTDIR/dns_full.txt

echo "[+] DNS resolution done"
echo ""


echo "[*] Extracting CNAME records..."
grep "\[CNAME\]" $OUTDIR/dns_full.txt > $OUTDIR/cname_only.txt
echo "[+] $(wc -l < $OUTDIR/cname_only.txt) subdomains have CNAME records"
echo ""


echo "[*] Finding dangling CNAMEs (CNAME with no A record)..."

comm -23 \
    <(grep "\[CNAME\]" $OUTDIR/dns_full.txt | awk '{print $1}' | sort -u) \
    <(grep "\[A\]"     $OUTDIR/dns_full.txt | awk '{print $1}' | sort -u) \
    > $OUTDIR/dangling.txt

echo "[+] $(wc -l < $OUTDIR/dangling.txt) dangling CNAMEs found"
echo ""


echo "[*] Checking CNAME targets against known vulnerable services..."
echo "" > $OUTDIR/vulnerable.txt

while read subdomain; do
    cname=$(grep "^$subdomain " $OUTDIR/dns_full.txt | grep "\[CNAME\]" | \
            grep -oP '\[CNAME\] \[\K[^\]]+' | head -1)

    service=""
    severity=""

    echo "$cname" | grep -qi "github\.io"            && service="GitHub Pages"   && severity="CRITICAL"
    echo "$cname" | grep -qi "herokuapp\.com"         && service="Heroku"         && severity="CRITICAL"
    echo "$cname" | grep -qi "s3\.amazonaws\.com"     && service="AWS S3"         && severity="CRITICAL"
    echo "$cname" | grep -qi "netlify"                && service="Netlify"        && severity="HIGH"
    echo "$cname" | grep -qi "vercel"                 && service="Vercel"         && severity="HIGH"
    echo "$cname" | grep -qi "surge\.sh"              && service="Surge.sh"       && severity="HIGH"
    echo "$cname" | grep -qi "azurewebsites\.net"     && service="Azure"          && severity="HIGH"
    echo "$cname" | grep -qi "fastly\.net"            && service="Fastly"         && severity="HIGH"
    echo "$cname" | grep -qi "fly\.dev"               && service="Fly.io"         && severity="HIGH"
    echo "$cname" | grep -qi "myshopify\.com"         && service="Shopify"        && severity="MEDIUM"
    echo "$cname" | grep -qi "wpengine\.com"          && service="WPEngine"       && severity="MEDIUM"
    echo "$cname" | grep -qi "pantheonsite\.io"       && service="Pantheon"       && severity="MEDIUM"
    echo "$cname" | grep -qi "ghost\.io"              && service="Ghost"          && severity="MEDIUM"
    echo "$cname" | grep -qi "webflow\.io"            && service="Webflow"        && severity="MEDIUM"
    echo "$cname" | grep -qi "zendesk\.com"           && service="Zendesk"        && severity="MEDIUM"
    echo "$cname" | grep -qi "hubspot\.net"           && service="HubSpot"        && severity="MEDIUM"
    echo "$cname" | grep -qi "squarespace\.com"       && service="Squarespace"    && severity="MEDIUM"
    echo "$cname" | grep -qi "onrender\.com"          && service="Render"         && severity="MEDIUM"
    echo "$cname" | grep -qi "railway\.app"           && service="Railway"        && severity="MEDIUM"
    echo "$cname" | grep -qi "unbounce\.com"          && service="Unbounce"       && severity="MEDIUM"
    echo "$cname" | grep -qi "outgrow\.co"            && service="Outgrow"        && severity="MEDIUM"
    echo "$cname" | grep -qi "almashines\.com"        && service="Almashines"     && severity="MEDIUM"
    echo "$cname" | grep -qi "nopaperforms\.com"      && service="NoPaperForms"   && severity="LOW"
    echo "$cname" | grep -qi "helpscoutdocs\.com"     && service="Help Scout"     && severity="LOW"
    echo "$cname" | grep -qi "readmessl\.com"         && service="ReadMe.io"      && severity="LOW"

    if [ -z "$service" ]; then
        service="Unknown (dangling CNAME)"
        severity="HIGH"
    fi

    echo "[$severity] $subdomain" | tee -a $OUTDIR/vulnerable.txt
    echo "         CNAME   : $cname"    | tee -a $OUTDIR/vulnerable.txt
    echo "         Service : $service"  | tee -a $OUTDIR/vulnerable.txt
    echo ""

done < $OUTDIR/dangling.txt

echo "[*] Probing HTTP responses for service fingerprints..."
echo "" > $OUTDIR/httpx_results.txt

if [ -s $OUTDIR/dangling.txt ]; then
    httpx -l $OUTDIR/dangling.txt \
        -status-code \
        -title \
        -body-preview 300 \
        -follow-redirects \
        -silent \
        -no-color \
        -o $OUTDIR/httpx_results.txt > /dev/null 2>&1

    echo "[+] HTTP probe done"
    echo ""

    echo "[*] Matching body fingerprints..."
    grep -i "NoSuchBucket"                          $OUTDIR/httpx_results.txt && echo "    → AWS S3 bucket not found"
    grep -i "no-such-app"                           $OUTDIR/httpx_results.txt && echo "    → Heroku app not found"
    grep -i "there isn't a github pages site here"  $OUTDIR/httpx_results.txt && echo "    → GitHub Pages unclaimed"
    grep -i "Not Found - Request ID"                $OUTDIR/httpx_results.txt && echo "    → Netlify unclaimed"
    grep -i "Fastly error"                          $OUTDIR/httpx_results.txt && echo "    → Fastly unclaimed"
    grep -i "project not found"                     $OUTDIR/httpx_results.txt && echo "    → Surge.sh unclaimed"
    grep -i "The deployment you are looking for"    $OUTDIR/httpx_results.txt && echo "    → Vercel unclaimed"
    grep -i "404 Web Site not found"                $OUTDIR/httpx_results.txt && echo "    → Azure unclaimed"
    grep -i "does not exist in our system"          $OUTDIR/httpx_results.txt && echo "    → HubSpot unclaimed"
    grep -i "Sorry, this shop is currently"         $OUTDIR/httpx_results.txt && echo "    → Shopify unclaimed"
    echo ""
else
    echo "[+] No dangling CNAMEs to probe"
    echo ""
fi

echo "================================================"
echo " Summary"
echo "================================================"
echo " Subdomains found     : $(wc -l < $OUTDIR/subfinder.txt)"
echo " Subdomains resolved  : $(wc -l < $OUTDIR/dns_full.txt)"
echo " CNAMEs found         : $(wc -l < $OUTDIR/cname_only.txt)"
echo " Dangling CNAMEs      : $(wc -l < $OUTDIR/dangling.txt)"
echo ""
echo " Output files:"
echo "   $OUTDIR/subfinder.txt    - raw subfinder output"
echo "   $OUTDIR/dns_full.txt     - full DNS records"
echo "   $OUTDIR/cname_only.txt   - subdomains with CNAMEs"
echo "   $OUTDIR/dangling.txt     - dangling CNAME candidates"
echo "   $OUTDIR/vulnerable.txt   - vulnerability findings"
echo "   $OUTDIR/httpx_results.txt- HTTP probe results"
echo "================================================"
echo ""
echo "[!] For authorized testing only."
