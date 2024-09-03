This script requires the rdp-check-sec 
https://github.com/CiscoCXSecurity/rdp-sec-check

This script executes rdp-check-sec on multiple IPs with RDP enabled and parses the results into xlsx or csv form.
This can be used as part of pentest reports

usage

python3 RDP_analyser.py -f ips.txt -d /PATH/TO_DIRECTORY_OF/rdp-sec-check -o vertical
python3 RDP_analyser.py -f ips.txt -d /PATH/TO_DIRECTORY_OF/rdp-sec-check -o horizontal

For vertical and horizontal views see examples uploaded
