# podelki

1. ffuf minimize FP
```
ffuf -u URL/TOP -w domains.txt:URL -w top.txt:TOP -t 1000 -ac -mc 200 -o fuzz_results.json -fs 0
python delete_falsepositives.py -j fuzz_results.json -o fuzz_output.txt -fp fp_domains.txt
httpx -l fp_domains.txt -rl 500 -o alive.txt
nuclei -l alive.txt -tags config,exposure -es unknown -c 100 -rl 1000 -o config_exposures.txt
```

2. Sensitive Data from Wayback Archive
```
katana -u root.txt -ps -o katana.txt
python sensitive.py
httpx -l sensitive_matches.txt -mc 200 -o sensitive.txt
httpx -l juicypath_matches.txt -mc 200 -o juicypath.txt
```

3. Second-Order Hijacking
```
subfinder -dL root.txt -all -silent -o subs.txt
python links.py
nuclei -l domains_output/full.txt -profile subdomain-takeovers -nh
```

4. Slicer (Nuclei Path Vulnerability Scanning)
```
katana -u alive_http_services.txt -ct 3m -ef js,png,css,jpeg,jpg,woff2 -c 50 -p 50 -rl 300 -d 5 -iqp -o katana.txt
python3 slicer.py katana.txt slicer; cat slicer*.txt > combined.txt
nuclei -l slicer1.txt -itags config,exposure -s medium,high,critical -rl 1000 -c 100 -stats -si 60 -o nuclei_path_results.txt
nuclei -l combined.txt -itags config,exposure -s medium,high,critical -rl 1000 -c 100 -stats -si 60 -o nuclei_path_results.txt
```
Expected Output
```
✓ Extracted 923 unique paths at depth 1
→ Saved to: slicer1.txt
✓ Extracted 807 unique paths at depth 2
→ Saved to: slicer2.txt
✓ Extracted 717 unique paths at depth 3
→ Saved to: slicer3.txt
✓ Extracted 92 unique paths at depth 4
→ Saved to: slicer4.txt
```
5. Nuclei (Default Scanning)
```
subfinder -dL root.txt -all -silent -o subs.txt
naabu -l subs.txt -s s -tp 100 -ec -c 50 -o naabu.txt
httpx -l naabu.txt -rl 500 -t 200 -o alive_http_services.txt
chmod +x par.sh && bash par.sh
python nuclei.py nuclei.txt # Open Nuclei_Report.html
```
![image](https://github.com/user-attachments/assets/87592c4f-ba72-4ad0-a941-ea00ff40b16e)

6. Nuclei (Fast Custom Templates)
```
git clone https://github.com/reewardius/nuclei-fast-templates && cd nuclei-fast-templates
katana -u root.txt -ps -f qurl -o passive.txt && uro -i passive.txt -o dedupe.txt && nuclei -l dedupe.txt -tags fuzzing-req -dast -t nuclei-fast-templates/ -o nuclei-dast-fast-templates-results.txt
```
