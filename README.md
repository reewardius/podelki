# podelki

1. ffuf minimize FP
```
ffuf -u URL/TOP -w domains.txt:URL -w top.txt:TOP -ac -mc 200 -o fuzz_results.json -fs 0
python delete_falsepositives.py -j fuzz_results.json -o fuzz_output.txt -fp fp_domains.txt
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
nuclei -l domains_output/full.txt -profile subdomain-takeovers -duc -nh
```

4. Slicer

Slicer is a simple tool developed in Python to test potential vulnerabilities in URL paths. 🌐 It progressively removes paths from a URL, leaving only the domain and generating variations with different directory depths..
```
katana -u alive_http_services.txt -ct 1m -ef js,png,css,jpeg,jpg,woff2 -c 50 -p 50 -rl 300 -d 5 -iqp -o katana.txt
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
