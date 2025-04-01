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

4. URLEXTRACT
Urlextract receives URLs via stdin and prints variations with different path levels.
```
echo "https://example.com/dir1/dir2/dir3" | ./urlextract
cat urls.txt | ./urlextract
```
Expected Outputs
```
https://example.com
https://example.com/dir1/dir2/dir3
https://example.com/dir1/dir2
https://example.com/dir1
```