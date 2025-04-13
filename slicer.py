import sys
import argparse
from urllib.parse import urlparse, unquote

def extract_domain_and_paths(url, depth=2, max_path_length=20):
    parsed_url = urlparse(url)
    domain = parsed_url.scheme + "://" + parsed_url.netloc

    raw_path = unquote(parsed_url.path).strip('/')
    if not raw_path or raw_path.strip() == '':
        return None

    path_parts = [part for part in raw_path.split('/') if part.strip()]
    if not path_parts:
        return None

    paths = []
    for i in range(1, depth + 1):
        trimmed_parts = path_parts[:i]
        path = '/' + '/'.join(trimmed_parts)
        if len(path) <= max_path_length:
            paths.append(domain + path)
    
    return paths

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract domains and paths from URLs.")
    parser.add_argument("input_file", help="File with list of URLs")
    parser.add_argument("output_file", help="Output file prefix")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Depth of path to extract (default: 2)")
    parser.add_argument("-m", "--maxlen", type=int, default=20, help="Max path length (default: 20)")

    args = parser.parse_args()

    with open(args.input_file, "r") as file:
        urls = file.readlines()

    unique_paths = {i: set() for i in range(1, args.depth + 1)}  # для каждой глубины создаём отдельный set

    for url in urls:
        url = url.strip()
        if not url:
            continue

        paths = extract_domain_and_paths(url, depth=args.depth, max_path_length=args.maxlen)
        if paths:
            for i, path in enumerate(paths, 1):
                unique_paths[i].add(path)

    # Записываем в отдельные файлы для каждой глубины
    for i in range(1, args.depth + 1):
        output_path = f"{args.output_file}{i}.txt"
        with open(output_path, "w") as out:
            for entry in sorted(unique_paths[i]):
                out.write(entry + "\n")
        
        print(f"✓ Extracted {len(unique_paths[i])} unique paths at depth {i}")
        print(f"→ Saved to: {output_path}")
