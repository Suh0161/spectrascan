#!/usr/bin/env python3
"""
SpectraScan - Total Scan Endpoint Detector
A comprehensive tool for static + dynamic + source-map endpoint discovery
"""
import argparse
import json
import logging
import sys
import os
from datetime import datetime
from typing import Optional

from detector.scanners import StaticScanner
from detector.dynamic import DynamicCapture
from detector.sourcemap import SourceMapHandler
from detector.hybrid import HybridAnalyzer
from detector.openapi_gen import OpenAPIGenerator
from detector.postman_gen import PostmanGenerator
from detector.writer import HARWriter, APIClientGenerator

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)


def redact_sensitive_data(data: dict, redact: bool = True) -> dict:
    """Redact sensitive data from output"""
    if not redact:
        return data
    
    sensitive_keys = ['authorization', 'x-api-key', 'api-key', 'x-auth-token', 'cookie']
    
    def redact_dict(d):
        if isinstance(d, dict):
            return {k: redact_dict(v) if k.lower() not in sensitive_keys else '[REDACTED]' for k, v in d.items()}
        elif isinstance(d, list):
            return [redact_dict(item) for item in d]
        else:
            return d
    
    return redact_dict(data)


def interactive_mode(args):
    """Interactive CLI mode"""
    print("=" * 70)
    print("SpectraScan - Interactive Mode")
    print("=" * 70)
    print("\n[!] ETHICS NOTICE:")
    print("   Use only on public/owned sites or with explicit permission.")
    print("   This tool discovers endpoints and may reveal internal APIs.")
    print("   For research, security testing (with permission), and developer analysis only.")
    print("   Do not attempt to exploit endpoints or bypass authentication.\n")
    print("=" * 70)
    print()
    
    urls = []
    
    print("[*] Enter URLs to scan (one per line)")
    print("[*] Type 'done' when finished, or 'quit' to exit")
    print("[*] You can paste multiple URLs at once\n")
    
    while True:
        try:
            line = input("URL> ").strip()
            
            if not line:
                continue
            
            if line.lower() in ('done', 'd', 'finish', 'f'):
                break
            
            if line.lower() in ('quit', 'q', 'exit', 'e'):
                print("\n[*] Exiting...")
                return
            
            if line.lower() == 'help':
                print("\n[*] Commands:")
                print("  - Paste URLs (one per line)")
                print("  - 'done' or 'd' - Start scanning")
                print("  - 'quit' or 'q' - Exit")
                print("  - 'list' or 'l' - Show entered URLs")
                print("  - 'clear' or 'c' - Clear all URLs")
                print("  - 'help' or 'h' - Show this help\n")
                continue
            
            if line.lower() in ('list', 'l'):
                if urls:
                    print(f"\n[*] Entered URLs ({len(urls)}):")
                    for i, url in enumerate(urls, 1):
                        print(f"  {i}. {url}")
                    print()
                else:
                    print("\n[*] No URLs entered yet\n")
                continue
            
            if line.lower() in ('clear', 'c'):
                urls = []
                print("\n[*] URLs cleared\n")
                continue
            
            # Validate URL
            if not line.startswith(('http://', 'https://')):
                print(f"[!] Invalid URL (must start with http:// or https://): {line}\n")
                continue
            
            if line in urls:
                print(f"[!] URL already added: {line}\n")
                continue
            
            urls.append(line)
            print(f"[+] Added: {line} ({len(urls)} total)\n")
        
        except KeyboardInterrupt:
            print("\n\n[*] Interrupted. Exiting...")
            return
        except EOFError:
            print("\n[*] Exiting...")
            return
    
    if not urls:
        print("\n[!] No URLs entered. Exiting...")
        return
    
    print(f"\n[*] Starting scan for {len(urls)} URL(s)...\n")
    
    # Ask for scan options
    print("[*] Scan Options:")
    print("  1. Quick scan (recommended)")
    print("     - Dynamic capture: Yes (7 seconds)")
    print("     - Source maps: Yes")
    print("     - Outputs: JSON only")
    print("     - Code extraction: No")
    print()
    print("  2. Full scan")
    print("     - Dynamic capture: Yes (10 seconds)")
    print("     - Source maps: Yes")
    print("     - Outputs: JSON + HAR + OpenAPI + Postman + Python client")
    print("     - Code extraction: Yes (all source files)")
    print()
    print("  3. Code extraction only")
    print("     - Dynamic capture: No")
    print("     - Source maps: No")
    print("     - Outputs: JSON only")
    print("     - Code extraction: Yes (all source files)")
    print()
    print("  4. Custom")
    print("     - Configure each option individually")
    print()
    print("  quit/exit - Cancel and exit")
    
    while True:
        try:
            choice = input("\nChoice [1-4] (default: 1): ").strip() or "1"
            
            # Allow exit at any time
            if choice.lower() in ('quit', 'q', 'exit', 'e', 'cancel', 'c'):
                print("\n[*] Cancelled. Exiting...")
                return
            
            if choice == "1":
                args.quick = True
                args.dynamic = True
                args.duration = 7
                args.sourcemaps = True
                args.extract_code = False
                break
            elif choice == "2":
                args.dynamic = True
                args.duration = 10
                args.sourcemaps = True
                args.har = "scan.har"
                args.openapi = "openapi.yaml"
                args.postman = "postman.json"
                args.client = "api_client.py"
                args.extract_code = True  # Enable code extraction in full scan
                break
            elif choice == "3":
                # Code extraction only
                args.dynamic = False
                args.sourcemaps = False
                args.extract_code = True
                print("\n[+] Code extraction only mode enabled")
                break
            elif choice == "4":
                # Custom options
                print("\n[*] Custom Scan Configuration:")
                print("    Configure each option individually\n")
                
                # Dynamic capture
                print("[*] Dynamic Capture:")
                print("    - Captures runtime network requests with Playwright")
                print("    - Recommended for discovering API endpoints")
                dynamic_input = input("    Enable? [Y/n/quit]: ").strip().lower()
                if dynamic_input in ('quit', 'q', 'exit', 'e', 'cancel', 'c'):
                    print("\n[*] Cancelled. Exiting...")
                    return
                dynamic = dynamic_input != 'n'
                if dynamic:
                    args.dynamic = True
                    duration_str = input("    Duration in seconds [7/quit]: ").strip() or "7"
                    if duration_str.lower() in ('quit', 'q', 'exit', 'e', 'cancel', 'c'):
                        print("\n[*] Cancelled. Exiting...")
                        return
                    try:
                        args.duration = int(duration_str)
                        if args.duration < 1 or args.duration > 60:
                            print(f"    [!] Duration adjusted to 7s (was {args.duration})")
                            args.duration = 7
                    except:
                        args.duration = 7
                    print(f"    [+] Dynamic capture enabled ({args.duration}s)\n")
                else:
                    args.dynamic = False
                    print("    [-] Dynamic capture disabled\n")
                
                # Source maps
                print("[*] Source Maps:")
                print("    - Maps minified code back to original TypeScript/JSX sources")
                print("    - Helps identify where endpoints are defined in source code")
                sourcemaps_input = input("    Process source maps? [Y/n/quit]: ").strip().lower()
                if sourcemaps_input in ('quit', 'q', 'exit', 'e', 'cancel', 'c'):
                    print("\n[*] Cancelled. Exiting...")
                    return
                sourcemaps = sourcemaps_input != 'n'
                args.sourcemaps = sourcemaps
                print(f"    {'[+]' if sourcemaps else '[-]'} Source maps {'enabled' if sourcemaps else 'disabled'}\n")
                
                # Code extraction option
                print("[*] Code Extraction:")
                print("    - Extracts all source code files (HTML, CSS, JS, TS, TSX, JSX)")
                print("    - Structures code with semantic labeling for AI analysis")
                extract_code_input = input("    Extract source code? [y/N/quit]: ").strip().lower()
                if extract_code_input in ('quit', 'q', 'exit', 'e', 'cancel', 'c'):
                    print("\n[*] Cancelled. Exiting...")
                    return
                extract_code = extract_code_input == 'y'
                args.extract_code = extract_code
                print(f"    {'[+]' if extract_code else '[-]'} Code extraction {'enabled' if extract_code else 'disabled'}\n")
                
                # Output files
                print("[*] Additional Output Files:")
                print("    - HAR: Network capture (import to Chrome DevTools)")
                print("    - OpenAPI: API specification (YAML)")
                print("    - Postman: Collection for API testing")
                print("    - Python Client: Ready-to-use API client code")
                outputs_input = input("    Generate all outputs? [y/N/quit]: ").strip().lower()
                if outputs_input in ('quit', 'q', 'exit', 'e', 'cancel', 'c'):
                    print("\n[*] Cancelled. Exiting...")
                    return
                outputs = outputs_input == 'y'
                if outputs:
                    # Output files will be saved in results directory
                    args.har = "scan.har"
                    args.openapi = "openapi.yaml"
                    args.postman = "postman.json"
                    args.client = "api_client.py"
                    print("    [+] All outputs will be generated\n")
                else:
                    print("    [-] Only JSON results will be generated\n")
                
                # Security option
                print("[*] Security:")
                print("    - Redacts sensitive data (auth tokens, cookies) from output")
                redact_input = input("    Redact sensitive data? [y/N/quit]: ").strip().lower()
                if redact_input in ('quit', 'q', 'exit', 'e', 'cancel', 'c'):
                    print("\n[*] Cancelled. Exiting...")
                    return
                redact = redact_input == 'y'
                args.no_sensitive_data = redact
                print(f"    {'[+]' if redact else '[-]'} Sensitive data redaction {'enabled' if redact else 'disabled'}\n")
                
                print("[*] Custom configuration complete!\n")
                break
            else:
                print("[!] Invalid choice. Enter 1, 2, 3, 4, or 'quit' to exit.")
        except KeyboardInterrupt:
            print("\n\n[*] Cancelled. Exiting...")
            return
    
    # Apply quick mode defaults if needed
    if args.quick:
        args.dynamic = True
        args.duration = 7
        args.sourcemaps = True
    
    # Create results directory
    results_dir = "scan_results"
    os.makedirs(results_dir, exist_ok=True)
    print(f"[*] Results will be saved to: {results_dir}/")
    
    # Now scan all URLs
    print("\n" + "=" * 70)
    print(f"[*] Scanning {len(urls)} URL(s)...")
    print("=" * 70 + "\n")
    
    batch_results = []
    
    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}] Scanning: {url}")
        print("-" * 70)
        
        # Create safe filename for this URL
        safe_name = url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
        safe_name = ''.join(c for c in safe_name if c.isalnum() or c in ('_', '-'))[:50]
        output_file = os.path.join(results_dir, f"{safe_name}_results.json")
        
        # Temporarily set args.urls for scan_single_url
        original_urls = args.urls
        args.urls = [url]
        
        result = scan_single_url(url, output_file, args)
        
        # Restore
        args.urls = original_urls
        
        batch_results.append({
            'url': url,
            'file': output_file,
            'endpoints': len(result.get('merged_endpoints', [])) if result else 0,
            'success': result is not None
        })
    
    # Print batch summary
    print("\n" + "=" * 70)
    print("[*] SCAN COMPLETE")
    print("=" * 70)
    successful = [r for r in batch_results if r['success']]
    print(f"[+] Successful: {len(successful)}/{len(batch_results)}")
    print(f"[+] Total endpoints: {sum(r['endpoints'] for r in successful)}")
    print("\n[*] Results:")
    for r in batch_results:
        status = "[+]" if r['success'] else "[!]"
        print(f"  {status} {r['url']}: {r['endpoints']} endpoints -> {r['file']}")
    print("=" * 70)
    print()


def main():
    parser = argparse.ArgumentParser(
        description='SpectraScan - Total Scan Endpoint Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (easiest!)
  python main.py
  
  # Single URL scan
  python main.py https://example.com

  # Multiple URLs (batch mode)
  python main.py https://example.com https://example2.com https://example3.com

  # Full scan with dynamic capture
  python main.py https://example.com --dynamic --duration 10

  # Batch scan with quick mode
  python main.py https://example.com https://example2.com --quick
        """
    )
    
    parser.add_argument('urls', nargs='*', help='Target URL(s) to scan (can specify multiple). If none provided, interactive mode starts.')
    parser.add_argument('--output', '-o', default='scan_results.json',
                       help='Output JSON file (default: scan_results.json). For multiple URLs, this is used as prefix.')
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Start interactive mode (default if no URLs provided)')
    
    # Static scan options
    parser.add_argument('--max-js-size', type=int, default=10 * 1024 * 1024,
                       help='Maximum JS file size to scan in bytes (default: 10MB)')
    
    # Dynamic scan options
    parser.add_argument('--dynamic', '-d', action='store_true',
                       help='Enable Playwright runtime capture')
    parser.add_argument('--duration', type=int, default=7,
                       help='Duration to record network activity in seconds (default: 7)')
    parser.add_argument('--headful', action='store_true',
                       help='Run browser headful (show window) for debugging')
    
    # Source map options
    parser.add_argument('--sourcemaps', action='store_true', default=True,
                       help='Fetch and apply source maps (default: True)')
    parser.add_argument('--no-sourcemaps', dest='sourcemaps', action='store_false',
                       help='Disable source map fetching')
    
    # Quick mode - sensible defaults
    parser.add_argument('--quick', action='store_true',
                       help='Quick scan mode: dynamic capture with 7s duration, no extra outputs')
    
    # Output options
    parser.add_argument('--har', help='Write HAR file of runtime capture')
    parser.add_argument('--openapi', help='Generate OpenAPI v3 specification (YAML)')
    parser.add_argument('--postman', help='Generate Postman collection (JSON)')
    parser.add_argument('--client', help='Generate Python API client (api_client.py)')
    
    # Security options
    parser.add_argument('--no-sensitive-data', action='store_true',
                       help='Redact sensitive data (auth tokens, cookies) from output')
    
    # Code extraction option
    parser.add_argument('--extract-code', action='store_true',
                       help='Extract all source code files (HTML, CSS, JS, TS, TSX, JSX, etc.) with semantic labeling')
    parser.add_argument('--max-pages', type=int, default=50,
                       help='Maximum number of pages to crawl (default: 50)')
    parser.add_argument('--crawl-depth', type=int, default=3,
                       help='Maximum crawl depth from main page (default: 3)')
    
    args = parser.parse_args()
    
    # If no URLs provided, start interactive mode
    if not args.urls or args.interactive:
        interactive_mode(args)
        return
    
    # Apply quick mode defaults
    if args.quick:
        args.dynamic = True
        args.duration = 7
        args.sourcemaps = True
    
    # Handle multiple URLs
    urls = args.urls
    is_batch = len(urls) > 1
    
    # Print ethics notice
    print("=" * 70)
    print("SpectraScan - Total Scan Endpoint Detector")
    print("=" * 70)
    print("\n[!] ETHICS NOTICE:")
    print("   Use only on public/owned sites or with explicit permission.")
    print("   This tool discovers endpoints and may reveal internal APIs.")
    print("   For research, security testing (with permission), and developer analysis only.")
    print("   Do not attempt to exploit endpoints or bypass authentication.\n")
    print("=" * 70)
    print()
    
    if is_batch:
        # Create results directory for batch mode
        results_dir = "scan_results"
        os.makedirs(results_dir, exist_ok=True)
        print(f"[*] Batch mode: Scanning {len(urls)} URLs")
        print(f"[*] Results will be saved to: {results_dir}/\n")
        batch_results = []
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{len(urls)}] Scanning: {url}")
            print("-" * 70)
            
            # Create safe filename for this URL
            safe_name = url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
            safe_name = ''.join(c for c in safe_name if c.isalnum() or c in ('_', '-'))[:50]
            if args.output == 'scan_results.json':
                output_file = os.path.join(results_dir, f"{safe_name}_results.json")
            else:
                output_file = os.path.join(results_dir, f"{args.output}_{safe_name}.json")
            
            result = scan_single_url(url, output_file, args)
            batch_results.append({
                'url': url,
                'file': output_file,
                'endpoints': len(result.get('merged_endpoints', [])) if result else 0,
                'success': result is not None
            })
        
        # Print batch summary
        print("\n" + "=" * 70)
        print("[*] BATCH SCAN SUMMARY")
        print("=" * 70)
        successful = [r for r in batch_results if r['success']]
        print(f"[+] Successful: {len(successful)}/{len(batch_results)}")
        print(f"[+] Total endpoints: {sum(r['endpoints'] for r in successful)}")
        print(f"\n[*] All results saved to: {results_dir}/")
        print("\n[*] Results:")
        for r in batch_results:
            status = "[+]" if r['success'] else "[!]"
            # Show relative path
            rel_file = r['file'].replace('\\', '/')
            print(f"  {status} {r['url']}: {r['endpoints']} endpoints -> {rel_file}")
        print("=" * 70)
    else:
        # Single URL scan - save to results directory
        results_dir = "scan_results"
        os.makedirs(results_dir, exist_ok=True)
        
        # If default output name, use results directory
        if args.output == 'scan_results.json':
            output_file = os.path.join(results_dir, 'scan_results.json')
        else:
            # If custom output, check if it's a full path or just filename
            if os.path.dirname(args.output):
                output_file = args.output
            else:
                output_file = os.path.join(results_dir, args.output)
        
        print(f"[*] Results will be saved to: {output_file}\n")
        scan_single_url(urls[0], output_file, args)


def scan_single_url(url, output_file, args):
    """Scan a single URL"""
    # Ensure output directory exists
    output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else '.'
    if output_dir != '.':
        os.makedirs(output_dir, exist_ok=True)
    
    results = {
        'target': url,
        'fetched_at': datetime.utcnow().isoformat() + 'Z',
        'static': {},
        'dynamic': {},
        'sourcemaps': {},
        'merged_endpoints': []
    }
    
    # Static scan
    logger.info("[+] Starting static scan...")
    try:
        scanner = StaticScanner(url, max_js_size=args.max_js_size)
        static_results = scanner.scan()
        results['static'] = static_results
        logger.info(f"[+] Static scan complete: {len(static_results.get('endpoints', []))} findings")
    except Exception as e:
        logger.error(f"Static scan failed: {e}")
        results['static'] = {'error': str(e)}
    
    # Source map processing
    sourcemap_handler = None
    if args.sourcemaps and results['static'].get('js_files'):
        logger.info("[+] Processing source maps...")
        try:
            sourcemap_handler = SourceMapHandler(url)
            sourcemap_count = 0
            
            for js_file in results['static'].get('js_files', []):
                js_url = js_file.get('url')
                if js_url:
                    # Re-fetch JS to check for sourcemap
                    js_result = scanner.fetch_js(js_url)
                    if js_result:
                        content, url = js_result
                        sourcemap_data = sourcemap_handler.process_js_file(content, url)
                        if sourcemap_data:
                            sourcemap_count += 1
                            results['sourcemaps'][url] = {
                                'map_url': sourcemap_data['map_url'],
                                'sources': sourcemap_handler.get_sources(url)
                            }
            
            logger.info(f"[+] Processed {sourcemap_count} source maps")
        except Exception as e:
            logger.warning(f"Source map processing failed: {e}")
    
    # Dynamic scan
    dynamic_results = {}
    if args.dynamic:
        logger.info("[+] Starting dynamic capture (Playwright)...")
        try:
            capture = DynamicCapture(
                duration=args.duration,
                headful=args.headful
            )
            dynamic_results = capture.run_capture(url)
            results['dynamic'] = dynamic_results
            logger.info(f"[+] Dynamic capture complete: {len(dynamic_results.get('requests', []))} requests")
        except ImportError:
            logger.error("Playwright not installed. Install with: pip install playwright && playwright install")
            results['dynamic'] = {'error': 'Playwright not available'}
        except Exception as e:
            logger.error(f"Dynamic capture failed: {e}")
            results['dynamic'] = {'error': str(e)}
    
    # Code extraction
    if args.extract_code:
        logger.info("[+] Extracting all source code files...")
        try:
            from detector.code_extractor import CodeExtractor
            extractor = CodeExtractor(
                url, 
                max_file_size=args.max_js_size,
                max_pages=args.max_pages,
                crawl_depth=args.crawl_depth
            )
            code_structure = extractor.run_extract()
            results['source_code'] = code_structure
            logger.info(f"[+] Code extraction complete: {code_structure.get('summary', {}).get('total_files', 0)} files")
        except ImportError as e:
            logger.error(f"Code extraction failed: {e}. Install beautifulsoup4: pip install beautifulsoup4")
            results['source_code'] = {'error': str(e)}
        except Exception as e:
            logger.error(f"Code extraction failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            results['source_code'] = {'error': str(e), 'traceback': traceback.format_exc()}
    
    # Hybrid merge
    if results.get('static') and (results.get('dynamic') or args.dynamic):
        logger.info("[+] Merging static and dynamic discoveries...")
        try:
            analyzer = HybridAnalyzer(sourcemap_handler=sourcemap_handler)
            merged = analyzer.merge(
                results['static'],
                results.get('dynamic', {}),
                results.get('sourcemaps', {})
            )
            results['merged_endpoints'] = merged['merged_endpoints']
            results['summary'] = merged['summary']
            logger.info(f"[+] Merged {len(results['merged_endpoints'])} unique endpoints")
        except Exception as e:
            logger.error(f"Merge failed: {e}")
            results['merge_error'] = str(e)
    
    # Redact sensitive data if requested
    if args.no_sensitive_data:
        results = redact_sensitive_data(results, redact=True)
    
    # Write main output
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        logger.info(f"[+] Wrote results to {output_file}")
    except Exception as e:
        logger.error(f"Failed to write output: {e}")
        return None
    
    # Generate HAR
    if args.har and results.get('dynamic'):
        try:
            har_writer = HARWriter()
            har = har_writer.generate(results['dynamic'], url)
            # Save HAR in same directory as output file
            output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else '.'
            har_file = os.path.join(output_dir, args.har) if output_dir != '.' else args.har
            har_writer.write(har, har_file)
        except Exception as e:
            logger.error(f"HAR generation failed: {e}")
    
    # Generate OpenAPI
    if args.openapi and results.get('merged_endpoints'):
        try:
            generator = OpenAPIGenerator(title=f"Discovered API - {url}")
            spec = generator.generate(results['merged_endpoints'], url)
            # Save OpenAPI in same directory as output file
            output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else '.'
            openapi_file = os.path.join(output_dir, args.openapi) if output_dir != '.' else args.openapi
            generator.write_yaml(spec, openapi_file)
        except Exception as e:
            logger.error(f"OpenAPI generation failed: {e}")
    
    # Generate Postman
    if args.postman and results.get('merged_endpoints'):
        try:
            generator = PostmanGenerator(name=f"SpectraScan - {url}")
            collection = generator.generate(results['merged_endpoints'], url)
            # Save Postman in same directory as output file
            output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else '.'
            postman_file = os.path.join(output_dir, args.postman) if output_dir != '.' else args.postman
            generator.write(collection, postman_file)
        except Exception as e:
            logger.error(f"Postman generation failed: {e}")
    
    # Generate API client
    if args.client and results.get('merged_endpoints'):
        try:
            generator = APIClientGenerator()
            code = generator.generate(results['merged_endpoints'], url)
            # Save client in same directory as output file
            output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else '.'
            client_file = os.path.join(output_dir, args.client) if output_dir != '.' else args.client
            generator.write(code, client_file)
        except Exception as e:
            logger.error(f"API client generation failed: {e}")
    
    # Print summary (only for single URL)
    if len(args.urls) == 1:
        print("\n" + "=" * 70)
        print("SCAN SUMMARY")
        print("=" * 70)
        print(f"Target: {url}")
        print(f"Static findings: {len(results.get('static', {}).get('endpoints', []))}")
        if results.get('dynamic'):
            print(f"Dynamic requests: {len(results.get('dynamic', {}).get('requests', []))}")
            print(f"WebSockets: {len(results.get('dynamic', {}).get('websockets', []))}")
        print(f"Merged endpoints: {len(results.get('merged_endpoints', []))}")
        print(f"Source maps: {len(results.get('sourcemaps', {}))}")
        if results.get('source_code'):
            code_summary = results['source_code'].get('summary', {})
            print(f"Source code files: {code_summary.get('total_files', 0)}")
            if code_summary.get('by_type'):
                types_str = ', '.join([f"{k}: {v}" for k, v in code_summary['by_type'].items() if v > 0])
                print(f"  By type: {types_str}")
        print("=" * 70)
        print(f"\nResults saved to: {output_file}")
    
    return results


if __name__ == '__main__':
    main()

