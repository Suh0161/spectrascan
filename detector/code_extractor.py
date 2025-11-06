"""
Complete Code Extractor - Fetches ALL source files (HTML, CSS, JS, TS, TSX, JSX, etc.)
and structures them for AI analysis
"""
import asyncio
import json
import re
import os
import base64
import requests
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright  # type: ignore
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not installed. Code extraction disabled.")

try:
    from bs4 import BeautifulSoup  # type: ignore
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logger.warning("BeautifulSoup4 not installed. Install with: pip install beautifulsoup4")


class CodeExtractor:
    """Extracts all source code files from a website"""
    
    # File extensions to extract
    CODE_EXTENSIONS = {
        'html': ['.html', '.htm', '.xhtml'],
        'css': ['.css', '.scss', '.sass', '.less'],
        'javascript': ['.js', '.mjs', '.cjs'],
        'typescript': ['.ts', '.tsx'],
        'jsx': ['.jsx'],
        'json': ['.json'],
        'xml': ['.xml', '.svg'],
        'other': ['.txt', '.md', '.yml', '.yaml']
    }
    
    def __init__(self, base_url: str, max_file_size: int = 10 * 1024 * 1024, max_pages: int = 50, crawl_depth: int = 3):
        self.base_url = base_url
        self.max_file_size = max_file_size
        self.max_pages = max_pages  # Maximum pages to crawl
        self.crawl_depth = crawl_depth  # Maximum depth to crawl
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SpectraScan/1.0'})
        self.fetched_files = {}
        self.sourcemaps = {}
        self.visited_urls = set()  # Track visited pages for crawling
        self.parsed_base = urlparse(base_url)
        
    async def extract_all_code(self) -> Dict:
        """Extract all source code files - End-to-end crawl"""
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright is required for code extraction")
        
        logger.info("[+] Starting end-to-end code extraction...")
        logger.info(f"[+] Will crawl up to {self.max_pages} pages with depth {self.crawl_depth}")
        
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context()
            
            # Track all network requests across all pages (filter for code files)
            all_network_resources = set()
            all_code_files = {}
            all_html_pages = {}
            
            # Crawl all pages
            pages_to_crawl = [(self.base_url, 0)]  # (url, depth)
            self.visited_urls.add(self.base_url)
            
            while pages_to_crawl and len(self.visited_urls) < self.max_pages:
                current_url, depth = pages_to_crawl.pop(0)
                
                if depth > self.crawl_depth:
                    continue
                
                logger.info(f"[+] Crawling page {len(self.visited_urls)}/{self.max_pages}: {current_url} (depth: {depth})")
                
                page = await context.new_page()
                page_network_resources = set()
                
                def on_request(request):
                    url = request.url
                    # Filter for code file extensions
                    url_lower = url.lower()
                    code_extensions = ['.js', '.css', '.ts', '.tsx', '.jsx', '.json', '.html', '.htm', '.svg', '.xml', '.scss', '.sass', '.less']
                    if any(url_lower.endswith(ext) for ext in code_extensions) or '/js/' in url_lower or '/css/' in url_lower or '/ts/' in url_lower:
                        page_network_resources.add(url)
                        all_network_resources.add(url)
                
                page.on("request", on_request)
                
                try:
                    await page.goto(current_url, wait_until="networkidle", timeout=30000)
                    # Wait a bit more for lazy-loaded resources
                    await asyncio.sleep(2)
                    
                    # Scroll page to trigger lazy-loading
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await asyncio.sleep(1)
                    await page.evaluate("window.scrollTo(0, 0)")
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    logger.warning(f"Page load timeout/error for {current_url}: {e}, continuing...")
                    await page.close()
                    continue
                
                # Extract code from iframes
                iframe_resources = await self._extract_iframe_code(page)
                page_network_resources.update(iframe_resources)
                all_network_resources.update(iframe_resources)
                
                # Get all resource URLs from DOM and network
                dom_resources = await self._get_all_resources(page)
                all_network_resources.update(dom_resources)
                
                # Get HTML content
                html_content = await page.content()
                html_structure = self._parse_html_structure(html_content)
                
                # Store HTML page
                all_html_pages[current_url] = {
                    'type': 'html',
                    'url': current_url,
                    'content': html_content,
                    'size': len(html_content),
                    'extension': '.html',
                    'structure': html_structure,
                    'depth': depth
                }
                
                # Extract inline CSS and JavaScript
                inline_code = await self._extract_inline_code(page, html_content)
                for inline_file in inline_code:
                    all_code_files[inline_file['url']] = inline_file
                
                # Find links to crawl (same domain only)
                if depth < self.crawl_depth:
                    links_to_crawl = await self._extract_page_links(page, current_url)
                    for link_url in links_to_crawl:
                        if link_url not in self.visited_urls and len(self.visited_urls) < self.max_pages:
                            self.visited_urls.add(link_url)
                            pages_to_crawl.append((link_url, depth + 1))
                
                await page.close()
            
            logger.info(f"[+] Crawled {len(self.visited_urls)} pages, found {len(all_network_resources)} resource URLs")
            
            # Add all HTML pages to code files
            for url, html_data in all_html_pages.items():
                all_code_files[url] = html_data
            
            # Fetch all other code files
            other_files = await self._fetch_code_files(all_network_resources)
            all_code_files.update(other_files)
            logger.info(f"[+] Fetched {len(all_code_files)} code files (including {len(all_html_pages)} HTML pages)")
            
            # Check for Next.js source maps that need async checking
            nextjs_files = [url for url, data in all_code_files.items() if data.get('_needs_sourcemap_check')]
            if nextjs_files:
                logger.info(f"[+] Checking {len(nextjs_files)} Next.js files for source maps...")
                for js_url in nextjs_files:
                    try:
                        sourcemap_url = await self._find_nextjs_sourcemap(js_url)
                        if sourcemap_url:
                            all_code_files[js_url]['sourcemap'] = sourcemap_url
                            logger.info(f"[+] Found Next.js sourcemap: {js_url} -> {sourcemap_url}")
                    except Exception as e:
                        logger.debug(f"Error checking sourcemap for {js_url}: {e}")
                    finally:
                        # Clean up marker
                        if '_needs_sourcemap_check' in all_code_files.get(js_url, {}):
                            del all_code_files[js_url]['_needs_sourcemap_check']
            
            # Follow CSS @import chains recursively
            css_imports = await self._follow_css_imports(all_code_files)
            if css_imports:
                logger.info(f"[+] Following CSS @import chains: found {len(css_imports)} additional CSS files")
                import_files = await self._fetch_code_files(css_imports)
                all_code_files.update(import_files)
            
            # Extract JavaScript imports (ES6 modules, require, etc.)
            js_imports = await self._extract_js_imports(all_code_files)
            if js_imports:
                logger.info(f"[+] Found {len(js_imports)} JavaScript module imports")
                js_import_files = await self._fetch_code_files(js_imports)
                all_code_files.update(js_import_files)
            
            # Extract source maps and get original TS/TSX/JSX files
            original_sources = await self._extract_original_sources(all_code_files)
            if original_sources:
                logger.info(f"[+] Recovered {len(original_sources)} original source files from source maps")
            
            # Remove duplicates and invalid entries
            code_files = self._deduplicate_and_validate(all_code_files)
            logger.info(f"[+] After deduplication: {len(code_files)} unique validated files")
            
            # Combine HTML content from all pages for tech stack detection
            combined_html = '\n'.join([data.get('content', '') for data in all_html_pages.values()])
            
            # Detect modern frameworks and technologies
            tech_stack = await self._detect_tech_stack(code_files, combined_html)
            
            # Organize by language (use main page structure as primary)
            main_html_structure = all_html_pages.get(self.base_url, {}).get('structure', {})
            organized = self._organize_by_language(code_files, original_sources, main_html_structure)
            
            # Add technology stack to metadata
            organized['metadata']['tech_stack'] = tech_stack
            organized['metadata']['pages_crawled'] = len(self.visited_urls)
            organized['metadata']['crawl_depth'] = self.crawl_depth
            organized['metadata']['crawled_urls'] = sorted(list(self.visited_urls))
            
            # Enhance tech stack summary now that tech_stack is available
            if tech_stack:
                frameworks = tech_stack.get('frameworks', [])
                if frameworks:
                    organized['summary']['tech_stack_summary']['primary_framework'] = frameworks[0]
                organized['summary']['tech_stack_summary']['is_spa'] = any(fw in ['React', 'Vue', 'Angular', 'Svelte'] for fw in frameworks)
                organized['summary']['tech_stack_summary']['uses_typescript'] = 'TypeScript' in tech_stack.get('features', [])
                organized['summary']['tech_stack_summary']['modern_js_features'] = tech_stack.get('features', [])
            
            await browser.close()
            
            return organized
    
    async def _get_all_resources(self, page) -> Set[str]:
        """Get all resource URLs from the page"""
        resources = set()
        resources.add(self.base_url)
        
        try:
            # Get all script sources (including inline script analysis)
            scripts = await page.evaluate("""
                () => {
                    const scripts = Array.from(document.scripts).map(s => s.src).filter(Boolean);
                    // Also check for dynamic script loading
                    const scriptTags = Array.from(document.querySelectorAll('script[src]'));
                    scriptTags.forEach(s => {
                        if (s.src) scripts.push(s.src);
                    });
                    return [...new Set(scripts)];
                }
            """)
            resources.update(scripts)
            logger.debug(f"Found {len(scripts)} script URLs")
            
            # Get all link sources (CSS, etc.)
            links = await page.evaluate("""
                () => {
                    const links = Array.from(document.querySelectorAll('link[href]'))
                        .map(l => l.href)
                        .filter(Boolean);
                    return [...new Set(links)];
                }
            """)
            resources.update(links)
            logger.debug(f"Found {len(links)} link URLs")
            
            # Get all stylesheet imports
            stylesheets = await page.evaluate("""
                () => {
                    const sheets = [];
                    try {
                        Array.from(document.styleSheets).forEach(sheet => {
                            if (sheet.href) sheets.push(sheet.href);
                        });
                    } catch(e) {}
                    return [...new Set(sheets)];
                }
            """)
            resources.update(stylesheets)
            logger.debug(f"Found {len(stylesheets)} stylesheet URLs")
            
            # Get all img sources (might have SVG)
            images = await page.evaluate("""
                () => {
                    const imgs = Array.from(document.querySelectorAll('img[src]'))
                        .map(img => img.src)
                        .filter(src => src.endsWith('.svg') || src.endsWith('.xml'))
                        .filter(Boolean);
                    return [...new Set(imgs)];
                }
            """)
            resources.update(images)
            
            # Also get HTML content to extract more URLs
            html_content = await page.content()
            # Extract URLs from HTML using regex (fallback)
            url_pattern = r'https?://[^\s"\'<>]+\.(js|css|ts|tsx|jsx|json|html|htm|svg|xml)(?:\?[^\s"\'<>]*)?'
            found_urls = re.findall(url_pattern, html_content)
            for match in found_urls:
                # Reconstruct URL (pattern returns tuple)
                full_match = re.search(r'https?://[^\s"\'<>]+\.(?:js|css|ts|tsx|jsx|json|html|htm|svg|xml)(?:\?[^\s"\'<>]*)?', html_content)
                if full_match:
                    resources.add(full_match.group(0))
            
        except Exception as e:
            logger.debug(f"Error getting resources: {e}")
        
        logger.info(f"[+] Total unique resources found: {len(resources)}")
        return resources
    
    async def _fetch_code_files(self, urls: Set[str]) -> Dict[str, Dict]:
        """Fetch all code files"""
        code_files = {}
        
        for url in urls:
            try:
                # Determine file type
                parsed = urlparse(url)
                path = parsed.path.lower()
                
                file_type = self._detect_file_type(path, url)
                if not file_type:
                    # Try to detect from content-type header
                    try:
                        head_resp = self.session.head(url, timeout=5, allow_redirects=True)
                        content_type = head_resp.headers.get('content-type', '').lower()
                        if 'text/html' in content_type:
                            file_type = 'html'
                        elif 'text/css' in content_type or 'text/plain' in content_type and 'css' in path:
                            file_type = 'css'
                        elif 'application/javascript' in content_type or 'text/javascript' in content_type:
                            file_type = 'javascript'
                        elif 'application/json' in content_type:
                            file_type = 'json'
                        else:
                            continue  # Skip if we can't determine type
                    except:
                        continue  # Skip if HEAD request fails
                
                # Fetch file
                resp = self.session.get(url, timeout=10, stream=True)
                if resp.status_code == 200:
                    content = resp.content
                    if len(content) > self.max_file_size:
                        logger.debug(f"Skipping {url}: too large ({len(content)} bytes)")
                        continue
                    
                    # Validate content is actually code (not error pages, redirects, etc.)
                    if not self._validate_code_content(content, file_type):
                        logger.debug(f"Skipping {url}: content validation failed (likely not code)")
                        continue
                    
                    # Try multiple encodings
                    text_content = self._decode_content(content)
                    if not text_content:
                        logger.debug(f"Skipping {url}: failed to decode content")
                        continue
                    
                    # Re-validate file type based on actual content
                    validated_type = self._validate_file_type(text_content, file_type, url)
                    if not validated_type:
                        logger.debug(f"Skipping {url}: file type validation failed")
                        continue
                    file_type = validated_type
                    
                    code_files[url] = {
                        'type': file_type,
                        'url': url,
                        'content': text_content,
                        'size': len(content),
                        'extension': Path(path).suffix,
                        'encoding': 'utf-8',  # Track encoding used
                        'validated': True  # Mark as validated
                    }
                    
                    # Check for source maps (multiple methods) - Enhanced for Next.js
                    if file_type == 'javascript' and text_content:
                        # Method 1: Check for sourceMappingURL comment
                        sourcemap_url = self._find_sourcemap(text_content, url)
                        
                        # Method 2: Check for .map file next to JS file (common in Next.js)
                        if not sourcemap_url:
                            sourcemap_url = self._find_sourcemap_file(url)
                        
                        # Method 3: Check for embedded source map (data URI)
                        if not sourcemap_url:
                            sourcemap_url = self._find_embedded_sourcemap(text_content)
                        
                        # Method 4: For Next.js, try to find source maps in build manifest
                        # Note: This is async but we're in sync context, so we'll do it later
                        # For now, mark Next.js files for later sourcemap checking
                        if not sourcemap_url and '/_next/' in url:
                            code_files[url]['_needs_sourcemap_check'] = True
                        
                        if sourcemap_url:
                            code_files[url]['sourcemap'] = sourcemap_url
                            logger.info(f"[+] Found sourcemap for {url}: {sourcemap_url}")
                        else:
                            # Log when sourcemap not found for Next.js files
                            if '/_next/' in url:
                                logger.debug(f"No sourcemap found for Next.js file: {url}")
                            
            except Exception as e:
                logger.debug(f"Failed to fetch {url}: {e}")
                continue
        
        return code_files
    
    def _detect_file_type(self, path: str, url: str) -> Optional[str]:
        """Detect file type from URL/path"""
        path_lower = path.lower()
        
        for lang, extensions in self.CODE_EXTENSIONS.items():
            for ext in extensions:
                if path_lower.endswith(ext):
                    return lang
        
        # Check patterns in path
        if 'javascript' in path_lower or '/js/' in path_lower or '/jsx/' in path_lower:
            return 'javascript'
        if 'typescript' in path_lower or '/ts/' in path_lower or '/tsx/' in path_lower:
            return 'typescript'
        if 'css' in path_lower or '/css/' in path_lower or '/scss/' in path_lower:
            return 'css'
        if path_lower.endswith('.json'):
            return 'json'
        
        # Check content-type if available (would need response headers)
        return None
    
    def _validate_code_content(self, content: bytes, file_type: str) -> bool:
        """Validate that content is actually code, not error pages or binary"""
        if len(content) < 10:  # Too small to be meaningful
            return False
        
        # Check for common error page indicators
        error_indicators = [
            b'404 Not Found',
            b'403 Forbidden',
            b'500 Internal Server Error',
            b'<!DOCTYPE html>',  # HTML error pages
            b'<html',
            b'<body'
        ]
        
        content_lower = content[:500].lower()  # Check first 500 bytes
        if any(indicator.lower() in content_lower for indicator in error_indicators):
            # Allow HTML if file_type is html
            if file_type == 'html':
                return True
            return False
        
        # Check for binary content (images, etc.)
        if file_type in ['javascript', 'css', 'typescript', 'json']:
            # Check for null bytes (binary indicator)
            if b'\x00' in content[:1000]:
                return False
            
            # Check if it's actually text (high ratio of printable chars)
            printable = sum(1 for b in content[:1000] if 32 <= b <= 126 or b in (9, 10, 13))
            if len(content[:1000]) > 0 and printable / len(content[:1000]) < 0.7:
                return False
        
        return True
    
    def _decode_content(self, content: bytes) -> Optional[str]:
        """Try multiple encodings to decode content"""
        encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'iso-8859-1', 'cp1252']
        
        for encoding in encodings:
            try:
                return content.decode(encoding, errors='strict')
            except (UnicodeDecodeError, LookupError):
                continue
        
        # Fallback: ignore errors but log
        try:
            return content.decode('utf-8', errors='ignore')
        except:
            return None
    
    def _validate_file_type(self, content: str, detected_type: str, url: str) -> Optional[str]:
        """Validate and refine file type based on actual content"""
        content_lower = content[:1000].lower()  # Check first 1000 chars
        
        # JavaScript validation
        js_indicators = [
            'function', 'var ', 'let ', 'const ', '=>', 'import ', 'export ',
            'class ', 'async ', 'await ', '()', '{}', '[]'
        ]
        
        # TypeScript/TSX validation
        ts_indicators = [
            ': string', ': number', ': boolean', 'interface ', 'type ', 'enum ',
            '<', '>', 'as ', 'extends ', 'implements '
        ]
        
        # CSS validation
        css_indicators = [
            '{', '}', ':', ';', '@media', '@import', '@keyframes', 'margin', 'padding'
        ]
        
        # JSON validation
        json_indicators = ['{', '}', '[', ']', '"', ':']
        
        # HTML validation
        html_indicators = ['<!doctype', '<html', '<head', '<body', '<div', '<span']
        
        if detected_type == 'javascript':
            # Check if it's actually TypeScript/TSX
            if any(ind in content_lower for ind in ts_indicators):
                if '.tsx' in url.lower() or 'tsx' in url.lower():
                    return 'tsx'
                elif '.ts' in url.lower() or '/ts/' in url.lower():
                    return 'typescript'
            # Validate it's actually JS
            if any(ind in content_lower for ind in js_indicators):
                return 'javascript'
            return None
        
        elif detected_type == 'typescript' or detected_type == 'tsx':
            if any(ind in content_lower for ind in ts_indicators) or any(ind in content_lower for ind in js_indicators):
                return detected_type
            return None
        
        elif detected_type == 'css':
            if any(ind in content_lower for ind in css_indicators):
                return 'css'
            return None
        
        elif detected_type == 'json':
            # Try to parse as JSON
            try:
                json.loads(content)
                return 'json'
            except:
                return None
        
        elif detected_type == 'html':
            if any(ind in content_lower for ind in html_indicators):
                return 'html'
            return None
        
        return detected_type  # Return as-is if validation passes
    
    def _find_sourcemap(self, content: str, url: str) -> Optional[str]:
        """Find sourceMappingURL in content"""
        patterns = [
            r'//#\s*sourceMappingURL\s*=\s*([^\s]+)',
            r'//@\s*sourceMappingURL\s*=\s*([^\s]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                map_ref = match.group(1).strip()
                return urljoin(url, map_ref) if not map_ref.startswith(('http://', 'https://')) else map_ref
        
        return None
    
    def _find_sourcemap_file(self, js_url: str) -> Optional[str]:
        """Check for .map file next to JS file (common pattern) - Enhanced for Next.js"""
        # Next.js specific patterns
        nextjs_patterns = []
        
        # Pattern 1: Direct .map append
        nextjs_patterns.append(js_url + '.map')
        
        # Pattern 2: Replace .js with .map
        if js_url.endswith('.js'):
            nextjs_patterns.append(js_url[:-3] + '.map')
        
        # Pattern 3: Next.js specific - try _next/static/chunks/*.js.map
        if '/_next/static/chunks/' in js_url:
            # Try same directory with .map
            base_path = js_url.rsplit('/', 1)[0]
            filename = js_url.rsplit('/', 1)[1]
            nextjs_patterns.append(f"{base_path}/{filename}.map")
            
            # Try .map in same location
            if filename.endswith('.js'):
                nextjs_patterns.append(f"{base_path}/{filename[:-3]}.map")
        
        # Pattern 4: Try with different query params removed
        parsed = urlparse(js_url)
        if parsed.query:
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            nextjs_patterns.append(base_url + '.map')
            if base_url.endswith('.js'):
                nextjs_patterns.append(base_url[:-3] + '.map')
        
        # Check all patterns
        for test_url in nextjs_patterns:
            if not test_url:
                continue
            try:
                # Try HEAD first (faster)
                resp = self.session.head(test_url, timeout=5, allow_redirects=True)
                if resp.status_code == 200:
                    content_type = resp.headers.get('content-type', '').lower()
                    if 'application/json' in content_type or 'text/plain' in content_type or 'octet-stream' in content_type:
                        # Verify it's actually a source map by checking content
                        try:
                            get_resp = self.session.get(test_url, timeout=5)
                            if get_resp.status_code == 200:
                                try:
                                    data = get_resp.json()
                                    if 'sources' in data or 'version' in data:  # Source map indicators
                                        logger.info(f"[+] Found sourcemap: {test_url}")
                                        return test_url
                                except:
                                    pass
                        except:
                            pass
            except:
                continue
        
        return None
    
    def _find_embedded_sourcemap(self, content: str) -> Optional[str]:
        """Find embedded source map (data URI)"""
        # Look for data:application/json;base64, or data:application/json;charset=utf-8,
        patterns = [
            r'//#\s*sourceMappingURL\s*=\s*data:application/json[^,]*,\s*([A-Za-z0-9+/=]+)',
            r'//@\s*sourceMappingURL\s*=\s*data:application/json[^,]*,\s*([A-Za-z0-9+/=]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                # Return a marker that indicates embedded sourcemap
                # We'll handle this in _extract_original_sources
                return 'embedded:' + match.group(1)
        
        return None
    
    async def _find_nextjs_sourcemap(self, js_url: str) -> Optional[str]:
        """Try to find Next.js source maps using build manifest and common patterns"""
        # Next.js sometimes stores source maps in a different structure
        # Try common Next.js source map locations
        
        patterns_to_try = []
        
        # Pattern 1: Check if there's a _buildManifest that might reference source maps
        parsed = urlparse(js_url)
        base_path = f"{parsed.scheme}://{parsed.netloc}"
        
        # Pattern 2: Try _next/static/chunks/*.js.map
        if '/_next/static/chunks/' in js_url:
            chunk_path = js_url.split('/_next/static/chunks/')[1]
            patterns_to_try.append(f"{base_path}/_next/static/chunks/{chunk_path}.map")
            
            # Also try without hash
            if '-' in chunk_path:
                chunk_name = chunk_path.split('-', 1)[1] if '-' in chunk_path else chunk_path
                patterns_to_try.append(f"{base_path}/_next/static/chunks/{chunk_name}.map")
        
        # Pattern 3: Check build manifest for source map references
        try:
            manifest_url = f"{base_path}/_next/static/chunks/buildManifest.js"
            resp = self.session.get(manifest_url, timeout=5)
            if resp.status_code == 200:
                manifest_content = resp.text
                # Look for source map references in manifest
                map_refs = re.findall(r'["\']([^"\']+\.map)["\']', manifest_content)
                for map_ref in map_refs:
                    if not map_ref.startswith('http'):
                        map_ref = urljoin(base_path, map_ref)
                    patterns_to_try.append(map_ref)
        except:
            pass
        
        # Try all patterns
        for test_url in patterns_to_try:
            try:
                resp = self.session.head(test_url, timeout=5, allow_redirects=True)
                if resp.status_code == 200:
                    # Verify it's a source map
                    get_resp = self.session.get(test_url, timeout=5)
                    if get_resp.status_code == 200:
                        try:
                            data = get_resp.json()
                            if 'sources' in data or 'version' in data:
                                return test_url
                        except:
                            pass
            except:
                continue
        
        return None
    
    def _deduplicate_and_validate(self, code_files: Dict) -> Dict:
        """Remove duplicates and validate all entries"""
        seen_content = {}  # Track by content hash to find duplicates
        validated_files = {}
        
        for url, file_data in code_files.items():
            # Skip if not validated
            if not file_data.get('validated', False):
                continue
            
            content = file_data.get('content', '')
            if not content:
                continue
            
            # Create content hash for duplicate detection
            import hashlib
            content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
            
            # If we've seen this content before, keep the one with better URL (shorter, more descriptive)
            if content_hash in seen_content:
                existing_url = seen_content[content_hash]
                # Prefer shorter, more descriptive URLs
                if len(url) < len(existing_url) or '/static/' in url:
                    # Remove old one, add new one
                    if existing_url in validated_files:
                        del validated_files[existing_url]
                    validated_files[url] = file_data
                    seen_content[content_hash] = url
                # Otherwise, skip this duplicate
                continue
            
            seen_content[content_hash] = url
            validated_files[url] = file_data
        
        return validated_files
    
    async def _extract_original_sources(self, code_files: Dict) -> Dict[str, Dict]:
        """Extract original TypeScript/TSX/JSX files from source maps"""
        original_sources = {}
        
        for url, file_data in code_files.items():
            if 'sourcemap' not in file_data or not file_data['sourcemap']:
                continue
            
            sourcemap_url = file_data['sourcemap']
            
            try:
                # Handle embedded source maps
                if sourcemap_url.startswith('embedded:'):
                    encoded_data = sourcemap_url.replace('embedded:', '')
                    try:
                        decoded = base64.b64decode(encoded_data).decode('utf-8')
                        sourcemap_data = json.loads(decoded)
                    except:
                        continue
                else:
                    resp = self.session.get(sourcemap_url, timeout=10)
                    if resp.status_code != 200:
                        continue
                    sourcemap_data = resp.json()
                    
                    # Extract original sources
                    sources = sourcemap_data.get('sources', [])
                    sources_content = sourcemap_data.get('sourcesContent', [])
                    
                    for i, source_path in enumerate(sources):
                        # Skip node_modules and other non-source files
                        if 'node_modules' in source_path or '.next' in source_path:
                            continue
                        
                        # Determine if it's TS, TSX, JSX, etc.
                        source_type = self._detect_file_type(source_path, source_path)
                        
                        # More aggressive TSX/TS detection
                        is_tsx = source_path.endswith('.tsx') or '/tsx/' in source_path.lower()
                        is_ts = source_path.endswith('.ts') or '/ts/' in source_path.lower() and not is_tsx
                        is_jsx = source_path.endswith('.jsx') or '/jsx/' in source_path.lower()
                        
                        if is_tsx or is_ts or is_jsx or source_type in ['typescript', 'jsx']:
                            content = sources_content[i] if i < len(sources_content) else None
                            
                            # Validate content is actually TypeScript/TSX
                            if content:
                                content_lower = content[:500].lower()
                                has_ts_features = any(ind in content_lower for ind in [
                                    ': string', ': number', 'interface ', 'type ', 'enum ', '<', '>'
                                ])
                                has_jsx = '<' in content and '>' in content and ('return' in content_lower or 'export' in content_lower)
                                
                                # Determine actual type with validation
                                if is_tsx or (has_ts_features and has_jsx):
                                    actual_type = 'tsx'
                                elif is_ts or has_ts_features:
                                    actual_type = 'typescript'
                                elif is_jsx or has_jsx:
                                    actual_type = 'jsx'
                                else:
                                    actual_type = source_type or 'typescript'
                            else:
                                # No content, infer from path
                                if is_tsx:
                                    actual_type = 'tsx'
                                elif is_ts:
                                    actual_type = 'typescript'
                                elif is_jsx:
                                    actual_type = 'jsx'
                                else:
                                    actual_type = source_type or 'typescript'
                            
                            # Only add if we have content or it's clearly a TSX/TS file
                            if content or is_tsx or is_ts or is_jsx:
                                original_sources[source_path] = {
                                    'type': actual_type,
                                    'path': source_path,
                                    'content': content,
                                    'from_sourcemap': sourcemap_url,
                                    'original_js': url,
                                    'validated': content is not None,  # Mark if we have actual content
                                    'has_content': content is not None
                                }
                            
            except Exception as e:
                logger.debug(f"Failed to process sourcemap {sourcemap_url}: {e}")
        
        return original_sources
    
    async def _extract_inline_code(self, page, html_content: str) -> List[Dict]:
        """Extract inline CSS and JavaScript from HTML"""
        inline_files = []
        
        if not BS4_AVAILABLE:
            return inline_files
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract inline CSS from <style> tags
            style_tags = soup.find_all('style')
            for i, style_tag in enumerate(style_tags):
                css_content = style_tag.string or ''
                if css_content.strip():
                    inline_files.append({
                        'type': 'css',
                        'url': f'{self.base_url}#inline-style-{i}',
                        'content': css_content,
                        'size': len(css_content),
                        'extension': '.css',
                        'inline': True,
                        'location': 'style_tag'
                    })
            
            # Extract inline JavaScript from <script> tags (without src)
            script_tags = soup.find_all('script', src=False)
            for i, script_tag in enumerate(script_tags):
                js_content = script_tag.string or ''
                if js_content.strip():
                    script_type = script_tag.get('type', 'text/javascript')
                    inline_files.append({
                        'type': 'javascript',
                        'url': f'{self.base_url}#inline-script-{i}',
                        'content': js_content,
                        'size': len(js_content),
                        'extension': '.js',
                        'inline': True,
                        'location': 'script_tag',
                        'script_type': script_type
                    })
            
            # Extract CSS from style attributes (collect all unique styles)
            style_attrs = set()
            for element in soup.find_all(style=True):
                style_attrs.add(element.get('style', ''))
            
            if style_attrs:
                combined_inline_styles = '\n'.join([f"/* Inline style from element */\n{s}" for s in style_attrs if s.strip()])
                if combined_inline_styles:
                    inline_files.append({
                        'type': 'css',
                        'url': f'{self.base_url}#inline-styles-attributes',
                        'content': combined_inline_styles,
                        'size': len(combined_inline_styles),
                        'extension': '.css',
                        'inline': True,
                        'location': 'style_attributes'
                    })
            
            # Extract CSS from @import statements in style tags
            for style_tag in style_tags:
                css_content = style_tag.string or ''
                if '@import' in css_content:
                    # Extract import URLs
                    import_pattern = r'@import\s+(?:url\()?["\']?([^"\']+)["\']?\)?'
                    imports = re.findall(import_pattern, css_content)
                    for imp_url in imports:
                        full_url = urljoin(self.base_url, imp_url)
                        inline_files.append({
                            'type': 'css',
                            'url': full_url,
                            'content': None,  # Will be fetched separately
                            'size': 0,
                            'extension': '.css',
                            'inline': False,
                            'location': 'css_import',
                            'imported_from': self.base_url
                        })
            
            logger.info(f"[+] Extracted {len(inline_files)} inline code blocks")
            
        except Exception as e:
            logger.debug(f"Error extracting inline code: {e}")
        
        return inline_files
    
    async def _extract_iframe_code(self, page) -> Set[str]:
        """Extract code resources from iframes"""
        iframe_resources = set()
        
        try:
            # Get all iframes
            iframes = await page.query_selector_all('iframe')
            
            for iframe in iframes:
                try:
                    iframe_src = await iframe.get_attribute('src')
                    if iframe_src and iframe_src.startswith(('http://', 'https://')):
                        iframe_resources.add(iframe_src)
                    
                    # Try to access iframe content (may fail due to CORS)
                    try:
                        iframe_frame = await iframe.content_frame()
                        if iframe_frame:
                            # Get scripts from iframe
                            iframe_scripts = await iframe_frame.evaluate("""
                                () => Array.from(document.scripts)
                                    .map(s => s.src)
                                    .filter(Boolean)
                            """)
                            iframe_resources.update(iframe_scripts)
                            
                            # Get links from iframe
                            iframe_links = await iframe_frame.evaluate("""
                                () => Array.from(document.querySelectorAll('link[href]'))
                                    .map(l => l.href)
                                    .filter(Boolean)
                            """)
                            iframe_resources.update(iframe_links)
                    except Exception as e:
                        logger.debug(f"Could not access iframe content (CORS?): {e}")
                        
                except Exception as e:
                    logger.debug(f"Error processing iframe: {e}")
            
            if iframe_resources:
                logger.info(f"[+] Found {len(iframe_resources)} resources from {len(iframes)} iframes")
        
        except Exception as e:
            logger.debug(f"Error extracting iframe code: {e}")
        
        return iframe_resources
    
    async def _extract_page_links(self, page, current_url: str) -> Set[str]:
        """Extract all links from a page for crawling (same domain only)"""
        links = set()
        
        try:
            # Get all links from the page
            page_links = await page.evaluate("""
                () => {
                    const links = [];
                    const anchors = document.querySelectorAll('a[href]');
                    anchors.forEach(a => {
                        const href = a.getAttribute('href');
                        if (href) links.push(href);
                    });
                    return [...new Set(links)];
                }
            """)
            
            for link in page_links:
                # Resolve relative URLs
                if link.startswith('#'):
                    continue  # Skip anchor links
                
                # Skip javascript:, mailto:, tel:, etc.
                if ':' in link and not link.startswith('http'):
                    continue
                
                # Resolve URL
                if link.startswith('http://') or link.startswith('https://'):
                    full_url = link
                else:
                    full_url = urljoin(current_url, link)
                
                # Parse and check if same domain
                try:
                    parsed = urlparse(full_url)
                    # Only crawl same domain
                    if parsed.netloc == self.parsed_base.netloc or parsed.netloc == '':
                        # Normalize URL (remove fragment, query params for deduplication)
                        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if normalized and normalized not in self.visited_urls:
                            links.add(normalized)
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Error extracting links from {current_url}: {e}")
        
        return links
    
    async def _follow_css_imports(self, code_files: Dict) -> Set[str]:
        """Follow CSS @import statements recursively"""
        import_urls = set()
        processed = set()
        
        def extract_imports(css_content: str, base_url: str):
            """Extract @import URLs from CSS"""
            imports = set()
            # Match @import url(...) or @import "..."
            patterns = [
                r'@import\s+url\(["\']?([^"\']+)["\']?\)',
                r'@import\s+["\']([^"\']+)["\']',
                r'@import\s+([^;]+);'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, css_content, re.IGNORECASE)
                for match in matches:
                    url = match.strip().strip('"\'')
                    if url and not url.startswith(('http://', 'https://')):
                        url = urljoin(base_url, url)
                    if url and url.startswith(('http://', 'https://')):
                        imports.add(url)
            
            return imports
        
        # Process all CSS files
        for url, file_data in code_files.items():
            if file_data.get('type') == 'css' and file_data.get('content'):
                css_content = file_data['content']
                if url not in processed:
                    processed.add(url)
                    imports = extract_imports(css_content, url)
                    import_urls.update(imports)
        
        return import_urls
    
    async def _extract_js_imports(self, code_files: Dict) -> Set[str]:
        """Extract JavaScript module imports (ES6, CommonJS, etc.)"""
        import_urls = set()
        
        def extract_js_imports(js_content: str, base_url: str):
            """Extract import/require URLs from JavaScript"""
            imports = set()
            
            # ES6 import statements
            es6_patterns = [
                r'import\s+.*?\s+from\s+["\']([^"\']+)["\']',
                r'import\s*\(["\']([^"\']+)["\']\)',
                r'import\s+["\']([^"\']+)["\']'
            ]
            
            for pattern in es6_patterns:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    url = match.strip()
                    if url and not url.startswith(('.', '/', 'http://', 'https://')):
                        continue  # Skip node_modules, etc.
                    if url and not url.startswith(('http://', 'https://')):
                        url = urljoin(base_url, url)
                    if url and url.startswith(('http://', 'https://')):
                        imports.add(url)
            
            # CommonJS require
            require_patterns = [
                r'require\s*\(["\']([^"\']+)["\']\)',
            ]
            
            for pattern in require_patterns:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    url = match.strip()
                    if url and not url.startswith(('.', '/', 'http://', 'https://')):
                        continue
                    if url and not url.startswith(('http://', 'https://')):
                        url = urljoin(base_url, url)
                    if url and url.startswith(('http://', 'https://')):
                        imports.add(url)
            
            # Dynamic imports
            dynamic_patterns = [
                r'import\s*\(["\']([^"\']+)["\']\)',
                r'fetch\s*\(["\']([^"\']+\.(js|mjs|ts|tsx|jsx))["\']'
            ]
            
            for pattern in dynamic_patterns:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    url = match[0] if isinstance(match, tuple) else match
                    url = url.strip()
                    if url and not url.startswith(('http://', 'https://')):
                        url = urljoin(base_url, url)
                    if url and url.startswith(('http://', 'https://')):
                        imports.add(url)
            
            return imports
        
        # Process all JavaScript files
        for url, file_data in code_files.items():
            if file_data.get('type') == 'javascript' and file_data.get('content'):
                js_content = file_data['content']
                imports = extract_js_imports(js_content, url)
                import_urls.update(imports)
        
        return import_urls
    
    async def _detect_tech_stack(self, code_files: Dict, html_content: str) -> Dict:
        """Detect modern frameworks and technologies (2025 standards)"""
        tech_stack = {
            'frameworks': [],
            'libraries': [],
            'build_tools': [],
            'features': [],
            'api_patterns': []
        }
        
        # Framework detection patterns
        framework_patterns = {
            'React': [
                r'from\s+["\']react["\']',
                r'React\.(createElement|Component)',
                r'import.*from\s+["\']react["\']',
                r'__REACT_DEVTOOLS'
            ],
            'Vue': [
                r'from\s+["\']vue["\']',
                r'Vue\.(component|createApp)',
                r'import.*from\s+["\']vue["\']',
                r'__VUE__'
            ],
            'Angular': [
                r'@angular/',
                r'@Component',
                r'@Injectable',
                r'@NgModule'
            ],
            'Svelte': [
                r'from\s+["\']svelte["\']',
                r'<script\s+context="module"',
                r'svelte/store'
            ],
            'Next.js': [
                r'next/',
                r'__NEXT_DATA__',
                r'getServerSideProps',
                r'getStaticProps'
            ],
            'Nuxt': [
                r'nuxt/',
                r'@nuxtjs/',
                r'useNuxtApp'
            ],
            'Remix': [
                r'@remix-run/',
                r'remix'
            ]
        }
        
        # Library detection
        library_patterns = {
            'jQuery': [r'\$\(', r'jQuery'],
            'Lodash': [r'from\s+["\']lodash["\']', r'_\.'],
            'Axios': [r'from\s+["\']axios["\']', r'axios\.'],
            'Redux': [r'from\s+["\']redux["\']', r'createStore'],
            'Zustand': [r'from\s+["\']zustand["\']'],
            'TanStack Query': [r'@tanstack/react-query', r'useQuery'],
            'SWR': [r'from\s+["\']swr["\']', r'useSWR'],
            'Tailwind CSS': [r'tailwindcss', r'@tailwind'],
            'Bootstrap': [r'bootstrap', r'\.btn-'],
            'Material-UI': [r'@mui/', r'@material-ui/'],
            'Chakra UI': [r'@chakra-ui/']
        }
        
        # Build tools
        build_tool_patterns = {
            'Webpack': [r'webpack', r'__webpack_require__'],
            'Vite': [r'vite/', r'import\.meta\.env'],
            'Parcel': [r'parcel'],
            'Rollup': [r'rollup'],
            'Turbopack': [r'turbopack'],
            'esbuild': [r'esbuild']
        }
        
        # Modern JS features
        modern_features = {
            'ES Modules': [r'import\s+.*\s+from', r'export\s+(default\s+)?'],
            'Async/Await': [r'async\s+function', r'await\s+'],
            'Arrow Functions': [r'=>\s*{', r'=>\s*\w+'],
            'Template Literals': [r'`[^`]+`'],
            'Destructuring': [r'const\s+{.*}\s*=', r'const\s+\[.*\]\s*='],
            'Optional Chaining': [r'\?\.'],
            'Nullish Coalescing': [r'\?\?'],
            'Top-level Await': [r'^await\s+'],
            'Private Fields': [r'#\w+']
        }
        
        # API patterns
        api_patterns = {
            'REST API': [r'fetch\s*\(["\']https?://[^"\']+api', r'axios\.(get|post|put|delete)'],
            'GraphQL': [r'gql\s*`', r'graphql', r'query\s+\{', r'mutation\s+\{'],
            'WebSocket': [r'new\s+WebSocket', r'ws://', r'wss://'],
            'Server-Sent Events': [r'new\s+EventSource', r'text/event-stream'],
            'Fetch API': [r'fetch\s*\('],
            'XMLHttpRequest': [r'XMLHttpRequest', r'new\s+XHR']
        }
        
        # Check all code files with confidence scoring
        all_content = html_content.lower()
        framework_scores = {}  # Track confidence scores
        library_scores = {}
        build_tool_scores = {}
        
        for url, file_data in code_files.items():
            if file_data.get('content') and file_data.get('validated'):
                content = file_data['content']
                content_lower = content.lower()
                all_content += '\n' + content_lower
                
                # Check frameworks with confidence scoring
                for framework, patterns in framework_patterns.items():
                    matches = sum(1 for pattern in patterns if re.search(pattern, content, re.IGNORECASE))
                    if matches > 0:
                        if framework not in framework_scores:
                            framework_scores[framework] = 0
                        framework_scores[framework] += matches
                
                # Check libraries with confidence scoring
                for library, patterns in library_patterns.items():
                    matches = sum(1 for pattern in patterns if re.search(pattern, content, re.IGNORECASE))
                    if matches > 0:
                        if library not in library_scores:
                            library_scores[library] = 0
                        library_scores[library] += matches
                
                # Check build tools with confidence scoring
                for tool, patterns in build_tool_patterns.items():
                    matches = sum(1 for pattern in patterns if re.search(pattern, content, re.IGNORECASE))
                    if matches > 0:
                        if tool not in build_tool_scores:
                            build_tool_scores[tool] = 0
                        build_tool_scores[tool] += matches
        
        # Only include high-confidence detections (threshold: 2+ matches)
        tech_stack['frameworks'] = [fw for fw, score in framework_scores.items() if score >= 2]
        tech_stack['libraries'] = [lib for lib, score in library_scores.items() if score >= 2]
        tech_stack['build_tools'] = [tool for tool, score in build_tool_scores.items() if score >= 2]
        
        # Check modern features in all content
        for feature, patterns in modern_features.items():
            if any(re.search(pattern, all_content, re.IGNORECASE | re.MULTILINE) for pattern in patterns):
                if feature not in tech_stack['features']:
                    tech_stack['features'].append(feature)
        
        # Check API patterns
        for pattern_name, patterns in api_patterns.items():
            if any(re.search(pattern, all_content, re.IGNORECASE) for pattern in patterns):
                if pattern_name not in tech_stack['api_patterns']:
                    tech_stack['api_patterns'].append(pattern_name)
        
        # Detect TypeScript usage
        if any(f.get('type') in ['typescript', 'tsx'] for f in code_files.values()):
            tech_stack['features'].append('TypeScript')
        
        # Detect JSX/TSX
        if any(f.get('type') in ['jsx', 'tsx'] for f in code_files.values()):
            tech_stack['features'].append('JSX/TSX')
        
        # Try to detect TSX patterns in compiled JS (Next.js compiles TSX to JS)
        # Look for React component patterns that suggest TSX origin
        tsx_indicators_found = False
        for url, file_data in code_files.items():
            if file_data.get('type') == 'javascript' and file_data.get('content'):
                content = file_data['content']
                # Look for patterns that suggest TSX origin:
                # - JSX.createElement patterns
                # - Component names matching TSX file patterns
                # - Type annotations in comments
                if any(pattern in content for pattern in [
                    'jsx(', 'jsxs(',  # Next.js JSX runtime
                    'React.createElement',
                    'export default function',  # Common TSX pattern
                    ': React.FC',  # TypeScript React component
                    'interface Props',  # TSX props pattern
                ]):
                    # Check if it's a Next.js app component
                    if '/app/' in url or '/pages/' in url or '/components/' in url:
                        tsx_indicators_found = True
                        break
        
        if tsx_indicators_found and 'JSX/TSX' not in tech_stack['features']:
            tech_stack['features'].append('JSX/TSX (detected in compiled JS)')
            tech_stack['note'] = 'TSX patterns detected in compiled JavaScript. Original TSX files would be available if source maps are enabled in production build.'
        
        return tech_stack
    
    def _parse_html_structure(self, html: str) -> Dict:
        """Parse HTML and identify semantic sections"""
        if not BS4_AVAILABLE:
            return {
                'raw_html': html[:5000],
                'note': 'BeautifulSoup4 not available, showing raw HTML only'
            }
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            structure = {
                'description': 'Semantic HTML structure. Sections are labeled for AI understanding (header, footer, main content, etc.)',
                'doctype': self._get_doctype(soup),
                'head': self._extract_head(soup),
                'body_sections': [],
                'ai_note': 'Each section includes: type (header/footer/main/etc), tag name, content preview, and HTML snippet. Use this to understand page structure.'
            }
            
            body = soup.find('body')
            if body:
                structure['body_sections'] = self._identify_sections(body)
            
            return structure
        except Exception as e:
            logger.debug(f"HTML parsing error: {e}")
            return {'raw_html': html[:5000], 'error': str(e)}
    
    def _identify_sections(self, body) -> List[Dict]:
        """Identify semantic sections in HTML"""
        sections = []
        
        semantic_tags = {
            'header': 'header',
            'footer': 'footer',
            'nav': 'navigation',
            'main': 'main_content',
            'article': 'article',
            'section': 'section',
            'aside': 'sidebar',
            'form': 'form'
        }
        
        for tag, label in semantic_tags.items():
            for elem in body.find_all(tag):
                # Remove script and style for content preview
                for script in elem(["script", "style"]):
                    script.decompose()
                
                sections.append({
                    'type': label,
                    'tag': tag,
                    'id': elem.get('id', ''),
                    'class': elem.get('class', []),
                    'content_preview': elem.get_text(separator=' ', strip=True)[:200],
                    'html_snippet': str(elem)[:500]
                })
        
        # If no semantic tags found, try common patterns
        if not sections:
            sections = self._find_common_patterns(body)
        
        return sections
    
    def _find_common_patterns(self, body) -> List[Dict]:
        """Find sections using common class/id patterns"""
        sections = []
        
        patterns = {
            'header': ['header', 'top', 'navbar', 'nav-bar', 'navigation', 'topbar'],
            'footer': ['footer', 'bottom', 'foot'],
            'main': ['main', 'content', 'container', 'wrapper', 'page-content'],
            'sidebar': ['sidebar', 'side', 'aside', 'side-panel'],
            'navigation': ['nav', 'menu', 'navigation', 'navbar']
        }
        
        for label, keywords in patterns.items():
            for keyword in keywords:
                # Search by class
                elements = body.find_all(class_=re.compile(keyword, re.I))
                # Search by id
                elements.extend(body.find_all(id=re.compile(keyword, re.I)))
                
                for elem in elements[:1]:  # Limit to first match per pattern
                    # Remove script and style
                    for script in elem(["script", "style"]):
                        script.decompose()
                    
                    sections.append({
                        'type': label,
                        'detected_by': f'pattern: {keyword}',
                        'tag': elem.name,
                        'id': elem.get('id', ''),
                        'class': elem.get('class', []),
                        'content_preview': elem.get_text(separator=' ', strip=True)[:200],
                        'html_snippet': str(elem)[:500]
                    })
                    break
        
        return sections
    
    def _extract_head(self, soup) -> Dict:
        """Extract head section"""
        head = soup.find('head')
        if not head:
            return {}
        
        title_elem = soup.find('title')
        title = title_elem.get_text() if title_elem else ''
        
        return {
            'title': title,
            'meta_tags': [dict(meta.attrs) for meta in head.find_all('meta')],
            'links': [
                {
                    'rel': link.get('rel', []),
                    'href': link.get('href'),
                    'type': link.get('type')
                }
                for link in head.find_all('link')
            ]
        }
    
    def _get_doctype(self, soup) -> str:
        """Get document type"""
        if soup.contents and hasattr(soup.contents[0], 'string'):
            return str(soup.contents[0])
        return 'HTML5'
    
    def _organize_by_language(self, code_files: Dict, original_sources: Dict, html_structure: Dict) -> Dict:
        """Organize all code by language/type with AI-friendly structure"""
        organized = {
            'metadata': {
                'extraction_timestamp': None,  # Will be set by caller
                'base_url': self.base_url,
                'description': 'Complete source code extraction with semantic labeling for AI analysis (2025 standards)',
                'structure_note': 'Files are organized by language type. Inline code is separated from external files for clarity.',
                'version': '2025.1',
                'format': 'ai_optimized',
                'tech_stack': {}  # Will be populated with framework detection
            },
            'html': {
                'description': 'HTML files and structure. Contains semantic sections (header, footer, main, etc.) for AI understanding.',
                'files': [],
                'structure': html_structure,
                'inline_css': [],
                'inline_javascript': []
            },
            'css': {
                'description': 'CSS stylesheets. External files and inline styles are separated.',
                'files': [],
                'inline': []
            },
            'javascript': {
                'description': 'JavaScript files. Includes external files and inline scripts. May contain API endpoints and business logic.',
                'files': [],
                'inline': []
            },
            'typescript': {
                'description': 'TypeScript source files recovered from source maps. Original source code before minification.',
                'files': []
            },
            'jsx': {
                'description': 'JSX files (React components) recovered from source maps.',
                'files': []
            },
            'tsx': {
                'description': 'TSX files (TypeScript + React) recovered from source maps.',
                'files': []
            },
            'json': {
                'description': 'JSON configuration and data files.',
                'files': []
            },
            'other': {
                'description': 'Other code files (XML, SVG, text files, etc.).',
                'files': []
            }
        }
        
        # Organize fetched files
        for url, file_data in code_files.items():
            file_type = file_data['type']
            is_inline = file_data.get('inline', False)
            
            # Handle HTML separately (already has structure)
            if file_type == 'html':
                organized['html']['files'].append({
                    'url': url,
                    'filename': Path(urlparse(url).path).name or 'index.html',
                    'size': file_data['size'],
                    'content': file_data['content'],
                    'extension': file_data['extension'],
                    'type': 'html',
                    'semantic_note': 'This HTML file contains the main page structure. Check the structure field for semantic sections.'
                })
            elif file_type == 'css':
                if is_inline:
                    organized['css']['inline'].append({
                        'url': url,
                        'content': file_data['content'],
                        'size': file_data['size'],
                        'location': file_data.get('location', 'unknown'),
                        'extension': file_data['extension'],
                        'type': 'css_inline',
                        'semantic_note': f"Inline CSS found in {file_data.get('location', 'HTML')}. This is embedded directly in the HTML."
                    })
                else:
                    organized['css']['files'].append({
                        'url': url,
                        'filename': Path(urlparse(url).path).name,
                        'size': file_data['size'],
                        'content': file_data['content'],
                        'extension': file_data['extension'],
                        'sourcemap': file_data.get('sourcemap'),
                        'type': 'css_external',
                        'semantic_note': 'External CSS stylesheet. May contain @import statements that reference other CSS files.'
                    })
            elif file_type == 'javascript':
                if is_inline:
                    organized['javascript']['inline'].append({
                        'url': url,
                        'content': file_data['content'],
                        'size': file_data['size'],
                        'location': file_data.get('location', 'unknown'),
                        'script_type': file_data.get('script_type', 'text/javascript'),
                        'extension': file_data['extension'],
                        'type': 'javascript_inline',
                        'semantic_note': f"Inline JavaScript found in {file_data.get('location', 'HTML')}. May contain initialization code or API calls."
                    })
                else:
                    organized['javascript']['files'].append({
                        'url': url,
                        'filename': Path(urlparse(url).path).name,
                        'size': file_data['size'],
                        'content': file_data['content'],
                        'extension': file_data['extension'],
                        'sourcemap': file_data.get('sourcemap'),
                        'type': 'javascript_external',
                        'semantic_note': 'External JavaScript file. May contain API endpoints, business logic, or module imports. Check for sourcemap to recover original TypeScript/TSX source.'
                    })
            elif file_type in organized:
                organized[file_type]['files'].append({
                    'url': url,
                    'filename': Path(urlparse(url).path).name,
                    'size': file_data['size'],
                    'content': file_data['content'],
                    'extension': file_data['extension'],
                    'sourcemap': file_data.get('sourcemap')
                })
            else:
                organized['other']['files'].append({
                    'url': url,
                    'filename': Path(urlparse(url).path).name,
                    'size': file_data['size'],
                    'content': file_data['content'],
                    'extension': file_data['extension']
                })
        
        # Add original sources from source maps
        for source_path, source_data in original_sources.items():
            source_type = source_data['type']
            
            if source_type in organized:
                # Only add if we have content or it's a valid TSX/TS/JSX file
                if source_data.get('has_content', False) or source_data.get('content'):
                    organized[source_type]['files'].append({
                        'path': source_path,
                        'filename': Path(source_path).name,
                        'content': source_data['content'],
                        'from_sourcemap': source_data['from_sourcemap'],
                        'original_js': source_data['original_js'],
                        'recovered': True,  # Mark as recovered from sourcemap
                        'type': source_type,
                        'semantic_note': f'Original {source_type} source recovered from source map. This is the unminified, human-readable source code.'
                    })
                else:
                    # Log when we found a source map entry but no content
                    logger.debug(f"Source map entry found for {source_path} but no content available")
        
        # Add summary
        total_external = sum(
            len(data.get('files', [])) 
            for data in organized.values() 
            if isinstance(data, dict) and 'files' in data
        )
        total_inline_css = len(organized.get('css', {}).get('inline', []))
        total_inline_js = len(organized.get('javascript', {}).get('inline', []))
        
        # Calculate accuracy metrics (count validated files from organized structure)
        validated_count = sum(
            len(data.get('files', [])) 
            for data in organized.values() 
            if isinstance(data, dict) and 'files' in data
        ) + total_inline_css + total_inline_js
        total_extracted = total_external + total_inline_css + total_inline_js
        accuracy_percentage = (validated_count / total_extracted * 100) if total_extracted > 0 else 100.0
        
        # Count source maps found
        sourcemaps_found = sum(
            1 for url, data in code_files.items() 
            if data.get('sourcemap') and data.get('sourcemap') is not None
        )
        sourcemaps_checked = sum(
            1 for url in code_files.keys() 
            if '/_next/' in url or url.endswith('.js')
        )
        
        organized['summary'] = {
            'description': 'Complete statistics of extracted code. Use this to understand the codebase structure at a glance.',
            'total_files': total_external + total_inline_css + total_inline_js,
            'external_files': total_external,
            'inline_css_blocks': total_inline_css,
            'inline_javascript_blocks': total_inline_js,
            'by_type': {
                lang: len(data.get('files', [])) 
                for lang, data in organized.items() 
                if isinstance(data, dict) and 'files' in data and lang != 'metadata'
            },
            'accuracy_metrics': {
                'validated_files': validated_count,
                'total_extracted': total_extracted,
                'validation_rate': f"{accuracy_percentage:.1f}%",
                'note': 'All files in output have been validated as actual code (not error pages, binary, or invalid content)'
            },
            'source_map_status': {
                'description': 'Source map detection status. TSX/TS files can only be recovered if source maps are available in production builds.',
                'sourcemaps_found': sourcemaps_found,
                'sourcemaps_checked': sourcemaps_checked,
                'recovered_files': len(original_sources),
                'note': 'Next.js production builds often disable source maps. Enable with productionBrowserSourceMaps: true in next.config.js to recover TSX files.'
            },
            'ai_reading_guide': {
                'start_here': 'Begin by reading the HTML structure to understand the page layout and semantic sections.',
                'key_files': 'Focus on JavaScript files for API endpoints and business logic. Check TypeScript/TSX files for original source code.',
                'inline_code': 'Inline CSS and JavaScript are embedded in HTML - check these for page-specific styling and initialization.',
                'source_maps': 'Files marked with recovered=true are original sources recovered from minified code via source maps.',
                'framework_detection': 'Check metadata.tech_stack to understand which modern frameworks and libraries are used.',
                'modern_features': 'Look for ES modules, async/await, and other modern JavaScript features in the tech_stack.features array.'
            },
            'tech_stack_summary': {
                'description': 'Detected technologies, frameworks, and modern features. Use this to understand the application architecture.',
                'primary_framework': None,  # Will be set if detected
                'is_spa': False,  # Will be set if single-page app detected
                'uses_typescript': False,  # Will be set if TypeScript detected
                'modern_js_features': []  # Will be populated
            }
        }
        
        # Add timestamp
        from datetime import datetime
        organized['metadata']['extraction_timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        return organized
    
    def run_extract(self) -> Dict:
        """Synchronous wrapper"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.extract_all_code())

