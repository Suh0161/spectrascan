"""
Static scanning module for JavaScript endpoint discovery
"""
import re
import requests
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class StaticScanner:
    """Scans JavaScript files for API endpoints using regex patterns"""
    
    # Common patterns for endpoint discovery
    PATTERNS = [
        # fetch() calls
        (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch'),
        (r'fetch\s*\(\s*`([^`]+)`', 'fetch'),
        # axios calls
        (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
        (r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'axios'),
        # XMLHttpRequest
        (r'\.open\s*\(\s*["\']([A-Z]+)["\']\s*,\s*["\']([^"\']+)["\']', 'xhr'),
        # WebSocket
        (r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', 'websocket'),
        # EventSource (SSE)
        (r'new\s+EventSource\s*\(\s*["\']([^"\']+)["\']', 'sse'),
        # GraphQL gql template literals (basic)
        (r'gql\s*`\s*query\s+(\w+)[^`]*`', 'graphql'),
    ]
    
    def __init__(self, base_url: str, max_js_size: int = 10 * 1024 * 1024):
        self.base_url = base_url
        self.max_js_size = max_js_size
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SpectraScan/1.0'
        })
    
    def fetch_html(self) -> Optional[str]:
        """Fetch the main HTML page"""
        try:
            resp = self.session.get(self.base_url, timeout=10)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            logger.error(f"Failed to fetch HTML: {e}")
            return None
    
    def extract_js_urls(self, html: str) -> List[str]:
        """Extract JavaScript file URLs from HTML"""
        js_urls = []
        
        # <script src="...">
        script_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        for match in re.finditer(script_pattern, html, re.IGNORECASE):
            url = match.group(1)
            full_url = urljoin(self.base_url, url)
            js_urls.append(full_url)
        
        # <script type="module" src="...">
        module_pattern = r'<script[^>]+type=["\']module["\'][^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        for match in re.finditer(module_pattern, html, re.IGNORECASE):
            url = match.group(1)
            full_url = urljoin(self.base_url, url)
            js_urls.append(full_url)
        
        return list(set(js_urls))  # deduplicate
    
    def fetch_js(self, url: str) -> Optional[tuple]:
        """Fetch a JavaScript file and return (content, url)"""
        try:
            resp = self.session.get(url, timeout=10, stream=True)
            resp.raise_for_status()
            
            # Check size
            content_length = resp.headers.get('Content-Length')
            if content_length and int(content_length) > self.max_js_size:
                logger.warning(f"Skipping {url}: too large ({content_length} bytes)")
                return None
            
            content = resp.content
            if len(content) > self.max_js_size:
                logger.warning(f"Skipping {url}: too large ({len(content)} bytes)")
                return None
            
            return (content.decode('utf-8', errors='ignore'), url)
        except Exception as e:
            logger.error(f"Failed to fetch JS {url}: {e}")
            return None
    
    def scan_js(self, content: str, url: str) -> List[Dict]:
        """Scan JavaScript content for endpoints"""
        findings = []
        
        for pattern, method_type in self.PATTERNS:
            for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
                try:
                    if method_type == 'xhr':
                        method = match.group(1)
                        endpoint_url = match.group(2)
                    elif method_type == 'axios':
                        if len(match.groups()) == 2:
                            method = match.group(1).upper()
                            endpoint_url = match.group(2)
                        else:
                            endpoint_url = match.group(1)
                            method = 'GET'  # default
                    else:
                        endpoint_url = match.group(1)
                        method = 'GET' if method_type in ['fetch', 'websocket', 'sse'] else 'POST'
                    
                    # Resolve relative URLs
                    if not endpoint_url.startswith(('http://', 'https://', 'ws://', 'wss://')):
                        endpoint_url = urljoin(self.base_url, endpoint_url)
                    
                    # Calculate line number
                    line_num = content[:match.start()].count('\n') + 1
                    col_num = match.start() - content[:match.start()].rfind('\n') - 1
                    
                    findings.append({
                        'url': endpoint_url,
                        'method': method,
                        'type': method_type,
                        'source': url,
                        'line': line_num,
                        'column': col_num,
                        'match': match.group(0)[:100]  # first 100 chars
                    })
                except Exception as e:
                    logger.debug(f"Error parsing match: {e}")
                    continue
        
        return findings
    
    def scan(self) -> Dict:
        """Run full static scan"""
        logger.info(f"[+] Starting static scan of {self.base_url}...")
        
        html = self.fetch_html()
        if not html:
            return {'endpoints': [], 'js_files': [], 'error': 'Failed to fetch HTML'}
        
        js_urls = self.extract_js_urls(html)
        logger.info(f"[+] Found {len(js_urls)} JavaScript files")
        
        all_findings = []
        js_files_processed = []
        
        for js_url in js_urls:
            result = self.fetch_js(js_url)
            if result:
                content, url = result
                findings = self.scan_js(content, url)
                all_findings.extend(findings)
                js_files_processed.append({
                    'url': url,
                    'size': len(content),
                    'findings_count': len(findings)
                })
                logger.debug(f"  Scanned {url}: {len(findings)} findings")
        
        logger.info(f"[+] Static scan complete: {len(all_findings)} findings from {len(js_files_processed)} files")
        
        return {
            'endpoints': all_findings,
            'js_files': js_files_processed,
            'html_url': self.base_url
        }

