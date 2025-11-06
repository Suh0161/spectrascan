"""
Source map fetching and mapping utilities
Maps minified code locations back to original source files
"""
import re
import json
import requests
import logging
from urllib.parse import urljoin, urlparse
from typing import Dict, Optional, List, Tuple

logger = logging.getLogger(__name__)

try:
    import sourcemap
    SOURCEMAP_AVAILABLE = True
except ImportError:
    SOURCEMAP_AVAILABLE = False
    logger.warning("sourcemap library not installed. Install with: pip install sourcemap")


class SourceMapHandler:
    """Handles source map fetching and location mapping"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SpectraScan/1.0'
        })
        self.sourcemaps = {}  # js_url -> sourcemap data
    
    def find_sourcemap_url(self, js_content: str, js_url: str) -> Optional[str]:
        """Find sourceMappingURL comment in JavaScript"""
        # Look for //# sourceMappingURL= or //@ sourceMappingURL=
        patterns = [
            r'//#\s*sourceMappingURL\s*=\s*([^\s]+)',
            r'//@\s*sourceMappingURL\s*=\s*([^\s]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, js_content, re.MULTILINE)
            if match:
                map_ref = match.group(1).strip()
                # Resolve relative URLs
                if not map_ref.startswith(('http://', 'https://')):
                    map_url = urljoin(js_url, map_ref)
                else:
                    map_url = map_ref
                return map_url
        
        return None
    
    def fetch_sourcemap(self, map_url: str) -> Optional[Dict]:
        """Fetch and parse a source map file"""
        try:
            resp = self.session.get(map_url, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.debug(f"Failed to fetch sourcemap {map_url}: {e}")
            return None
    
    def process_js_file(self, js_content: str, js_url: str) -> Optional[Dict]:
        """Process a JS file and fetch its sourcemap if available"""
        map_url = self.find_sourcemap_url(js_content, js_url)
        if not map_url:
            return None
        
        logger.debug(f"Found sourcemap for {js_url}: {map_url}")
        sourcemap_data = self.fetch_sourcemap(map_url)
        
        if sourcemap_data:
            self.sourcemaps[js_url] = {
                'map_url': map_url,
                'data': sourcemap_data,
                'js_url': js_url
            }
            return self.sourcemaps[js_url]
        
        return None
    
    def map_location(self, js_url: str, line: int, column: int) -> Optional[Dict]:
        """Map a minified location (line, column) to original source location"""
        if js_url not in self.sourcemaps:
            return None
        
        if not SOURCEMAP_AVAILABLE:
            logger.warning("sourcemap library not available, cannot map locations")
            return None
        
        try:
            sourcemap_data = self.sourcemaps[js_url]['data']
            
            # Use sourcemap library to decode
            decoder = sourcemap.Decoder(sourcemap_data)
            
            # sourcemap uses 0-based indexing, but we have 1-based
            mapped = decoder.lookup(line - 1, column)
            
            if mapped:
                return {
                    'source': mapped.source,
                    'line': mapped.line + 1,  # Convert back to 1-based
                    'column': mapped.column + 1,
                    'name': mapped.name
                }
        except Exception as e:
            logger.debug(f"Error mapping location: {e}")
        
        return None
    
    def get_sources(self, js_url: str) -> List[str]:
        """Get list of original source files from sourcemap"""
        if js_url not in self.sourcemaps:
            return []
        
        sourcemap_data = self.sourcemaps[js_url]['data']
        return sourcemap_data.get('sources', [])
    
    def get_source_content(self, js_url: str, source_file: str) -> Optional[str]:
        """Get original source content from sourcemap if available"""
        if js_url not in self.sourcemaps:
            return None
        
        sourcemap_data = self.sourcemaps[js_url]['data']
        sources = sourcemap_data.get('sources', [])
        sources_content = sourcemap_data.get('sourcesContent', [])
        
        try:
            idx = sources.index(source_file)
            if idx < len(sources_content):
                return sources_content[idx]
        except (ValueError, IndexError):
            pass
        
        return None

