"""
Output writing utilities: HAR export, API client generation
"""
import json
import logging
from typing import Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)


class HARWriter:
    """Writes HAR (HTTP Archive) format from network captures"""
    
    def generate(self, dynamic_results: Dict, base_url: str = None) -> Dict:
        """Generate HAR format from dynamic capture results"""
        logger.info("[+] Generating HAR file...")
        
        # HAR structure
        har = {
            'log': {
                'version': '1.2',
                'creator': {
                    'name': 'SpectraScan',
                    'version': '1.0.0'
                },
                'pages': [],
                'entries': []
            }
        }
        
        # Create page entry
        if base_url:
            har['log']['pages'].append({
                'startedDateTime': datetime.utcnow().isoformat() + 'Z',
                'id': 'page_1',
                'title': base_url,
                'pageTimings': {
                    'onContentLoad': -1,
                    'onLoad': -1
                }
            })
        
        # Convert requests/responses to HAR entries
        request_map = {req.get('id'): req for req in dynamic_results.get('requests', [])}
        
        for resp in dynamic_results.get('responses', []):
            req_id = resp.get('request_id')
            req = request_map.get(req_id)
            
            if not req:
                continue
            
            # Build HAR entry
            entry = {
                'pageref': 'page_1',
                'startedDateTime': datetime.utcnow().isoformat() + 'Z',
                'time': 100,  # Default timing
                'request': {
                    'method': req.get('method', 'GET'),
                    'url': req.get('url', ''),
                    'httpVersion': 'HTTP/1.1',
                    'headers': [{'name': k, 'value': v} for k, v in req.get('headers', {}).items()],
                    'queryString': [],
                    'cookies': [],
                    'headersSize': -1,
                    'bodySize': len(req.get('post_data', '')) if req.get('post_data') else -1
                },
                'response': {
                    'status': resp.get('status', 200),
                    'statusText': resp.get('status_text', 'OK'),
                    'httpVersion': 'HTTP/1.1',
                    'headers': [{'name': k, 'value': v} for k, v in resp.get('headers', {}).items()],
                    'cookies': [],
                    'content': {
                        'size': len(resp.get('body', '')) if resp.get('body') else -1,
                        'mimeType': resp.get('headers', {}).get('content-type', 'application/octet-stream')
                    },
                    'redirectURL': '',
                    'headersSize': -1,
                    'bodySize': len(resp.get('body', '')) if resp.get('body') else -1
                },
                'cache': {},
                'timings': {
                    'blocked': -1,
                    'dns': -1,
                    'connect': -1,
                    'send': 10,
                    'wait': 50,
                    'receive': 40
                }
            }
            
            # Add request body
            if req.get('post_data'):
                entry['request']['postData'] = {
                    'mimeType': req.get('headers', {}).get('content-type', 'application/json'),
                    'text': req.get('post_data')
                }
            
            # Add response body
            if resp.get('body'):
                entry['response']['content']['text'] = resp.get('body')
            
            har['log']['entries'].append(entry)
        
        logger.info(f"[+] Generated HAR with {len(har['log']['entries'])} entries")
        
        return har
    
    def write(self, har: Dict, output_path: str):
        """Write HAR to file"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(har, f, indent=2)
            logger.info(f"[+] Wrote HAR file to {output_path}")
        except Exception as e:
            logger.error(f"Failed to write HAR file: {e}")


class APIClientGenerator:
    """Generates Python API client from discovered endpoints"""
    
    def generate(self, endpoints: List[Dict], base_url: str = None) -> str:
        """Generate Python API client code"""
        logger.info(f"[+] Generating API client for {len(endpoints)} endpoints...")
        
        # Extract base URL
        if not base_url and endpoints:
            first_url = endpoints[0].get('url_examples', [None])[0]
            if first_url:
                from urllib.parse import urlparse
                parsed = urlparse(first_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        code_lines = [
            '"""',
            'Auto-generated API client from SpectraScan',
            'This is a stub client - implement authentication and error handling as needed',
            '"""',
            '',
            'import requests',
            'from typing import Optional, Dict, Any',
            'from urllib.parse import urljoin',
            '',
            '',
            'class APIClient:',
            '    """Generated API client for discovered endpoints"""',
            '',
            '    def __init__(self, base_url: str = None, api_key: str = None, bearer_token: str = None):',
            f'        self.base_url = base_url or "{base_url or "https://example.com"}"',
            '        self.session = requests.Session()',
            '',
            '        # Set up authentication',
            '        if bearer_token:',
            '            self.session.headers["Authorization"] = f"Bearer {bearer_token}"',
            '        if api_key:',
            '            self.session.headers["X-API-Key"] = api_key',
            '',
            ''
        ]
        
        # Generate methods for each endpoint
        for endpoint in endpoints:
            path = endpoint.get('path', '/')
            method = endpoint.get('method', 'GET').lower()
            operation_id = self._generate_method_name(path, method)
            
            # Method signature
            path_params = endpoint.get('path_params', {})
            param_list = []
            if path_params:
                for param_name in path_params.keys():
                    param_list.append(f"{param_name}: str")
            
            # Add body param for POST/PUT/PATCH
            if method in ['post', 'put', 'patch']:
                param_list.append('body: Optional[Dict[str, Any]] = None')
            
            param_str = ', '.join(param_list) if param_list else ''
            
            code_lines.append(f'    def {operation_id}(self{", " + param_str if param_str else ""}):')
            code_lines.append(f'        """{method.upper()} {path}"""')
            
            # Build URL
            url_code = f"url = urljoin(self.base_url, '{path}')"
            if path_params:
                for param_name in path_params.keys():
                    url_code = url_code.replace(f"{{{param_name}}}", f"{{{param_name}}}")
                    url_code = f"url = url.replace('{{{param_name}}}', {param_name})"
            
            code_lines.append(f'        {url_code}')
            code_lines.append('')
            
            # Make request
            if method in ['post', 'put', 'patch']:
                code_lines.append('        response = self.session.request(')
                code_lines.append(f"            method='{method.upper()}',")
                code_lines.append('            url=url,')
                code_lines.append('            json=body')
                code_lines.append('        )')
            else:
                code_lines.append(f"        response = self.session.{method}(url)")
            
            code_lines.append('        response.raise_for_status()')
            code_lines.append('        return response.json()')
            code_lines.append('')
        
        code = '\n'.join(code_lines)
        logger.info(f"[+] Generated API client with {len(endpoints)} methods")
        
        return code
    
    def _generate_method_name(self, path: str, method: str) -> str:
        """Generate Python method name from path and method"""
        # Clean path
        clean_path = path.replace('/', '_').replace('{', '').replace('}', '').strip('_')
        if not clean_path:
            clean_path = 'root'
        
        # Convert to snake_case
        import re
        clean_path = re.sub(r'[^a-zA-Z0-9_]', '_', clean_path)
        clean_path = re.sub(r'_+', '_', clean_path).strip('_')
        
        return f"{method}_{clean_path}"
    
    def write(self, code: str, output_path: str):
        """Write API client to file"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(code)
            logger.info(f"[+] Wrote API client to {output_path}")
        except Exception as e:
            logger.error(f"Failed to write API client: {e}")

