"""
Hybrid analysis: merges static, dynamic, and sourcemap discoveries
"""
import re
import logging
from typing import Dict, List, Set
from urllib.parse import urlparse, urlunparse, parse_qs
from collections import defaultdict

logger = logging.getLogger(__name__)


class HybridAnalyzer:
    """Merges static, dynamic, and sourcemap analysis results"""
    
    def __init__(self, sourcemap_handler=None):
        self.sourcemap_handler = sourcemap_handler
    
    def normalize_url(self, url: str) -> tuple:
        """Normalize URL to (scheme, netloc, path_template, query_keys)"""
        parsed = urlparse(url)
        
        # Extract path and try to parameterize numeric segments
        path_parts = parsed.path.split('/')
        path_template_parts = []
        
        for part in path_parts:
            if part.isdigit():
                path_template_parts.append('{id}')
            elif re.match(r'^[a-f0-9]{8,}$', part, re.IGNORECASE):  # UUID-like
                path_template_parts.append('{uuid}')
            else:
                path_template_parts.append(part)
        
        path_template = '/'.join(path_template_parts)
        
        # Extract query parameter keys
        query_keys = sorted(parse_qs(parsed.query).keys()) if parsed.query else []
        
        return (
            parsed.scheme,
            parsed.netloc,
            path_template,
            tuple(query_keys)
        )
    
    def infer_path_params(self, url: str) -> Dict[str, str]:
        """Infer path parameters from URL"""
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        params = {}
        
        for i, part in enumerate(path_parts):
            if part.isdigit():
                params[f'param_{i}'] = {'type': 'integer', 'example': part}
            elif re.match(r'^[a-f0-9]{8,}$', part, re.IGNORECASE):
                params[f'param_{i}'] = {'type': 'string', 'format': 'uuid', 'example': part}
            elif part and part not in ('', 'api', 'v1', 'v2'):
                # Could be a named param
                pass
        
        return params
    
    def detect_auth(self, request: Dict) -> Dict:
        """Detect authentication method from request"""
        headers = request.get('headers', {})
        auth_info = {
            'type': 'none',
            'detected': False
        }
        
        # Check for Bearer token
        if 'authorization' in headers:
            auth_val = headers['authorization']
            if auth_val.startswith('Bearer '):
                auth_info = {
                    'type': 'bearer',
                    'detected': True,
                    'token_present': True
                }
            elif auth_val.startswith('Basic '):
                auth_info = {
                    'type': 'basic',
                    'detected': True
                }
        
        # Check for API key in headers
        api_key_headers = ['x-api-key', 'api-key', 'x-auth-token']
        for key_header in api_key_headers:
            if key_header in headers:
                auth_info = {
                    'type': 'api_key',
                    'detected': True,
                    'header': key_header
                }
                break
        
        # Check for cookies
        if 'cookie' in headers:
            auth_info['cookies'] = True
        
        return auth_info
    
    def detect_graphql(self, request: Dict) -> bool:
        """Detect if request is GraphQL"""
        headers = request.get('headers', {})
        content_type = headers.get('content-type', '').lower()
        
        if 'application/json' in content_type:
            post_data = request.get('post_data')
            if post_data:
                try:
                    import json
                    data = json.loads(post_data)
                    if 'query' in data or 'mutation' in data:
                        return True
                except:
                    pass
        
        return False
    
    def infer_schema(self, body: str) -> Dict:
        """Infer JSON schema from request/response body"""
        if not body:
            return {}
        
        try:
            import json
            data = json.loads(body)
            return self._infer_json_schema(data)
        except:
            return {}
    
    def _infer_json_schema(self, data, depth=0) -> Dict:
        """Recursively infer JSON schema"""
        if depth > 3:  # Limit recursion
            return {'type': 'object'}
        
        if isinstance(data, dict):
            schema = {
                'type': 'object',
                'properties': {}
            }
            for key, value in data.items():
                schema['properties'][key] = self._infer_json_schema(value, depth + 1)
            return schema
        elif isinstance(data, list):
            if data:
                return {
                    'type': 'array',
                    'items': self._infer_json_schema(data[0], depth + 1)
                }
            return {'type': 'array'}
        elif isinstance(data, bool):
            return {'type': 'boolean'}
        elif isinstance(data, int):
            return {'type': 'integer'}
        elif isinstance(data, float):
            return {'type': 'number'}
        elif isinstance(data, str):
            return {'type': 'string'}
        else:
            return {'type': 'string'}
    
    def merge(self, static_results: Dict, dynamic_results: Dict, sourcemap_data: Dict = None) -> Dict:
        """Merge static, dynamic, and sourcemap results"""
        logger.info("[+] Merging static and dynamic discoveries...")
        
        # Group endpoints by normalized URL + method
        endpoint_groups = defaultdict(lambda: {
            'url_examples': [],
            'methods': set(),
            'sources': [],
            'static_findings': [],
            'dynamic_requests': [],
            'websocket_traces': []
        })
        
        # Process static findings
        for finding in static_results.get('endpoints', []):
            url = finding['url']
            method = finding.get('method', 'GET')
            normalized = self.normalize_url(url)
            
            key = (normalized, method)
            endpoint_groups[key]['url_examples'].append(url)
            endpoint_groups[key]['methods'].add(method)
            endpoint_groups[key]['static_findings'].append(finding)
            
            # Add sourcemap mapping if available
            source_ref = f"static:{finding.get('type', 'unknown')}@{finding.get('source', 'unknown')}:{finding.get('line', 0)}"
            if self.sourcemap_handler:
                mapped = self.sourcemap_handler.map_location(
                    finding.get('source', ''),
                    finding.get('line', 0),
                    finding.get('column', 0)
                )
                if mapped:
                    source_ref += f" -> {mapped['source']}:{mapped['line']}"
            
            endpoint_groups[key]['sources'].append(source_ref)
        
        # Process dynamic requests
        for req in dynamic_results.get('requests', []):
            url = req['url']
            method = req.get('method', 'GET')
            
            # Skip data URLs and browser internals
            if url.startswith(('data:', 'blob:', 'chrome-extension:')):
                continue
            
            normalized = self.normalize_url(url)
            key = (normalized, method)
            
            endpoint_groups[key]['url_examples'].append(url)
            endpoint_groups[key]['methods'].add(method)
            endpoint_groups[key]['dynamic_requests'].append(req)
            endpoint_groups[key]['sources'].append(f"dynamic:request#{req.get('id', 'unknown')}")
        
        # Process WebSocket traces
        for ws in dynamic_results.get('websockets', []):
            url = ws['url']
            normalized = self.normalize_url(url)
            key = (normalized, 'WS')
            
            endpoint_groups[key]['url_examples'].append(url)
            endpoint_groups[key]['methods'].add('WS')
            endpoint_groups[key]['websocket_traces'].append(ws)
            endpoint_groups[key]['sources'].append(f"dynamic:websocket#{ws.get('id', 'unknown')}")
        
        # Build merged endpoints
        merged_endpoints = []
        
        for (normalized, method), group in endpoint_groups.items():
            scheme, netloc, path_template, query_keys = normalized
            
            # Get most common URL as example
            url_examples = list(set(group['url_examples']))
            primary_url = url_examples[0] if url_examples else ''
            
            # Determine primary method
            methods = list(group['methods'])
            primary_method = method if method in methods else methods[0] if methods else 'GET'
            
            # Get request/response schemas from dynamic data
            request_schema = {}
            response_schema = {}
            auth_info = {'type': 'none', 'detected': False}
            is_graphql = False
            
            if group['dynamic_requests']:
                # Use first dynamic request for schema inference
                req = group['dynamic_requests'][0]
                if req.get('post_data'):
                    request_schema = self.infer_schema(req['post_data'])
                
                # Find matching response
                for resp in dynamic_results.get('responses', []):
                    if resp.get('request_id') == req.get('id'):
                        if resp.get('body'):
                            response_schema = self.infer_schema(resp['body'])
                        break
                
                auth_info = self.detect_auth(req)
                is_graphql = self.detect_graphql(req)
            
            # Build endpoint record
            endpoint = {
                'id': f"ep_{len(merged_endpoints):04d}",
                'path': path_template,
                'url_examples': url_examples[:5],  # Limit to 5 examples
                'method': primary_method,
                'methods': methods,
                'sources': list(set(group['sources'])),
                'request_schema': request_schema,
                'response_schema': response_schema,
                'auth': auth_info,
                'path_params': self.infer_path_params(primary_url),
                'static_count': len(group['static_findings']),
                'dynamic_count': len(group['dynamic_requests']),
                'websocket_messages': len([m for ws in group['websocket_traces'] for m in ws.get('messages', [])])
            }
            
            if is_graphql:
                endpoint['notes'] = 'GraphQL endpoint detected'
            
            merged_endpoints.append(endpoint)
        
        logger.info(f"[+] Merged {len(merged_endpoints)} unique endpoints")
        
        return {
            'merged_endpoints': merged_endpoints,
            'summary': {
                'total_static': len(static_results.get('endpoints', [])),
                'total_dynamic': len(dynamic_results.get('requests', [])),
                'total_websockets': len(dynamic_results.get('websockets', [])),
                'total_merged': len(merged_endpoints)
            }
        }

