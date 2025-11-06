"""
Postman collection generation from discovered endpoints
"""
import json
import logging
from typing import Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class PostmanGenerator:
    """Generates Postman collection from discovered endpoints"""
    
    def __init__(self, name: str = "SpectraScan Discovered API"):
        self.name = name
    
    def generate(self, endpoints: List[Dict], base_url: str = None) -> Dict:
        """Generate Postman collection"""
        logger.info(f"[+] Generating Postman collection for {len(endpoints)} endpoints...")
        
        # Extract base URL
        if not base_url and endpoints:
            first_url = endpoints[0].get('url_examples', [None])[0]
            if first_url:
                parsed = urlparse(first_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Group endpoints by path prefix (for folders)
        folders = {}
        
        for endpoint in endpoints:
            path = endpoint.get('path', '/')
            method = endpoint.get('method', 'GET')
            
            # Extract folder name (first path segment)
            path_parts = [p for p in path.split('/') if p and not p.startswith('{')]
            folder_name = path_parts[0] if path_parts else 'root'
            
            if folder_name not in folders:
                folders[folder_name] = []
            
            # Build request
            request = {
                'name': f"{method} {path}",
                'request': {
                    'method': method,
                    'header': [],
                    'url': {
                        'raw': '{{base_url}}' + path,
                        'host': ['{{base_url}}'],
                        'path': path.split('/')[1:]  # Remove leading /
                    }
                }
            }
            
            # Add path variables
            path_params = endpoint.get('path_params', {})
            if path_params:
                request['request']['url']['variable'] = []
                for param_name, param_spec in path_params.items():
                    request['request']['url']['variable'].append({
                        'key': param_name,
                        'value': param_spec.get('example', ''),
                        'type': 'string'
                    })
            
            # Add request body for POST/PUT/PATCH
            if method in ['POST', 'PUT', 'PATCH']:
                request_schema = endpoint.get('request_schema', {})
                if request_schema:
                    request['request']['body'] = {
                        'mode': 'raw',
                        'raw': json.dumps({}, indent=2),
                        'options': {
                            'raw': {
                                'language': 'json'
                            }
                        }
                    }
            
            # Add auth if detected
            auth = endpoint.get('auth', {})
            if auth.get('detected'):
                if auth.get('type') == 'bearer':
                    request['request']['auth'] = {
                        'type': 'bearer',
                        'bearer': [
                            {
                                'key': 'token',
                                'value': '{{bearer_token}}',
                                'type': 'string'
                            }
                        ]
                    }
                elif auth.get('type') == 'api_key':
                    header_name = auth.get('header', 'X-API-Key')
                    request['request']['header'].append({
                        'key': header_name,
                        'value': '{{api_key}}',
                        'type': 'string'
                    })
            
            folders[folder_name].append(request)
        
        # Build collection structure
        items = []
        for folder_name, requests in folders.items():
            if len(requests) == 1:
                # Single request, no folder needed
                items.append(requests[0])
            else:
                # Multiple requests, create folder
                items.append({
                    'name': folder_name,
                    'item': requests
                })
        
        collection = {
            'info': {
                'name': self.name,
                'description': 'Auto-generated Postman collection from SpectraScan',
                'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
            },
            'item': items,
            'variable': [
                {
                    'key': 'base_url',
                    'value': base_url or 'https://example.com',
                    'type': 'string'
                }
            ]
        }
        
        # Add auth variables if needed
        has_bearer = any(ep.get('auth', {}).get('type') == 'bearer' for ep in endpoints)
        has_api_key = any(ep.get('auth', {}).get('type') == 'api_key' for ep in endpoints)
        
        if has_bearer:
            collection['variable'].append({
                'key': 'bearer_token',
                'value': '',
                'type': 'string'
            })
        
        if has_api_key:
            collection['variable'].append({
                'key': 'api_key',
                'value': '',
                'type': 'string'
            })
        
        logger.info(f"[+] Generated Postman collection with {len(items)} items")
        
        return collection
    
    def write(self, collection: Dict, output_path: str):
        """Write Postman collection to file"""
        try:
            with open(output_path, 'w') as f:
                json.dump(collection, f, indent=2)
            logger.info(f"[+] Wrote Postman collection to {output_path}")
        except Exception as e:
            logger.error(f"Failed to write Postman collection: {e}")

