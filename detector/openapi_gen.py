"""
OpenAPI v3 specification generation from discovered endpoints
"""
import json
import logging
from typing import Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class OpenAPIGenerator:
    """Generates OpenAPI v3 specification from discovered endpoints"""
    
    def __init__(self, title: str = "Discovered API", version: str = "1.0.0"):
        self.title = title
        self.version = version
    
    def generate(self, endpoints: List[Dict], base_url: str = None) -> Dict:
        """Generate OpenAPI v3 specification"""
        logger.info(f"[+] Generating OpenAPI spec for {len(endpoints)} endpoints...")
        
        # Extract base URL from first endpoint if not provided
        if not base_url and endpoints:
            first_url = endpoints[0].get('url_examples', [None])[0]
            if first_url:
                parsed = urlparse(first_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        spec = {
            'openapi': '3.0.0',
            'info': {
                'title': self.title,
                'version': self.version,
                'description': 'Auto-generated API specification from SpectraScan discovery'
            },
            'servers': [
                {
                    'url': base_url or 'https://example.com',
                    'description': 'Discovered server'
                }
            ],
            'paths': {}
        }
        
        # Group endpoints by path
        paths = {}
        
        for endpoint in endpoints:
            path = endpoint.get('path', '/')
            method = endpoint.get('method', 'GET').lower()
            
            if path not in paths:
                paths[path] = {}
            
            operation = {
                'operationId': self._generate_operation_id(path, method),
                'summary': f"{method.upper()} {path}",
                'tags': self._extract_tags(path)
            }
            
            # Add path parameters
            path_params = endpoint.get('path_params', {})
            if path_params:
                operation['parameters'] = []
                for param_name, param_spec in path_params.items():
                    operation['parameters'].append({
                        'name': param_name,
                        'in': 'path',
                        'required': True,
                        'schema': {
                            'type': param_spec.get('type', 'string')
                        },
                        'example': param_spec.get('example')
                    })
            
            # Add request body for POST/PUT/PATCH
            if method in ['post', 'put', 'patch']:
                request_schema = endpoint.get('request_schema', {})
                if request_schema:
                    operation['requestBody'] = {
                        'required': True,
                        'content': {
                            'application/json': {
                                'schema': request_schema
                            }
                        }
                    }
                else:
                    # Default empty object
                    operation['requestBody'] = {
                        'required': True,
                        'content': {
                            'application/json': {
                                'schema': {'type': 'object'}
                            }
                        }
                    }
            
            # Add responses
            response_schema = endpoint.get('response_schema', {})
            operation['responses'] = {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'schema': response_schema if response_schema else {'type': 'object'}
                        }
                    }
                },
                'default': {
                    'description': 'Error'
                }
            }
            
            # Add security if auth detected
            auth = endpoint.get('auth', {})
            if auth.get('detected'):
                if auth.get('type') == 'bearer':
                    operation['security'] = [{'bearerAuth': []}]
                elif auth.get('type') == 'api_key':
                    operation['security'] = [{'apiKeyAuth': []}]
            
            # Add notes
            if endpoint.get('notes'):
                operation['description'] = endpoint.get('notes')
            
            paths[path][method] = operation
        
        spec['paths'] = paths
        
        # Add security schemes
        security_schemes = {}
        has_bearer = any(ep.get('auth', {}).get('type') == 'bearer' for ep in endpoints)
        has_api_key = any(ep.get('auth', {}).get('type') == 'api_key' for ep in endpoints)
        
        if has_bearer:
            security_schemes['bearerAuth'] = {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT'
            }
        
        if has_api_key:
            security_schemes['apiKeyAuth'] = {
                'type': 'apiKey',
                'in': 'header',
                'name': 'X-API-Key'
            }
        
        if security_schemes:
            spec['components'] = {'securitySchemes': security_schemes}
        
        logger.info(f"[+] Generated OpenAPI spec with {len(paths)} paths")
        
        return spec
    
    def _generate_operation_id(self, path: str, method: str) -> str:
        """Generate operation ID from path and method"""
        # Clean path: remove params, slashes, special chars
        clean_path = path.replace('/', '_').replace('{', '').replace('}', '').strip('_')
        if not clean_path:
            clean_path = 'root'
        return f"{method}_{clean_path}"
    
    def _extract_tags(self, path: str) -> List[str]:
        """Extract tags from path"""
        parts = [p for p in path.split('/') if p and not p.startswith('{')]
        if parts:
            return [parts[0]]  # Use first path segment as tag
        return ['default']
    
    def write_yaml(self, spec: Dict, output_path: str):
        """Write OpenAPI spec as YAML"""
        try:
            import yaml
            with open(output_path, 'w') as f:
                yaml.dump(spec, f, default_flow_style=False, sort_keys=False)
            logger.info(f"[+] Wrote OpenAPI spec to {output_path}")
        except ImportError:
            logger.warning("PyYAML not installed, writing JSON instead")
            with open(output_path.replace('.yaml', '.json').replace('.yml', '.json'), 'w') as f:
                json.dump(spec, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write OpenAPI spec: {e}")

