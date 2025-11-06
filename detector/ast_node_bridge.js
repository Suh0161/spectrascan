#!/usr/bin/env node
/**
 * AST-based JavaScript endpoint extraction
 * Uses acorn to parse JS and extract fetch, axios, WebSocket, etc. calls
 * 
 * Usage: node ast_node_bridge.js <js_file_path>
 * Output: JSON array of discovered endpoints
 */

const fs = require('fs');
const path = require('path');

// Try to use acorn, fallback to basic regex if not available
let acorn, walk;

try {
    acorn = require('acorn');
    walk = require('acorn-walk');
} catch (e) {
    console.error('Error: acorn and acorn-walk are required. Install with: npm install acorn acorn-walk');
    process.exit(1);
}

function extractEndpoints(jsContent, filePath) {
    const results = [];
    
    try {
        // Parse with modern JS features
        const ast = acorn.parse(jsContent, {
            ecmaVersion: 2022,
            sourceType: 'module',
            locations: true
        });
        
        walk.simple(ast, {
            CallExpression(node) {
                // fetch() calls
                if (node.callee && node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
                    const arg = node.arguments[0];
                    if (arg) {
                        const url = extractStringValue(arg);
                        if (url) {
                            results.push({
                                type: 'fetch',
                                url: url,
                                method: 'GET', // fetch defaults to GET
                                line: node.loc.start.line,
                                column: node.loc.start.column
                            });
                        }
                    }
                }
                
                // axios.get(), axios.post(), etc.
                if (node.callee && node.callee.type === 'MemberExpression') {
                    const obj = node.callee.object;
                    const prop = node.callee.property;
                    
                    if (obj && obj.type === 'Identifier' && obj.name === 'axios' && prop) {
                        const method = prop.name.toUpperCase();
                        const arg = node.arguments[0];
                        if (arg) {
                            const url = extractStringValue(arg);
                            if (url) {
                                results.push({
                                    type: 'axios',
                                    url: url,
                                    method: method,
                                    line: node.loc.start.line,
                                    column: node.loc.start.column
                                });
                            }
                        }
                    }
                }
                
                // axios({ url: '...', method: '...' })
                if (node.callee && node.callee.type === 'Identifier' && node.callee.name === 'axios') {
                    const arg = node.arguments[0];
                    if (arg && arg.type === 'ObjectExpression') {
                        const url = extractObjectProperty(arg, 'url');
                        const method = extractObjectProperty(arg, 'method') || 'GET';
                        if (url) {
                            results.push({
                                type: 'axios',
                                url: url,
                                method: method.toUpperCase(),
                                line: node.loc.start.line,
                                column: node.loc.start.column
                            });
                        }
                    }
                }
                
                // new WebSocket(url)
                if (node.callee && node.callee.type === 'NewExpression' && 
                    node.callee.callee && node.callee.callee.type === 'Identifier' && 
                    node.callee.callee.name === 'WebSocket') {
                    const arg = node.callee.arguments[0];
                    if (arg) {
                        const url = extractStringValue(arg);
                        if (url) {
                            results.push({
                                type: 'websocket',
                                url: url,
                                method: 'WS',
                                line: node.loc.start.line,
                                column: node.loc.start.column
                            });
                        }
                    }
                }
                
                // new EventSource(url)
                if (node.callee && node.callee.type === 'NewExpression' && 
                    node.callee.callee && node.callee.callee.type === 'Identifier' && 
                    node.callee.callee.name === 'EventSource') {
                    const arg = node.callee.arguments[0];
                    if (arg) {
                        const url = extractStringValue(arg);
                        if (url) {
                            results.push({
                                type: 'sse',
                                url: url,
                                method: 'GET',
                                line: node.loc.start.line,
                                column: node.loc.start.column
                            });
                        }
                    }
                }
            },
            
            // XMLHttpRequest.open(method, url)
            ExpressionStatement(node) {
                if (node.expression && node.expression.type === 'CallExpression') {
                    const callee = node.expression.callee;
                    if (callee && callee.type === 'MemberExpression' && 
                        callee.property && callee.property.name === 'open') {
                        const obj = callee.object;
                        if (obj && (obj.type === 'Identifier' && obj.name === 'xhr') ||
                            (obj.type === 'MemberExpression' && 
                             obj.property && obj.property.name === 'XMLHttpRequest')) {
                            const args = node.expression.arguments;
                            if (args.length >= 2) {
                                const method = extractStringValue(args[0]);
                                const url = extractStringValue(args[1]);
                                if (method && url) {
                                    results.push({
                                        type: 'xhr',
                                        url: url,
                                        method: method.toUpperCase(),
                                        line: node.loc.start.line,
                                        column: node.loc.start.column
                                    });
                                }
                            }
                        }
                    }
                }
            }
        });
    } catch (e) {
        // If AST parsing fails, return empty results
        console.error(`AST parsing error for ${filePath}: ${e.message}`);
    }
    
    return results;
}

function extractStringValue(node) {
    if (node.type === 'Literal' && typeof node.value === 'string') {
        return node.value;
    }
    if (node.type === 'TemplateLiteral') {
        // Simple case: template literal with no expressions
        if (node.expressions.length === 0 && node.quasis.length > 0) {
            return node.quasis[0].value.cooked;
        }
    }
    return null;
}

function extractObjectProperty(node, propName) {
    if (node.type !== 'ObjectExpression') {
        return null;
    }
    
    for (const prop of node.properties) {
        if (prop.key && prop.key.name === propName) {
            return extractStringValue(prop.value);
        }
    }
    
    return null;
}

// Main execution
if (process.argv.length < 3) {
    console.error('Usage: node ast_node_bridge.js <js_file_path>');
    process.exit(1);
}

const jsFilePath = process.argv[2];

if (!fs.existsSync(jsFilePath)) {
    console.error(`Error: File not found: ${jsFilePath}`);
    process.exit(1);
}

try {
    const jsContent = fs.readFileSync(jsFilePath, 'utf-8');
    const results = extractEndpoints(jsContent, jsFilePath);
    console.log(JSON.stringify(results, null, 2));
} catch (e) {
    console.error(`Error processing file: ${e.message}`);
    process.exit(1);
}

