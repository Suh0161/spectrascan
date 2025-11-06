"""
Dynamic runtime capture using Playwright
Captures network requests, WebSockets, and console logs
"""
import asyncio
import json
import time
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not installed. Dynamic capture disabled.")


class DynamicCapture:
    """Captures runtime network activity using Playwright"""
    
    def __init__(self, duration: int = 7, headful: bool = False, timeout: int = 30):
        self.duration = duration
        self.headful = headful
        self.timeout = timeout
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright is required. Install with: pip install playwright && playwright install")
    
    async def capture_runtime(self, url: str) -> Dict:
        """Capture runtime network activity"""
        results = {
            "requests": [],
            "responses": [],
            "websockets": [],
            "console": [],
            "errors": []
        }
        
        # Map request_id -> request data for pairing with responses
        request_map = {}
        
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=not self.headful,
                args=['--disable-blink-features=AutomationControlled']
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={'width': 1920, 'height': 1080}
            )
            page = await context.new_page()
            
            # Capture network requests
            def on_request(request):
                req_id = id(request)
                req_data = {
                    "id": req_id,
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "post_data": request.post_data,
                    "resource_type": request.resource_type,
                    "timestamp": time.time()
                }
                request_map[req_id] = req_data
                results["requests"].append(req_data)
            
            def on_response(response):
                req_id = id(response.request)
                resp_data = {
                    "request_id": req_id,
                    "url": response.url,
                    "status": response.status,
                    "status_text": response.status_text,
                    "headers": dict(response.headers),
                    "timestamp": time.time()
                }
                
                # Try to get response body (may fail for binary/large responses)
                # Note: We'll fetch body asynchronously after response is captured
                asyncio.create_task(self._get_response_body(response, resp_data))
                
                results["responses"].append(resp_data)
            
            page.on("request", on_request)
            page.on("response", on_response)
            
            # Capture WebSockets
            websocket_sessions = {}
            
            def on_websocket(ws):
                ws_id = id(ws)
                ws_info = {
                    "id": ws_id,
                    "url": ws.url,
                    "messages": [],
                    "timestamp": time.time()
                }
                websocket_sessions[ws_id] = ws_info
                
                def on_frame_received(frame):
                    try:
                        payload = frame.text if hasattr(frame, 'text') else frame.payload
                        ws_info["messages"].append({
                            "type": "received",
                            "payload": payload,
                            "timestamp": time.time()
                        })
                    except Exception:
                        pass
                
                def on_frame_sent(frame):
                    try:
                        payload = frame.text if hasattr(frame, 'text') else frame.payload
                        ws_info["messages"].append({
                            "type": "sent",
                            "payload": payload,
                            "timestamp": time.time()
                        })
                    except Exception:
                        pass
                
                ws.on("framereceived", on_frame_received)
                ws.on("framesent", on_frame_sent)
                results["websockets"].append(ws_info)
            
            page.on("websocket", on_websocket)
            
            # Capture console logs
            def on_console(msg):
                results["console"].append({
                    "type": msg.type,
                    "text": msg.text,
                    "timestamp": time.time()
                })
            
            page.on("console", on_console)
            
            # Capture page errors
            def on_page_error(error):
                results["errors"].append({
                    "message": str(error),
                    "timestamp": time.time()
                })
            
            page.on("pageerror", on_page_error)
            
            # Navigate and wait
            try:
                logger.info(f"[+] Navigating to {url}...")
                await page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
                logger.info(f"[+] Page loaded, waiting {self.duration}s for dynamic requests...")
                await asyncio.sleep(self.duration)
            except PlaywrightTimeoutError:
                logger.warning(f"Page load timeout, but continuing with captured data...")
            except Exception as e:
                logger.error(f"Error during page navigation: {e}")
                results["errors"].append({"message": str(e), "timestamp": time.time()})
            
            await browser.close()
        
        # Pair requests with responses
        for resp in results["responses"]:
            req_id = resp.get("request_id")
            if req_id in request_map:
                resp["request"] = request_map[req_id]
        
        logger.info(f"[+] Captured {len(results['requests'])} requests, "
                   f"{len(results['responses'])} responses, "
                   f"{len(results['websockets'])} websockets")
        
        return results
    
    async def _get_response_body(self, response, resp_data):
        """Asynchronously get response body"""
        try:
            body = await response.body()
            if len(body) < 1024 * 1024:  # Only for < 1MB
                try:
                    resp_data["body"] = body.decode('utf-8', errors='ignore')
                except Exception:
                    resp_data["body"] = "<binary>"
        except Exception:
            pass
    
    def run_capture(self, url: str) -> Dict:
        """Synchronous wrapper for capture_runtime"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.capture_runtime(url))

