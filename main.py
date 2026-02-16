import os
import json
from fastapi import FastAPI, Depends, HTTPException, Query, status, Request, Response, File, UploadFile
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import requests
import models
import auth
import shutil
from database import engine, get_db, DB_URL, SessionLocal
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from typing import List, Optional
import logging
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# Create database tables (serverless-safe)
try:
    models.Base.metadata.create_all(bind=engine)
except Exception as e:
    # Log but don't crash on serverless environments
    print(f"Warning: Database initialization issue: {e}")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Premium Proxy API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS Middleware for stability
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Static Files
if not os.path.exists("static"):
    os.makedirs("static")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Global Exception Handler - serverless compatible (no file writes)
import traceback
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_msg = traceback.format_exc()
    # Log to stdout for Vercel logs
    print(f"\n--- ERROR {datetime.utcnow()} ---")
    print(error_msg)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "error": str(exc)},
    )

# Initialize database on first access (lazy loading for serverless)
_db_initialized = False

def ensure_db_initialized():
    """Initialize database with default admin user and settings - called on demand"""
    global _db_initialized
    if _db_initialized:
        return
    
    try:
        db = SessionLocal()
        try:
            admin_user = db.query(models.User).filter(models.User.username == "admin").first()
            if not admin_user:
                hashed_pw = auth.get_password_hash("admin123")
                new_admin = models.User(username="admin", hashed_password=hashed_pw)
                db.add(new_admin)
                db.commit()
            
            settings = db.query(models.Settings).first()
            if not settings:
                new_settings = models.Settings()
                db.add(new_settings)
                db.commit()
            
            # Create a default 'num' endpoint if it doesn't exist
            num_endpoint = db.query(models.Endpoint).filter(models.Endpoint.path == "num").first()
            if not num_endpoint:
                new_ep = models.Endpoint(
                    path="num",
                    source_url_template="https://invalid-num-info.vercel.app/api/lund?number={number}",
                    description="Default Number Lookup API"
                )
                db.add(new_ep)
                db.commit()
            
            _db_initialized = True
        finally:
            db.close()
    except Exception as e:
        print(f"Warning: Database initialization failed: {e}")

@app.get("/")
def read_root():
    # STEALTH MODE
    raise HTTPException(status_code=404, detail="Not Found")

def self_ping():
    """Ping own health endpoint to prevent Render sleep"""
    try:
        # Get the deployed URL from environment or use localhost for dev
        base_url = os.getenv("RENDER_EXTERNAL_URL") or "http://localhost:8000"
        response = requests.get(f"{base_url}/health", timeout=10)
        print(f"[Keep-Alive] Self-ping: {response.status_code} at {datetime.utcnow()}")
    except Exception as e:
        print(f"[Keep-Alive] Self-ping failed: {e}")

def start_keep_alive():
    """Start background scheduler for keep-alive"""
    scheduler = BackgroundScheduler()
    # Ping every 10 minutes (Render sleeps after 15 min)
    scheduler.add_job(self_ping, 'interval', minutes=10)
    scheduler.start()
    print("[Keep-Alive] Started - will ping every 10 minutes")

# Start keep-alive on app startup
try:
    start_keep_alive()
except Exception as e:
    print(f"[Keep-Alive] Failed to start: {e}")

# --- Pydantic Models ---
class ApiKeyCreate(BaseModel):
    key: str
    description: Optional[str] = None
    expiry_days: Optional[int] = None
    endpoint_id: int

class EndpointCreate(BaseModel):
    path: str
    source_url_template: str
    description: Optional[str] = None

class KeyUpdate(BaseModel):
    expiry_days: Optional[int] = None
    is_active: Optional[bool] = None

class PasswordUpdate(BaseModel):
    new_password: str

# --- Middleware ---

@app.middleware("http")
async def traffic_logger(request: Request, call_next):
    start_time = datetime.utcnow()
    
    # Process request
    response = await call_next(request)
    
    # Calculate latency
    process_time = (datetime.utcnow() - start_time).total_seconds() * 1000
    
    # Log to DB (background task to not block response)
    # We'll do it synchronously for simplicity here, or use BackgroundTasks
    try:
        # Only log API requests
        if request.url.path.startswith("/api/"):
            db = SessionLocal()
            log = models.RequestLog(
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                client_ip=request.client.host,
                latency_ms=int(process_time)
            )
            db.add(log)
            db.commit()
            db.close()
    except Exception as e:
        print(f"Logging failed: {e}")

    # Inject Branding if JSON
    if "application/json" in response.headers.get("content-type", ""):
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
            
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                data["developer_credits"] = "⚡ Developed by @InvalidAyush x @AyushIsInvalid 🔥"
                # Re-serialize
                modified_body = json.dumps(data).encode("utf-8")
                response.headers["content-length"] = str(len(modified_body))
                from fastapi.responses import Response
                return Response(content=modified_body, status_code=response.status_code, 
                                media_type="application/json", headers=dict(response.headers))
        except:
            pass # Keep original if parsing fails
            
        # If not modified, return original body (need to re-stream)
        from fastapi.responses import Response
        return Response(content=body, status_code=response.status_code, 
                        media_type=response.media_type, headers=dict(response.headers))

    return response

# --- Auth Endpoints ---

@app.post("/token")
@limiter.limit("5/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ensure_db_initialized()  # Ensure admin user is created
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Endpoint Management ---

@app.get("/admin/endpoints")
async def list_endpoints(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    return db.query(models.Endpoint).all()

@app.post("/admin/endpoints")
async def create_endpoint(data: EndpointCreate, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    # Check if path already exists
    existing = db.query(models.Endpoint).filter(models.Endpoint.path == data.path).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"The path '{data.path}' is already in use. Please use a unique identifier.")
    
    new_ep = models.Endpoint(**data.dict())
    db.add(new_ep)
    db.commit()
    return {"message": "Endpoint created"}

@app.put("/admin/endpoints/{ep_id}")
async def update_endpoint(ep_id: int, data: EndpointCreate, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    ep = db.query(models.Endpoint).filter(models.Endpoint.id == ep_id).first()
    if not ep: raise HTTPException(status_code=404)

    # Check if new path is taken by another endpoint
    other = db.query(models.Endpoint).filter(models.Endpoint.path == data.path, models.Endpoint.id != ep_id).first()
    if other:
        raise HTTPException(status_code=400, detail=f"The path '{data.path}' is already in use by another endpoint.")

    ep.path = data.path
    ep.source_url_template = data.source_url_template
    ep.description = data.description
    db.commit()
    return {"message": "Endpoint updated"}

@app.delete("/admin/endpoints/{ep_id}")
async def delete_endpoint(ep_id: int, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    ep = db.query(models.Endpoint).filter(models.Endpoint.id == ep_id).first()
    db.delete(ep)
    db.commit()
    return {"message": "Endpoint deleted"}

# --- Key Management ---

@app.get("/admin/keys")
async def list_keys(endpoint_id: Optional[int] = None, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    query = db.query(models.ApiKey)
    if endpoint_id:
        query = query.filter(models.ApiKey.endpoint_id == endpoint_id)
    keys = query.all()
    return [{
        "id": k.id, 
        "key": k.key, 
        "description": k.description, 
        "is_active": k.is_active, 
        "expiry_date": k.expiry_date, 
        "endpoint_path": k.endpoint.path if k.endpoint else "Deleted"
    } for k in keys]

@app.post("/admin/keys")
async def create_key(key_data: ApiKeyCreate, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    # Check if key already exists
    existing = db.query(models.ApiKey).filter(models.ApiKey.key == key_data.key).first()
    if existing:
        raise HTTPException(status_code=400, detail="This API key already exists. Please use a unique key.")

    expiry_date = None
    if key_data.expiry_days and key_data.expiry_days > 0:
        expiry_date = datetime.utcnow() + timedelta(days=key_data.expiry_days)
    
    new_key = models.ApiKey(
        key=key_data.key,
        description=key_data.description,
        expiry_date=expiry_date,
        endpoint_id=key_data.endpoint_id
    )
    db.add(new_key)
    db.commit()
    return {"message": "Key generated"}

@app.put("/admin/keys/{key_id}")
async def update_key(key_id: int, data: KeyUpdate, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    key = db.query(models.ApiKey).filter(models.ApiKey.id == key_id).first()
    if not key: raise HTTPException(status_code=404, detail="Key not found")

    if data.expiry_days is not None:
        if data.expiry_days <= 0:
            key.expiry_date = None # Lifetime
        else:
            key.expiry_date = datetime.utcnow() + timedelta(days=data.expiry_days)
    
    if data.is_active is not None:
        key.is_active = data.is_active

    db.commit()
    return {"message": "Key updated"}
    return {"message": "Key created successfully"}

@app.delete("/admin/keys/{key_id}")
async def delete_key(key_id: int, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    key = db.query(models.ApiKey).filter(models.ApiKey.id == key_id).first()
    if not key: raise HTTPException(status_code=404)
    db.delete(key)
    db.commit()
    return {"message": "Key deleted"}

@app.get("/admin/stats/logs")
async def get_traffic_logs(limit: int = 50, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    logs = db.query(models.RequestLog).order_by(models.RequestLog.timestamp.desc()).limit(limit).all()
    return logs

@app.post("/admin/change-password")
async def change_password(data: PasswordUpdate, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    current_user.hashed_password = auth.get_password_hash(data.new_password)
    db.commit()
    return {"message": "Password updated successfully"}

@app.get("/admin/backup")
async def backup_database(current_user: models.User = Depends(auth.get_current_user)):
    """Download the current database file"""
    db_path = "./database.db"
    return FileResponse(db_path, media_type="application/octet-stream", filename=f"backup_{datetime.now().strftime('%Y%m%d%H%M%S')}.db")

@app.post("/admin/restore")
async def restore_database(file: UploadFile = File(...), current_user: models.User = Depends(auth.get_current_user)):
    """Restore database from uploaded file"""
    try:
        location = "./database.db"
        with open(location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)
        return {"message": "Database restored successfully. Server needs restart to apply changes completely."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Admin Web Routes ---

@app.get("/Osint-Api/dashboard")
async def get_lund_dashboard_page():
    from fastapi.responses import FileResponse
    import os
    file_path = "static/Osint-Api/dashboard.html"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Dashboard not available")
    return FileResponse(file_path)

@app.get("/Osint-Api")
async def get_lund_admin_page():
    from fastapi.responses import FileResponse
    import os
    file_path = "static/Osint-Api/index.html"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Admin page not available")
    return FileResponse(file_path)

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring services (UptimeRobot, etc.)"""
    return {
        "status": "healthy",
        "message": "API is running",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/ping")
async def ping():
    """Simple ping endpoint to keep Render free tier awake"""
    return {"pong": True, "time": datetime.utcnow().isoformat()}

@app.get("/")
async def root():
    return {"message": "Premium Proxy API is active. Access /Osint-Api for admin."}

# Static files - mount only if directories exist (optional for serverless)
try:
    import os
    if os.path.exists("static/assets"):
        app.mount("/assets", StaticFiles(directory="static/assets"), name="assets")
    if os.path.exists("static"):
        app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception as e:
    print(f"Static files not mounted: {e}")

# --- Proxy Endpoint (Catch-All) ---
# Moved to end to allow matching specific routes primarily FIRST

@app.api_route("/{rest_of_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(rest_of_path: str, request: Request, key: str = Query(None, description="API Access Key")):
    # 0. Bypass internal routes (just in case)
    if rest_of_path.startswith("Osint-Api") or rest_of_path.startswith("static") or rest_of_path.startswith("admin"):
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    ensure_db_initialized()
    db = SessionLocal()
    try:
        # 1. Identify Endpoint Configuration
        # We look for a match at the START of the path
        endpoints = db.query(models.Endpoint).all()
        endpoint = None
        
        # Sort by length desc to match most specific path first
        endpoints.sort(key=lambda x: len(x.path), reverse=True)
        
        for ep in endpoints:
            # We check if path matches "/{ep.path}" or "/{ep.path}/..."
            # Clean slashes for comparison
            req_path_clean = rest_of_path.strip("/")
            ep_path_clean = ep.path.strip("/")
            
            if req_path_clean == ep_path_clean or req_path_clean.startswith(ep_path_clean + "/"):
                endpoint = ep
                break
        if not endpoint:
             if rest_of_path == "":
                  return JSONResponse(content={"message": "Premium Proxy is Running. Access /Osint-Api for Admin Panel."})
             raise HTTPException(status_code=404, detail="Proxy Endpoint Not Found")

        # --- PATH-BASED AUTHENTICATION LOGIC ---
        # User wants to pass key in path: /config_name/KEY/real_path
        path_segments = rest_of_path.strip("/").split("/")
        ep_segments = endpoint.path.strip("/").split("/")
        ep_len = len(ep_segments)
        
        # Check path for key EVEN IF query param 'key' exists.
        # This prevents target keys (e.g. ?key=lo) from blocking our detection of the real proxy key in the path.
        if len(path_segments) > ep_len:
            potential_key = path_segments[ep_len]
            valid_key = db.query(models.ApiKey).filter(models.ApiKey.key == potential_key, models.ApiKey.endpoint_id == endpoint.id).first()
            if valid_key:
                key = potential_key
                # Remove key from path
                new_segments = path_segments[:ep_len] + path_segments[ep_len+1:]
                rest_of_path = "/".join(new_segments)
        # ---------------------------------------

        # 1. Validate Key
        if not key:
            # If no key, maybe homepage or 404? 
            if rest_of_path == "":
                 return JSONResponse(content={"message": "Premium Proxy is Running. Access /Osint-Api for Admin Panel."})
            raise HTTPException(status_code=403, detail="API Key Required")

        api_key_record = db.query(models.ApiKey).filter(models.ApiKey.key == key).first()
        
        if not api_key_record:
            raise HTTPException(status_code=403, detail="Invalid API Key: Access Denied")
            
        if not api_key_record.is_active:
             raise HTTPException(status_code=403, detail="API Key is inactive or revoked")
             
        if api_key_record.expiry_date and api_key_record.expiry_date < datetime.utcnow():
             raise HTTPException(status_code=403, detail="API Key has expired")

        # 2. Get Target Source
        endpoint = api_key_record.endpoint
        if not endpoint:
            raise HTTPException(status_code=500, detail="Orphaned API Key (No linked config)")

        # 3. Construct Target URL with Advanced Logic
        template = endpoint.source_url_template
        
        # Robust Query Param Handling:
        # We need to handle duplicate keys (e.g. ?key=proxy_key&key=target_key)
        # We convert to a list of (k, v) tuples to preserve everything.
        all_params = request.query_params.multi_items()
        
        # Surgical extraction: Remove ONLY the key that was used for auth
        forward_params = []
        for k, v in all_params:
            if k == 'key' and v == key:
                continue # Skip the proxy auth key
            forward_params.append((k, v))
            
        # Convert back to dict for template merging (taking the last value for template vars is standard behavior)
        # But we will use forward_params for the final reconstruction to keep duplicates.
        query_params_dict = dict(all_params) 
            
        # A. Handle Placeholders (e.g., {number})
        placeholders = re.findall(r'\{(\w+)\}', template)
        used_params = set()
        
        for var in placeholders:
            if var in query_params_dict:
                val = query_params_dict[var]
                template = template.replace(f'{{{var}}}', str(val))
                used_params.add(var)
        
        # B. Parse Template URL
        parsed_template = urlparse(template)
        template_params = parse_qsl(parsed_template.query) # List of (k, v)
        
        # C. Merge Paths
        final_path = parsed_template.path
        
        # Intelligent Path Stripping: 
        ep_path_clean = endpoint.path.strip("/")
        ro_path_clean = rest_of_path.strip("/")
        
        path_to_append = ro_path_clean
        
        if ep_path_clean and ro_path_clean.startswith(ep_path_clean):
            if len(ro_path_clean) == len(ep_path_clean) or ro_path_clean[len(ep_path_clean)] == '/':
                path_to_append = ro_path_clean[len(ep_path_clean):].lstrip("/")
        
        if path_to_append:
            if final_path.endswith('/'):
                final_path += path_to_append
            else:
                final_path += '/' + path_to_append
        
        # D. Merge Query Parameters
        # Strategy: Start with template params, append request params (excluding used placeholders)
        # formatting: template_params is list of (k,v), forward_params is list of (k,v)
        
        final_qs_list = list(template_params)
        
        # If we have specific overrides from request, we might want to use them?
        # Actually, standard behavior for duplicate keys is usually to append.
        # But for 'merging', if a key exists in template, do we replace it? 
        # The user wants request to override template.
        
        # Let's rebuild the list carefully:
        # 1. Map template params for easy lookup/replacement if we wanted strict override
        # But since we support duplicates, we'll just append filtered request params.
        
        # Actually, to support "override", we should check if request provided a value.
        # If request provided 'mobile', we use that.
        
        # Simplified robust merge:
        # 1. Start with template params.
        # 2. If a key from template is ALSO in request (and not used in placeholder), request wins? 
        #    - Hard to say "wins" with duplicates. 
        #    - Current best bet: Keep template params unless exact key is in request?
        #    - Let's just append request params. If target api handles duplicates, good. 
        #    - If target API takes last, request (appended last) wins.
        
        # Filter forward_params to remove things we already consumed in placeholders?
        # The user's specific case: consumed placeholders ARE removed from URL, 
        # but if we used them in template, they shouldn't be duplicated in Query String? 
        # The previous code did `if k not in used_params`.
        
        for k, v in forward_params:
            if k not in used_params:
                 final_qs_list.append((k, v))
        
        # E. Reconstruct Final URL
        new_query = urlencode(final_qs_list)
        target_url = urlunparse((
            parsed_template.scheme,
            parsed_template.netloc,
            final_path,
            parsed_template.params,
            new_query,
            parsed_template.fragment
        ))
        
        # 4. Prepare Headers (params are now in target_url)
        params = {} 
        
        # Forward Headers
        excluded_request_headers = ['host', 'content-length', 'accept-encoding']
        headers = {
            k: v for k, v in request.headers.items() 
            if k.lower() not in excluded_request_headers
        }
        
        # 5. Make Request
        # Read body first
        body = await request.body()
        
        try:
            response = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Target Connection Failed: {str(e)}")
        
        # 6. Forward Response
        excluded_response_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = {
            k: v for k, v in response.headers.items() 
            if k.lower() not in excluded_response_headers
        }
        
        # CORS Handling
        response_headers['Access-Control-Allow-Origin'] = '*'
        
        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type"),
            headers=response_headers
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Proxy Error: {e}")
        raise HTTPException(status_code=500, detail=str(0))
    finally:
        db.close()

