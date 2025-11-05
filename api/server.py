from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext
import base64
import shutil

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT config
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

security = HTTPBearer()

# Create uploads directory
UPLOADS_DIR = ROOT_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

# Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    email: EmailStr
    password: str
    role: str = "admin"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Post(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str
    slug: str
    image: Optional[str] = None
    author_id: str
    author_name: str
    meta_title: Optional[str] = None
    meta_description: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class PostCreate(BaseModel):
    title: str
    content: str
    image: Optional[str] = None
    meta_title: Optional[str] = None
    meta_description: Optional[str] = None

class Pengurus(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    position: str
    photo: Optional[str] = None
    bio: str

class PengurusCreate(BaseModel):
    name: str
    position: str
    photo: Optional[str] = None
    bio: str

class Pengelola(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    role: str
    photo: Optional[str] = None
    bio: str

class PengelolaCreate(BaseModel):
    name: str
    role: str
    photo: Optional[str] = None
    bio: str

class ProfilDesa(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = "profil-desa"
    name: str
    description: str
    vision: str
    mission: str
    contact: str
    logo: Optional[str] = None

class ProfilDesaUpdate(BaseModel):
    name: str
    description: str
    vision: str
    mission: str
    contact: str
    logo: Optional[str] = None

class ContactMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    email: EmailStr
    message: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ContactMessageCreate(BaseModel):
    name: str
    email: EmailStr
    message: str

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_slug(title: str) -> str:
    slug = title.lower().replace(" ", "-")
    slug = "".join(c for c in slug if c.isalnum() or c == "-")
    return slug

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await db.users.find_one({"email": email}, {"_id": 0})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Auth routes
@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": user["email"]})
    return {
        "token": access_token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "name": current_user["name"],
        "email": current_user["email"],
        "role": current_user["role"]
    }

# Posts routes
@api_router.get("/posts")
async def get_posts(limit: Optional[int] = None, skip: int = 0):
    if limit:
        posts = await db.posts.find({}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    else:
        posts = await db.posts.find({}, {"_id": 0}).sort("created_at", -1).skip(skip).to_list(1000)
    total = await db.posts.count_documents({})
    return {"posts": posts, "total": total}

@api_router.get("/posts/{slug}")
async def get_post_by_slug(slug: str):
    post = await db.posts.find_one({"slug": slug}, {"_id": 0})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post

@api_router.post("/posts")
async def create_post(post_data: PostCreate, current_user: dict = Depends(get_current_user)):
    slug = create_slug(post_data.title)
    existing = await db.posts.find_one({"slug": slug})
    if existing:
        slug = f"{slug}-{str(uuid.uuid4())[:8]}"
    
    post = Post(
        **post_data.model_dump(),
        slug=slug,
        author_id=current_user["id"],
        author_name=current_user["name"]
    )
    await db.posts.insert_one(post.model_dump())
    return post

@api_router.put("/posts/{post_id}")
async def update_post(post_id: str, post_data: PostCreate, current_user: dict = Depends(get_current_user)):
    existing = await db.posts.find_one({"id": post_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Post not found")
    
    slug = create_slug(post_data.title)
    if slug != existing["slug"]:
        slug_exists = await db.posts.find_one({"slug": slug, "id": {"$ne": post_id}})
        if slug_exists:
            slug = f"{slug}-{str(uuid.uuid4())[:8]}"
    
    update_data = post_data.model_dump()
    update_data["slug"] = slug
    
    await db.posts.update_one({"id": post_id}, {"$set": update_data})
    updated = await db.posts.find_one({"id": post_id}, {"_id": 0})
    return updated

@api_router.delete("/posts/{post_id}")
async def delete_post(post_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.posts.delete_one({"id": post_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Post not found")
    return {"message": "Post deleted successfully"}

# Pengurus routes
@api_router.get("/pengurus", response_model=List[Pengurus])
async def get_pengurus():
    pengurus = await db.pengurus.find({}, {"_id": 0}).to_list(1000)
    return pengurus

@api_router.post("/pengurus")
async def create_pengurus(pengurus_data: PengurusCreate, current_user: dict = Depends(get_current_user)):
    pengurus = Pengurus(**pengurus_data.model_dump())
    await db.pengurus.insert_one(pengurus.model_dump())
    return pengurus

@api_router.put("/pengurus/{pengurus_id}")
async def update_pengurus(pengurus_id: str, pengurus_data: PengurusCreate, current_user: dict = Depends(get_current_user)):
    result = await db.pengurus.update_one({"id": pengurus_id}, {"$set": pengurus_data.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Pengurus not found")
    updated = await db.pengurus.find_one({"id": pengurus_id}, {"_id": 0})
    return updated

@api_router.delete("/pengurus/{pengurus_id}")
async def delete_pengurus(pengurus_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.pengurus.delete_one({"id": pengurus_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Pengurus not found")
    return {"message": "Pengurus deleted successfully"}

# Pengelola routes
@api_router.get("/pengelola", response_model=List[Pengelola])
async def get_pengelola():
    pengelola = await db.pengelola.find({}, {"_id": 0}).to_list(1000)
    return pengelola

@api_router.post("/pengelola")
async def create_pengelola(pengelola_data: PengelolaCreate, current_user: dict = Depends(get_current_user)):
    pengelola = Pengelola(**pengelola_data.model_dump())
    await db.pengelola.insert_one(pengelola.model_dump())
    return pengelola

@api_router.put("/pengelola/{pengelola_id}")
async def update_pengelola(pengelola_id: str, pengelola_data: PengelolaCreate, current_user: dict = Depends(get_current_user)):
    result = await db.pengelola.update_one({"id": pengelola_id}, {"$set": pengelola_data.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Pengelola not found")
    updated = await db.pengelola.find_one({"id": pengelola_id}, {"_id": 0})
    return updated

@api_router.delete("/pengelola/{pengelola_id}")
async def delete_pengelola(pengelola_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.pengelola.delete_one({"id": pengelola_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Pengelola not found")
    return {"message": "Pengelola deleted successfully"}

# Profil Desa routes
@api_router.get("/profil-desa")
async def get_profil_desa():
    profil = await db.profil_desa.find_one({"id": "profil-desa"}, {"_id": 0})
    if not profil:
        return None
    return profil

@api_router.put("/profil-desa")
async def update_profil_desa(profil_data: ProfilDesaUpdate, current_user: dict = Depends(get_current_user)):
    profil = ProfilDesa(**profil_data.model_dump())
    await db.profil_desa.update_one(
        {"id": "profil-desa"},
        {"$set": profil.model_dump()},
        upsert=True
    )
    return profil

# Contact messages routes
@api_router.get("/messages")
async def get_messages(current_user: dict = Depends(get_current_user)):
    messages = await db.messages.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return messages

@api_router.post("/messages")
async def create_message(message_data: ContactMessageCreate):
    message = ContactMessage(**message_data.model_dump())
    await db.messages.insert_one(message.model_dump())
    return message

@api_router.delete("/messages/{message_id}")
async def delete_message(message_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.messages.delete_one({"id": message_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Message not found")
    return {"message": "Message deleted successfully"}

# Upload route
@api_router.post("/upload")
async def upload_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    file_extension = file.filename.split(".")[-1]
    file_name = f"{uuid.uuid4()}.{file_extension}"
    file_path = UPLOADS_DIR / file_name
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    return {"url": f"/uploads/{file_name}"}

# Dashboard stats
@api_router.get("/dashboard/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    posts_count = await db.posts.count_documents({})
    pengurus_count = await db.pengurus.count_documents({})
    messages_count = await db.messages.count_documents({})
    
    return {
        "posts": posts_count,
        "pengurus": pengurus_count,
        "messages": messages_count
    }

# Include the router in the main app
app.include_router(api_router)

# Serve static files
app.mount("/uploads", StaticFiles(directory=str(UPLOADS_DIR)), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_db():
    # Create default admin user
    admin_exists = await db.users.find_one({"email": "admin@desa.id"})
    if not admin_exists:
        admin_user = User(
            name="Admin Desa",
            email="admin@desa.id",
            password=hash_password("admin123"),
            role="admin"
        )
        await db.users.insert_one(admin_user.model_dump())
        logger.info("Default admin user created")
    
    # Create sample data
    posts_count = await db.posts.count_documents({})
    if posts_count == 0:
        admin = await db.users.find_one({"email": "admin@desa.id"})
        sample_posts = [
            {
                "title": "Program Posyandu Bulan Ini",
                "content": "Posyandu akan dilaksanakan pada tanggal 15 bulan ini. Semua ibu dan balita diharapkan hadir untuk pemeriksaan kesehatan rutin.",
                "image": "https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?w=800"
            },
            {
                "title": "Gotong Royong Membersihkan Lingkungan",
                "content": "Mari kita bersama-sama menjaga kebersihan lingkungan desa kita. Kegiatan gotong royong akan dilaksanakan setiap hari Minggu.",
                "image": "https://images.unsplash.com/photo-1559027615-cd4628902d4a?w=800"
            },
            {
                "title": "Pelatihan Kewirausahaan untuk Pemuda",
                "content": "Desa mengadakan pelatihan kewirausahaan gratis untuk pemuda desa. Pendaftaran dibuka hingga akhir bulan ini.",
                "image": "https://images.unsplash.com/photo-1552664730-d307ca884978?w=800"
            }
        ]
        
        for post_data in sample_posts:
            post = Post(
                **post_data,
                slug=create_slug(post_data["title"]),
                author_id=admin["id"],
                author_name=admin["name"]
            )
            await db.posts.insert_one(post.model_dump())
        
        logger.info("Sample posts created")
    
    # Create sample pengurus
    pengurus_count = await db.pengurus.count_documents({})
    if pengurus_count == 0:
        sample_pengurus = [
            {
                "name": "Budi Santoso",
                "position": "Kepala Desa",
                "photo": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=300",
                "bio": "Kepala desa yang berdedikasi untuk kemajuan desa."
            },
            {
                "name": "Siti Aminah",
                "position": "Sekretaris Desa",
                "photo": "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=300",
                "bio": "Mengelola administrasi desa dengan baik."
            },
            {
                "name": "Ahmad Hidayat",
                "position": "Bendahara Desa",
                "photo": "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=300",
                "bio": "Bertanggung jawab atas keuangan desa."
            }
        ]
        
        for p in sample_pengurus:
            pengurus = Pengurus(**p)
            await db.pengurus.insert_one(pengurus.model_dump())
        
        logger.info("Sample pengurus created")
    
    # Create profil desa
    profil_exists = await db.profil_desa.find_one({"id": "profil-desa"})
    if not profil_exists:
        profil = ProfilDesa(
            name="Desa Maju Sejahtera",
            description="Desa yang terletak di kaki gunung dengan pemandangan yang indah dan udara yang sejuk.",
            vision="Menjadi desa yang maju, sejahtera, dan mandiri.",
            mission="Meningkatkan kesejahteraan masyarakat melalui pembangunan berkelanjutan.",
            contact="Jl. Raya Desa No. 123, Telp: (0274) 123456",
            logo="https://images.unsplash.com/photo-1582213782179-e0d53f98f2ca?w=200"
        )
        await db.profil_desa.insert_one(profil.model_dump())
        logger.info("Profil desa created")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

handler = Mangum(app)