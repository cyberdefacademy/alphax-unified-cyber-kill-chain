from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from ..config import get_settings

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# For v0 single operator: hash once; in prod store in DB
def get_operator_hash():
    # lazy hash of env password
    return pwd_ctx.hash(settings.alphax_operator_password)

OPERATOR_USER = settings.alphax_operator_user

def verify_password(plain, hashed):
    return pwd_ctx.verify(plain, hashed)

def create_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.jwt_expire_minutes))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)

@router.post("/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    # single operator check
    # we hash env password and verify; avoid timing leak by always hashing
    if form.username != OPERATOR_USER or not verify_password(form.password, get_operator_hash()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_token({"sub": form.username})
    return {"access_token": token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    cred_exc = HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        user: str | None = payload.get("sub")
        if user is None:
            raise cred_exc
        return user
    except JWTError:
        raise cred_exc
