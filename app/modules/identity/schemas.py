from pydantic import BaseModel


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RefreshTokenRecord(BaseModel):
    token_hash: str
    family_id: str
    user_id: str
    refresh_epoch: int
