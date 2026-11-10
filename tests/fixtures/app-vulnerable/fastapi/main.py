import jwt
from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)


def current_user(authorization: str = Header()):
    return jwt.decode(authorization, options={"verify_signature": False})


@app.delete("/orders/{order_id}")
async def delete_order(order_id: int):
    await db.execute(f"DELETE FROM orders WHERE id = {order_id}")
