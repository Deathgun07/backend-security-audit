from fastapi import Depends, FastAPI

app = FastAPI()


@app.delete("/orders/{order_id}")
async def delete_order(
    order_id: int,
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    await db.delete_order(order_id, owner=user.id)


@app.post("/items")
async def create_item(item: dict, user=Security(get_current_user, scopes=["items"])):
    return item
