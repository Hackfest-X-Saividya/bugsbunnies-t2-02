from fastapi import FastAPI

app = FastAPI()


@app.get("/unsafe")
def unsafe():
    return eval("1 + 1")
