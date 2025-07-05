from fastapi import FastAPI
from fastfsx import FileRouter
from tortoise.contrib.fastapi import register_tortoise
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.include_router(FileRouter('app/pages').build())
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

register_tortoise(
    app,
    db_url='sqlite://db/.sqlite3',
    modules={'models': ['app.models.models']},
    generate_schemas=True
)
