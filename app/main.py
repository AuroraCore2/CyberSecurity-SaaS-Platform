from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-app.vercel.app", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

### Step 2 — Deploy Backend to Railway

1. Push your repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Add a **Postgres** plugin inside Railway
4. Set these environment variables in Railway:
   - `DATABASE_URL` → auto-filled by Railway's Postgres plugin
   - `PORT` → `8000`
5. Add a `Procfile` to your repo root:
```
   web: uvicorn app.main:app --host 0.0.0.0 --port $PORT