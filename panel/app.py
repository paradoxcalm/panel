# app.py
import os, json, random, datetime
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from waitress import serve
from uploader import auth_service, upload_one, rfc3339

app = Flask(__name__)
app.secret_key = "change-me"
DATA="panel/data"
UPLOAD_DIR=os.path.join(DATA,"uploads")
QUEUE=os.path.join(DATA,"queue.json")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA, exist_ok=True)

def load_queue():
    return json.load(open(QUEUE,"r",encoding="utf-8")) if os.path.exists(QUEUE) else []
def save_queue(items):
    json.dump(items, open(QUEUE,"w",encoding="utf-8"), ensure_ascii=False, indent=2)

@app.route("/")
def index():
    q=load_queue()
    return render_template("index.html", queue=q)

@app.route("/upload", methods=["POST"])
def upload():
    f=request.files.get("video")
    thumb=request.files.get("thumb")
    title=request.form.get("title") or os.path.splitext(f.filename)[0]
    desc=request.form.get("description") or ""
    tg=request.form.get("tg") or ""
    tags=[t.strip() for t in (request.form.get("tags") or "").split(",") if t.strip()]
    cat=request.form.get("categoryId") or "22"
    mode=request.form.get("mode")  # now | schedule | random
    publish_at=None
    # расписание
    if mode=="schedule":
        date=request.form.get("date"); time_=request.form.get("time")
        if date and time_:
            dt=datetime.datetime.fromisoformat(f"{date}T{time_}")
            publish_at=dt.astimezone(datetime.timezone.utc)
    elif mode=="random":
        min_h=float(request.form.get("min_h",1)); max_h=float(request.form.get("max_h",3))
        start_dt=datetime.datetime.utcnow()+datetime.timedelta(minutes=10)
        delta=random.uniform(min_h,max_h)
        publish_at=start_dt+datetime.timedelta(hours=delta)

    video_path=os.path.join(UPLOAD_DIR, f.filename); f.save(video_path)
    thumb_path=None
    if thumb and thumb.filename:
        thumb_path=os.path.join(UPLOAD_DIR, thumb.filename); thumb.save(thumb_path)

    item={
      "video_path":video_path,
      "thumb_path":thumb_path,
      "title":title,
      "description":(desc + (f"\nПодпишись на Telegram: {tg}" if tg else "")).strip(),
      "tags":tags or ["youtube","shorts"],
      "categoryId":cat,
      "publishAt": rfc3339(publish_at) if publish_at else None
    }
    q=load_queue(); q.append(item); save_queue(q)
    flash("Добавлено в очередь")
    return redirect(url_for("index"))

@app.route("/queue")
def queue():
    return render_template("queue.html", queue=load_queue())

@app.route("/start", methods=["POST"])
def start():
    q=load_queue()
    if not q:
        flash("Очередь пуста"); return redirect(url_for("index"))
    yt=auth_service()
    errors=0
    for item in q:
        try:
            vid=upload_one(yt,
                video_path=item["video_path"],
                title=item["title"],
                description=item["description"],
                tags=item["tags"],
                category_id=item["categoryId"],
                publish_at_iso=item["publishAt"],
                thumb_path=item.get("thumb_path"))
            print("Uploaded:", vid)
        except Exception as e:
            print("Error:", e); errors+=1
    save_queue([])  # очистить
    flash(f"Готово. Ошибок: {errors}")
    return redirect(url_for("index"))

if __name__=="__main__":
    # dev: app.run(debug=True, port=8080)
    serve(app, host="0.0.0.0", port=8080)
