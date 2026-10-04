# Guardian-X

## نظام كشف الشذوذ السلوكي لأنشطة الملفات على الحافة (Edge)

---

# القسم الأول: نظرة عامة

## 1.1 فكرة المشروع

Guardian-X نظام أمني لاكتشاف السلوك غير الطبيعي لمستخدمي الحواسيب عبر تحليل أنشطة الملفات (إنشاء، قراءة، تعديل، حذف) على الجهاز نفسه (Edge). يجمع بين القواعد الثابتة، التعلم الآلي، والتفسير القابل للفهم (XAI) للكشف المبكر عن التهديدات الداخلية.

## 1.2 الميزات الرئيسية

| الميزة | الوصف |
|--------|-------|
| **مراقبة تلقائية** | Edge Agent يراقب نظام الملفات مباشرة (watchdog) ويرسل الأحداث للسيرفر |
| **وضع المحاكاة** | تشغيل كامل بدون هاردوير فعلي: وكلاء محاكاة، معاملات، تحميل ملفات |
| **خط أساس متكيف** | يتعلم من البيانات الفعلية ويحدّث حدود السلوك الطبيعي تلقائياً |
| **ثلاث طبقات تحليل** | قواعد → مجموعة ML (Isolation Forest, LightGBM, Autoencoder) → تفسير SHAP/LIME |
| **استجابة تلقائية** | عند High Risk يُسجّل إجراء احتواء (block) تلقائياً |
| **لوحة تحكم** | عرض الأحداث، التنبيهات، التقارير، والمقاييس |

## 1.3 مسرد المصطلحات التقنية

| المصطلح | بالعربي | الشرح |
|---------|---------|-------|
| **Edge** | الحافة | الجهاز المحلي الذي تُنفَّذ عليه العمليات (بدلاً من السحابة) |
| **Behavioral Anomaly** | الشذوذ السلوكي | سلوك يختلف عن النمط المعتاد للمستخدم |
| **Adaptive Baseline** | خط أساس متكيف | حدود سلوكية تُحدَّث من البيانات الفعلية |
| **Isolation Forest** | غابة العزل | نموذج ML يعزل الشواذ في أشجار قرار |
| **LightGBM** | تعزيز التدرج | نموذج ML قوي للتصنيف |
| **Autoencoder** | المترمّز التلقائي | شبكة عصبية تُعيد بناء المدخلات؛ خطأ عالٍ = شذوذ |
| **SHAP** | قيم شابلي | تفسير مساهمة كل ميزة في قرار النموذج |
| **LIME** | تفسير محلي | تقريب النموذج محلياً لتوضيح سبب التصنيف |
| **XAI** | الذكاء الاصطناعي القابل للتفسير | تقنيات تجعل قرارات الـ ML مفهومة |
| **REST API** | واجهة برمجية | تواصل عبر HTTP بصيغة JSON |
| **SQLite** | قاعدة بيانات | قاعدة بيانات خفيفة في ملف واحد |
| **watchdog** | مراقب الملفات | مكتبة Python لمراقبة تغييرات نظام الملفات |

---

# القسم الثاني: المعمارية والتشغيل

## 2.1 المعمارية

```
┌──────────────────┐   POST /api/events   ┌─────────────────────────────────────────────────┐
│   Edge Agent     │ ───────────────────► │              Flask Server                       │
│   (watchdog)     │                      │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│  مراقبة مجلدات   │                      │  │ rules.py    │ │ ai_model.py │ │explainability│ │
│  Create/Modify/  │                      │  │ (قواعد)     │ │ (ML + قواعد)│ │ (SHAP/LIME) │ │
│  Delete          │                      │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ │
└──────────────────┘                      │ ┌──────┴──────────────┴──────────────┴──────┐ │
         ▲                                │ │              db.py (SQLite)               │ │
         │                                │ │  file_events | alerts | explanations | ... │ │
┌────────┴────────┐                        │ └──────────────────────────────────────────┘ │
│  Simulate Form │  POST /api/events      └────────────────────────────┬──────────────────┘
│  (لوحة التحكم)  │                                                      │
└──────────────────────────────────────────────────────────────────────┼──────────────────┘
                                                                        ▼
                                                         ┌──────────────────────────────┐
                                                         │   Dashboard (Frontend)       │
                                                         │   أحداث | تنبيهات | تقارير   │
                                                         └──────────────────────────────┘
```

## 2.2 هيكلة المشروع

```
Guardian-X/
├── agent/
│   ├── edge_agent.py         # مراقبة تلقائية للملفات (watchdog) — جاهز للهاردوير
│   └── README.md
├── config.py                 # إعدادات + إمكانية الربط بالهاردوير
├── HARDWARE.md               # خطوات الربط بـ Raspberry Pi / Mini-PC
├── dataset/
│   └── synthetic/            # CSV اصطناعية (معاملات + سجلات موظفين) تُنشأ عند التدريب/التصدير
├── server/
│   ├── app.py                # Flask + واجهات API
│   ├── security_framework.py # NIST CSF + تعيين ISO 27001
│   ├── synthetic_dataset.py  # بيانات مصرفية وموظفين اصطناعية
│   ├── evaluation.py         # قياس Accuracy و CPU/RAM
│   ├── ai_model.py           # تحليل هجين: قواعد + ML
│   ├── rules.py              # الطبقة القاعدية
│   ├── ml_models.py          # Isolation Forest, LightGBM, Autoencoder
│   ├── feature_extractor.py  # استخراج 17 ميزة من الحدث
│   ├── explainability.py     # SHAP و LIME
│   ├── adaptive_baseline.py  # خط أساس متكيف
│   ├── training.py           # تدريب + UNSW-NB15, CICIDS-2017
│   ├── train_models.py       # سكربت التدريب
│   ├── db.py                 # SQLite
│   └── models/               # نماذج ML (تُنشأ بعد التدريب)
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
├── requirements.txt
└── README.md
```

## 2.3 خطوات التشغيل

### الخطوة 1: تثبيت المتطلبات

```bash
cd Guardian-X
pip install -r requirements.txt
```

### الخطوة 2: تدريب نماذج التعلم الآلي (أول مرة)

```bash
python server/train_models.py
```

**تدريب على بيانات المشروع الاصطناعية (معاملات مصرفية + سجلات موظفين):**

```bash
python server/train_models.py --dataset guardian
```

أو من لوحة التحكم: زر **Train ML Models**، أو طلب `POST /api/train` مع `"mode": "guardian"`.

### الخطوة 3: تشغيل السيرفر

```bash
python server/app.py
```

- إن وُجدت `server/certs/cert.pem` و `server/certs/key.pem` يعمل السيرفر بـ **HTTPS** (TLS 1.2 كحد أدنى؛ TLS 1.3 عند دعم بيئة التشغيل).
- بدون شهادات: **http://127.0.0.1:5000**

### الخطوة 4: فتح لوحة التحكم

افتح المتصفح على نفس العنوان والمنفذ (مثلاً **https://127.0.0.1:5000** إذا فُعّل TLS). الواجهة تستخدم `window.location` للاتصال بـ API تلقائياً.

## 2.4 الأمن، البيانات الاصطناعية، التقييم، والسيناريوهات

| الموضوع | الوصف |
|--------|--------|
| **إطار أمني** | تطبيق وتوثيق **NIST CSF 2.0** مع تعيين مؤشر لـ **ISO/IEC 27001** (Annex A) عبر `server/security_framework.py` ومسار **GET `/api/security/framework`**. |
| **TLS / HTTPS** | إعداد السياق في `server/app.py` (`get_ssl_context`) — استهداف TLS 1.3 مع `minimum_version` 1.2. |
| **Dataset اصطناعي** | `server/synthetic_dataset.py` يولّد **banking transactions** و **employee activity logs** ويصدّر CSV تحت `dataset/synthetic/`. |
| **تقييم دقة وموارد** | `python server/evaluation.py` أو **POST `/api/evaluation/run`** — يطبع **Accuracy** و Precision/Recall/F1 و**CPU/RAM** (عبر `psutil`). |
| **سيناريوهات** | **POST `/api/scenarios/fraud`** (احتيال مالي) و **POST `/api/scenarios/unauthorized_copy`** (نسخ غير مصرح). |
| **نشاط FileCopy** | نوع حدث `FileCopy` بصيغة مسار `مصدر|وجهة` لاكتشاف نسخ حساس إلى وسائط خارجية. |

### الخطوة 5: (اختياري) تشغيل Edge Agent أو المحاكاة

**بدون هاردوير (محاكاة):** من لوحة التحكم:
- **Simulate Agent** — تسجيل وكيل حافة محاكى
- **Simulate Transaction** — محاكاة معاملة مالية (مبلغ، نوع)
- **FileDownload** — محاكاة تحميل ملف حساس
- **Batch Simulate** — إنشاء أحداث عشوائية (ملفات + معاملات + تحميلات)

**مع الوكيل الفعلي:** في نافذة أوامر أخرى:

```bash
python agent/edge_agent.py --path "C:\Users\YourName\Documents"
```

مع **HTTPS** وشهادة ذاتية، أضف `--insecure` للوكيل (تطوير فقط):

```bash
python agent/edge_agent.py --path "C:\Users\YourName\Documents" --server https://127.0.0.1:5000 --insecure
```

---

## الميزات العشر (حسب التقرير) — حالة التنفيذ

| الميزة | الحالة | التفاصيل |
|--------|--------|----------|
| **Edge-Based Monitoring / Edge Agent** | ✅ | `agent/edge_agent.py` — مراقبة ملفات، يعمل على أي جهاز |
| **Real-Time File System Monitoring** | ✅ | watchdog — Create, Modify, Delete فوري |
| **Machine Learning Model Training** | ✅ | Isolation Forest, LightGBM, Autoencoder |
| **Dataset-Based Learning** | ✅ | UNSW-NB15, CICIDS-2017، وبيانات اصطناعية مصرفية + موظفين (`--dataset guardian`) |
| **Explainable AI (SHAP / LIME)** | ✅ | `explainability.py` — تقارير XAI |
| **Endpoint Monitoring Agent** | ✅ | نفس Edge Agent — مراقبة نقاط النهاية |
| **Automated Incident Response** | ✅ | block, isolate, freeze عند High Risk |
| **Adaptive Behavioral Baseline** | ✅ | `adaptive_baseline.py` + `behavior_profile` |
| **Data-Driven Threat Analysis** | ✅ | تحليل من السياق + ML |
| **Advanced User Behavior Profiling** | ✅ | ملف سلوك ديناميكي لكل مستخدم |

---

## الربط بالهاردوير مستقبلاً

المشروع مُهيَّأ للربط بـ **Raspberry Pi** و **Mini-PC** المذكورين في التقرير:

- **`config.py`** — إعدادات الربط (TLS، ML محلي، إلخ)
- **`HARDWARE.md`** — خطوات الربط بالهاردوير
- **`agent/edge_agent.py`** — يدعم `--agent-id` ويسجّل الوكيل تلقائياً

```bash
# على Raspberry Pi مستقبلاً
python3 agent/edge_agent.py --path /home/pi/Documents --server http://SERVER:5000 --agent-id raspberry-pi-01
```

---

# القسم الثالث: قاعدة البيانات بالتفصيل

## 3.1 الجداول والأعمدة

### جدول `behavior_profile`

| العمود | النوع | الوصف |
|--------|------|-------|
| id | INTEGER | المفتاح الأساسي |
| avg_ops_per_hour | INTEGER | متوسط العمليات في الساعة (افتراضي: 15) |
| normal_delete_limit | INTEGER | حد الحذف الطبيعي في 10 دقائق (افتراضي: 3) |
| normal_modify_limit | INTEGER | حد التعديل الطبيعي في الساعة (افتراضي: 5) |
| work_start_time | TEXT | بداية أوقات العمل (افتراضي: 08:00) |
| work_end_time | TEXT | نهاية أوقات العمل (افتراضي: 17:00) |
| created_at | TIMESTAMP | تاريخ الإنشاء |

**مثال:** سجل واحد يحدد السلوك الطبيعي للمؤسسة؛ يُحدَّث تلقائياً كل 30 حدثاً عند توفر بيانات كافية.

### جدول `file_events`

| العمود | النوع | الوصف |
|--------|------|-------|
| id | INTEGER | المفتاح الأساسي |
| user_id | TEXT | معرف المستخدم (مثل user01، admin، أو اسم الجهاز) |
| activity_type | TEXT | Create | Read | Modify | Delete |
| file_path | TEXT | مسار الملف |
| risk_level | TEXT | Normal | Suspicious | High Risk |
| timestamp | TIMESTAMP | وقت الحدث |
| details | TEXT | تفاصيل إضافية |

**مثال:** `(user01, Delete, C:\data\secret.key, High Risk, 2025-03-11 02:30:00)`

### جدول `alerts`

| العمود | النوع | الوصف |
|--------|------|-------|
| id | INTEGER | المفتاح الأساسي |
| user_id | TEXT | المستخدم |
| risk_level | TEXT | Suspicious | High Risk |
| reason | TEXT | سبب التنبيه |
| timestamp | TIMESTAMP | وقت التنبيه |
| file_event_ids | TEXT | معرفات الأحداث المرتبطة (مفصولة بفاصلة) |

### جدول `explanations`

| العمود | النوع | الوصف |
|--------|------|-------|
| id | INTEGER | المفتاح الأساسي |
| file_event_id | INTEGER | مرجع لـ file_events |
| shap_json | TEXT | JSON لمساهمات SHAP |
| lime_json | TEXT | JSON لمساهمات LIME |
| summary_text | TEXT | ملخص نصي للتفسير |
| created_at | TIMESTAMP | تاريخ الإنشاء |

### جدول `containment_actions`

| العمود | النوع | الوصف |
|--------|------|-------|
| id | INTEGER | المفتاح الأساسي |
| alert_id | INTEGER | مرجع لـ alerts |
| file_event_id | INTEGER | مرجع لـ file_events |
| action_type | TEXT | block | isolate | log | freeze |
| status | TEXT | simulated (افتراضي) |
| details | TEXT | تفاصيل الإجراء |
| created_at | TIMESTAMP | تاريخ الإنشاء |

## 3.2 العلاقات بين الجداول

```
file_events (1) ────► (N) alerts        [file_event_ids]
file_events (1) ────► (N) explanations  [file_event_id]
alerts (1) ─────────► (N) containment_actions [alert_id]
```

## 3.3 كود إنشاء الجداول (من db.py)

```python
cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        activity_type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        details TEXT
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS behavior_profile (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        avg_ops_per_hour INTEGER DEFAULT 15,
        normal_delete_limit INTEGER DEFAULT 3,
        normal_modify_limit INTEGER DEFAULT 5,
        work_start_time TEXT DEFAULT '08:00',
        work_end_time TEXT DEFAULT '17:00',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')
```

---

# القسم الرابع: الأكواد المهمة

## 4.1 استقبال الحدث وتحليله (app.py)

```python
@app.route('/api/events', methods=['POST'])
def add_event():
    data = request.get_json()
    user_id = data.get('user_id', 'anonymous')
    activity_type = data.get('activity_type')  # Create, Read, Modify, Delete
    file_path = data.get('file_path', '')

    profile = db.get_behavior_profile()
    events = db.get_file_events(200)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    risk_level, reason, score = analyze_event(
        user_id, activity_type, file_path, timestamp, events, profile
    )

    event_id = db.add_file_event(user_id, activity_type, file_path, risk_level, reason)

    if risk_level in ['Suspicious', 'High Risk']:
        alert_id = db.add_alert(user_id, risk_level, reason, str(event_id))
        if risk_level == 'High Risk':
            db.add_containment_action(alert_id, event_id, 'block', f'Auto response: {reason[:100]}')

    return jsonify({'id': event_id, 'risk_level': risk_level, 'reason': reason, 'score': round(score, 2)})
```

## 4.2 طبقة القواعد (rules.py)

```python
SENSITIVE_EXTENSIONS = ['.ini', '.config', '.env', '.key', '.pem', '.crt', '.xml']

def apply_rules(activity_type, file_path, timestamp, context, profile):
    risk_level = 'Normal'
    reasons = []

    # حذف خارج أوقات العمل → High Risk
    if rule_outside_work_hours(timestamp, ...) and activity_type == 'Delete':
        risk_level = 'High Risk'
        reasons.append('File deletion outside working hours')

    # تعديل ملف حساس → Suspicious
    if activity_type == 'Modify' and is_sensitive_file(file_path):
        risk_level = 'Suspicious'
        reasons.append('Modification of sensitive file')

    # حذف مفرط في 10 دقائق → High Risk
    if context.get('delete_count_10min', 0) > profile.get('normal_delete_limit', 3):
        risk_level = 'High Risk'
        reasons.append('Excessive deletions')

    # تكرار وصول لنفس الملف (≥3 في دقيقة) → Suspicious
    if context.get('same_file_access_count', 0) >= 3:
        risk_level = 'Suspicious'
        reasons.append('Excessive file access frequency')

    return risk_level, '; '.join(reasons)
```

## 4.3 التحليل الهجين (ai_model.py)

```python
def analyze_event(user_id, activity_type, file_path, timestamp, event_history, profile):
    # بناء السياق: عدد الحذف في 10 دقائق، التعديل في ساعة، تكرار الوصول
    context = {'delete_count_10min': 0, 'modify_count_hour': 0, 'same_file_access_count': 0}
    for e in event_history:
        if e.get('user_id') != user_id:
            continue
        # ... حساب السياق من event_history

    # الطبقة 1: القواعد
    risk_level, reason = apply_rules(activity_type, file_path, timestamp, context, profile)

    # الطبقة 2: ML Ensemble
    if ensemble.is_ready():
        feats = extract_features_single(...)
        X = [features_to_vector(feats)]
        ml_score, ml_risk = ensemble.predict(X)
        # دمج: نأخذ الأعلى بين القواعد و ML
        if ml_risk == 'High Risk' or risk_level == 'High Risk':
            risk_level = 'High Risk'
        elif ml_risk == 'Suspicious' and risk_level == 'Normal':
            risk_level = 'Suspicious'
        score = ml_score
    else:
        score, _ = _threshold_fallback(combined_events, profile)

    return risk_level, reason, score
```

## 4.4 استخراج الميزات (feature_extractor.py)

```python
def get_feature_names():
    return [
        'activity_type', 'path_depth', 'path_length', 'is_sensitive_file',
        'hour_of_day', 'minute', 'is_weekend', 'is_work_hours',
        'delete_count_10min', 'modify_count_hour', 'same_file_access',
        'create_count_hour', 'read_count_hour', 'total_ops_hour',
        'ops_ratio', 'delete_ratio', 'modify_ratio'
    ]

# 17 ميزة رقمية تُدخل لنماذج ML
def features_to_vector(features):
    return [float(features.get(n, 0)) for n in get_feature_names()]
```

## 4.5 مجموعة ML (ml_models.py)

```python
# Isolation Forest: عزل الشواذ
model = IsolationForest(n_estimators=100, contamination=0.1)
model.fit(X)

# LightGBM: تصنيف ثنائي (0=عادي، 1=شاذ)
model = LGBMClassifier(num_leaves=31, n_estimators=100)
model.fit(X, y)
# proba[:, 1] = احتمال الشذوذ

# Autoencoder: إعادة البناء، خطأ عالٍ = شذوذ
mse = np.mean(np.square(X - reconstructed), axis=1)
# تحويل MSE إلى درجة 0-100

# النتيجة النهائية: متوسط مرجح لدرجات الثلاثة
# عتبات: ≥70 High Risk، ≥35 Suspicious، وإلا Normal
```

---

# القسم الخامس: واجهات API

## 5.1 جدول جميع المسارات

| المسار | الطريقة | الوظيفة |
|--------|---------|----------|
| `/api/events` | GET | قائمة الأحداث |
| `/api/events` | POST | إضافة حدث وتحليله |
| `/api/alerts` | GET | قائمة التنبيهات |
| `/api/explain/<id>` | GET | تقرير XAI لحدث |
| `/api/containment` | GET | قائمة إجراءات الاحتواء |
| `/api/containment` | POST | تنفيذ إجراء احتواء |
| `/api/train` | POST | تدريب نماذج ML (`mode`: synthetic \| guardian، أو `use_db`) |
| `/api/security/framework` | GET | إطار NIST + تعيين ISO 27001 وحالة TLS |
| `/api/evaluation/run` | POST | تقييم على بيانات اصطناعية (دقة، CPU/RAM) |
| `/api/scenarios/fraud` | POST | سيناريو احتيال مالي |
| `/api/scenarios/unauthorized_copy` | POST | سيناريو نسخ ملفات غير مصرح |
| `/api/stats` | GET | إحصائيات اللوحة |
| `/api/metrics` | GET | MTTD, MTTR, Precision, Recall |
| `/api/simulate/batch` | POST | محاكاة دفعة أحداث |
| `/api/health` | GET | حالة السيرفر وقاعدة البيانات |
| `/api/profile` | GET | إعدادات ملف السلوك |

## 5.2 أمثلة طلبات حقيقية (curl)

### إرسال حدث

```bash
curl -X POST http://127.0.0.1:5000/api/events \
  -H "Content-Type: application/json" \
  -d '{"user_id":"user01","activity_type":"Delete","file_path":"C:\\data\\secret.key"}'
```

**استجابة:**
```json
{"id": 14, "risk_level": "High Risk", "reason": "File deletion outside working hours", "score": 85.2}
```

### جلب الأحداث

```bash
curl http://127.0.0.1:5000/api/events?limit=10
```

### جلب تفسير XAI

```bash
curl http://127.0.0.1:5000/api/explain/14
```

### محاكاة دفعة أحداث

```bash
curl -X POST http://127.0.0.1:5000/api/simulate/batch \
  -H "Content-Type: application/json" \
  -d '{"count": 5}'
```

### تدريب النماذج

```bash
curl -X POST http://127.0.0.1:5000/api/train \
  -H "Content-Type: application/json" \
  -d '{"use_db": false}'
```

---

# القسم السادس: أمثلة واقعية

## 6.1 سيناريو: موظف يحذف ملفات حساسة ليلاً

**الوضع:** موظف ينسخ بيانات سرية ويحذف ملفات خارج أوقات العمل (02:30 صباحاً).

**الحدث المرسل:**
```json
{"user_id":"employee01","activity_type":"Delete","file_path":"C:\\confidential\\client_data.xlsx"}
```

**النتيجة:**
- `risk_level`: High Risk
- `reason`: File deletion outside working hours
- `score`: 85
- يُنشأ تنبيه تلقائياً
- يُسجّل إجراء block
- يُولَّد تقرير XAI (SHAP/LIME) يوضح أن `hour_of_day` و `is_work_hours` ساهما في التصنيف

## 6.2 سيناريو: مهاجم يعدّل ملف إعدادات

**الوضع:** شخص يعدّل ملف `.env` أو `config.ini` لسرقة مفاتيح أو تغيير إعدادات.

**الحدث المرسل:**
```json
{"user_id":"unknown","activity_type":"Modify","file_path":"C:\\app\\.env"}
```

**النتيجة:**
- `risk_level`: Suspicious
- `reason`: Modification of sensitive file
- `score`: 45
- يُنشأ تنبيه
- زر Explain يظهر مساهمات SHAP: `is_sensitive_file` و `path_depth` الأعلى

## 6.3 سيناريو: حذف مفرط في دقائق

**الوضع:** مستخدم يحذف 6 ملفات خلال 10 دقائق (الحد الطبيعي 3).

**الأحداث المتتالية:**
```json
{"user_id":"admin","activity_type":"Delete","file_path":"/data/temp1.tmp"}
{"user_id":"admin","activity_type":"Delete","file_path":"/data/temp2.tmp"}
...
{"user_id":"admin","activity_type":"Delete","file_path":"/data/temp6.tmp"}
```

**النتيجة:**
- الحدث السادس: `risk_level`: High Risk
- `reason`: Excessive deletions (>3 in 10 min)
- `score`: 90
- استجابة تلقائية: block

## 6.4 سيناريو: Edge Agent يراقب مجلد Documents

```bash
python agent/edge_agent.py --path "C:\Users\Ahmed\Documents" --user "ahmed-pc"
```

**ما يحدث:**
- عند إنشاء ملف جديد → يُرسل `Create` للسيرفر
- عند تعديل ملف → يُرسل `Modify`
- عند حذف ملف → يُرسل `Delete`
- السيرفر يحلل كل حدث فوراً ويعرض النتيجة في لوحة التحكم

---

# القسم السابع: التدريب ومجموعات البيانات

## 7.1 أوامر التدريب

| الأمر | الوصف |
|-------|-------|
| `python server/train_models.py` | تدريب من بيانات اصطناعية (800 عينة) |
| `python server/train_models.py --db` | تدريب من قاعدة البيانات |
| `python server/train_models.py --dataset unsw` | UNSW-NB15 من HuggingFace |
| `python server/train_models.py --dataset cicids` | CICIDS-2017 (يتطلب CSV في datasets/) |

## 7.2 الملفات المُنشأة بعد التدريب

```
server/models/
├── isolation_forest.pkl
├── lightgbm.pkl
├── autoencoder/           (أو autoencoder_sklearn.pkl)
```

---

# القسم الثامن: سير العمل الكامل

```
1. وصول حدث (من Agent أو نموذج المحاكاة)
   ↓
2. استخراج السياق: delete_count_10min, modify_count_hour, same_file_access_count
   ↓
3. الطبقة 1: rules.apply_rules() → risk_level, reason
   ↓
4. الطبقة 2: feature_extractor → 17 ميزة → MLEnsemble → ml_score, ml_risk
   ↓
5. دمج: أخذ الأعلى بين القواعد و ML
   ↓
6. حفظ في file_events
   ↓
7. إنشاء تنبيه (إن وجد) في alerts
   ↓
8. استجابة تلقائية: block عند High Risk (containment_actions)
   ↓
9. توليد XAI (SHAP/LIME) للأحداث المشبوهة/عالية الخطورة
   ↓
10. تحديث الخط الأساس المتكيف كل 30 حدثاً إذا توفرت بيانات
```

---

# المراجع

- Flask: https://flask.palletsprojects.com/
- scikit-learn Isolation Forest: https://scikit-learn.org/stable/modules/ensemble.html#isolation-forest
- SHAP: https://github.com/slundberg/shap
- LIME: https://github.com/marcotcr/lime
