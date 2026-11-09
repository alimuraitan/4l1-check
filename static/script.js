document.addEventListener('DOMContentLoaded', () => { // تشغيل الكود بعد تحميل الصفحة بالكامل
    const scanBtn = document.getElementById('scan-btn'); // زر بدء الفحص
    const clearBtn = document.getElementById('clear-btn'); // زر مسح النتائج
    const websiteUrlInput = document.getElementById('website-url'); // حقل إدخال رابط الموقع
    const vulnTypeSelect = document.getElementById('vuln-type'); // قائمة نوع الثغرة
    const progressSection = document.getElementById('progress-section'); // قسم حالة "جاري الفحص"
    const resultsSection = document.getElementById('results-section'); // قسم عرض النتائج
    const vulnerabilitiesContainer = document.getElementById('vulnerabilities-container'); // حاوية بطاقات الثغرات

    scanBtn.addEventListener('click', startScan); // عند الضغط على زر الفحص يبدأ الفحص
    clearBtn.addEventListener('click', clearResults); // عند الضغط على زر المسح يتم مسح النتائج

    websiteUrlInput.addEventListener('keypress', (e) => { // تشغيل الفحص إذا ضغط المستخدم Enter داخل خانة الرابط
        if (e.key === 'Enter') startScan(); // إذا كان المفتاح Enter ابدأ الفحص
    });

    async function startScan() { // الدالة الأساسية التي تبدأ عملية الفحص
        const url = websiteUrlInput.value.trim(); // أخذ الرابط المدخل وإزالة المسافات
        const type = vulnTypeSelect.value; // أخذ نوع الفحص المحدد

        if (!url) { // إذا لم يدخل المستخدم رابط
            alert('أدخل رابط الموقع'); // إظهار رسالة خطأ للمستخدم
            return; // إيقاف تنفيذ الفحص
        }

        scanBtn.disabled = true; // تعطيل زر "ابدأ الفحص" حتى لا يضغطه المستخدم مرة أخرى
        progressSection.classList.remove('hidden'); // إظهار قسم "جاري الفحص"
        resultsSection.classList.add('hidden'); // إخفاء نتائج الفحص السابقة

        try {
            const response = await fetch('/scan', { // إرسال طلب POST إلى مسار /scan في الباك إند
                method: 'POST', // نوع الطلب POST
                headers: { 'Content-Type': 'application/json' }, // تحديد نوع البيانات المرسلة JSON
                body: JSON.stringify({
                    site: url, // إرسال رابط الموقع
                    vuln_type: type // إرسال نوع الثغرة المراد فحصها
                })
            });

            const data = await response.json(); // تحويل الرد من JSON إلى كائن JavaScript

            if (!data.success) { // إذا لم يكن الفحص ناجحاً
                alert(data.error || "حدث خطأ أثناء الفحص"); // إظهار رسالة خطأ
                return; // إيقاف الدالة
            }

            displayResults(data); // عرض النتائج القادمة من السيرفر

        } catch (error) {
            alert("خطأ في الاتصال بالسيرفر:\n" + error.message); // خطأ في الشبكة أو السيرفر
        }

        progressSection.classList.add('hidden'); // إخفاء قسم "جاري الفحص"
        scanBtn.disabled = false; // إعادة تفعيل زر الفحص
    }

    function displayResults(data) { // دالة عرض النتائج على الصفحة
        document.getElementById('pages-tested').textContent = data.pages_tested; // عدد الصفحات التي تم فحصها
        document.getElementById('total-found').textContent = data.total_found; // إجمالي عدد الثغرات المكتشفة

        vulnerabilitiesContainer.innerHTML = ""; // مسح محتوى النتائج القديمة

        if (data.results.length === 0) { // إذا لم يتم العثور على ثغرات
            vulnerabilitiesContainer.innerHTML =
                '<p style="text-align:center;color:#00ff96;padding:40px;">✓ لم يتم العثور على ثغرات</p>'; // عرض رسالة عدم وجود ثغرات
        } else {
            const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2 }; // ترتيب مستويات الخطورة

            data.results.sort(
                (a, b) => severityOrder[a.severity] - severityOrder[b.severity] // ترتيب الثغرات حسب الخطورة
            );

            data.results.forEach((vuln, index) => { // المرور على كل ثغرة
                vulnerabilitiesContainer.appendChild(
                    createVulnerabilityCard(vuln, index) // إضافة بطاقة ثغرة جديدة
                );
            });
        }

        resultsSection.classList.remove('hidden'); // إظهار نتائج الفحص
    }

    function createVulnerabilityCard(vuln, index) { // دالة تقوم ببناء بطاقة واحدة لكل ثغرة
        const card = document.createElement('div'); // إنشاء عنصر div جديد
        card.className = `vulnerability-card ${vuln.severity.toLowerCase()}`; // إضافة جلس حسب نوع الخطورة
        card.style.animationDelay = `${index * 0.08}s`; // إضافة تأخير بسيط للأنيميشن حسب ترتيب البطاقة

        const severityClass = `severity-${vuln.severity.toLowerCase()}`; // كلاس مستوى الخطورة
        const shortUrl =
            vuln.url.length > 100 ? vuln.url.substring(0, 100) + "..." : vuln.url; // تقصير الرابط إذا كان طويل جداً

        card.innerHTML = `
            <div class="vuln-header">
                <div class="vuln-type">${escapeHtml(vuln.type)}</div>
                <div class="severity-badge ${severityClass}">
                    ${escapeHtml(vuln.severity)}
                </div>
            </div>

            <div class="vuln-content">
                <span class="vuln-label">🔗 الرابط:</span>
                <div class="vuln-url">${escapeHtml(shortUrl)}</div>
                <button class="copy-btn copy-url-btn">نسخ</button>
            </div>

            <div class="vuln-content">
                <span class="vuln-label">💣 Payload:</span>
                <div class="vuln-payload">${escapeHtml(vuln.payload)}</div>
                <button class="copy-btn copy-payload-btn">نسخ</button>
            </div>

            <div class="vuln-description">
                <strong>📌 الوصف:</strong><br>
                ${escapeHtml(vuln.description)}
            </div>
        `; // هذا هو المحتوى الداخلي للبطاقة مع بيانات الثغرة

        const copyUrlBtn = card.querySelector('.copy-url-btn'); // زر نسخ الرابط
        const copyPayloadBtn = card.querySelector('.copy-payload-btn'); // زر نسخ البايلود

        copyUrlBtn.addEventListener('click', () => { // عند الضغط على زر نسخ الرابط
            copyToClipboard(vuln.url); // نسخ الرابط إلى الحافظة
        });

        copyPayloadBtn.addEventListener('click', () => { // عند الضغط على زر نسخ البايلود
            copyToClipboard(vuln.payload); // نسخ البايلود إلى الحافظة
        });

        return card; // إعادة البطاقة النهائية
    }

    function clearResults() { // دالة مسح النتائج من الصفحة
        websiteUrlInput.value = ""; // مسح خانة إدخال الرابط
        vulnerabilitiesContainer.innerHTML = ""; // مسح البطاقات
        resultsSection.classList.add("hidden"); // إخفاء قسم النتائج
        progressSection.classList.add("hidden"); // إخفاء حالة الفحص
    }
});

function copyToClipboard(text) { // دالة نسخ نص إلى الحافظة
    const area = document.createElement("textarea"); // إنشاء عنصر textarea مؤقت
    area.value = text; // وضع النص المطلوب نسخه
    document.body.appendChild(area); // إضافته للصفحة
    area.select(); // تحديد النص الموجود
    document.execCommand("copy"); // تنفيذ النسخ
    document.body.removeChild(area); // حذف Textarea
    alert("✔ تم النسخ"); // إظهار رسالة النجاح
}

function escapeHtml(text) { // دالة لمنع تنفيذ أي شيفرات داخل النصوص
    const map = {
        '&': '&amp;', // تحويل & إلى كود HTML آمن
        '<': '&lt;', // تحويل <
        '>': '&gt;', // تحويل >
        '"': '&quot;', // تحويل "
        "'": '&#039;', // تحويل '
        "`": '&#x60;' // تحويل `
    };
    return text.replace(/[&<>"'`]/g, (m) => map[m]); // استبدال الرموز غير الآمنة
}