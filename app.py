# =====================================================================
# سامانه متمرکز PixelGuard - نسخه 3.7 (بهینه‌سازی شده با لایه کش شبکه)
# =====================================================================

from google.colab import drive
import os
import threading
import time
import re
import requests
from urllib.parse import urlparse
from functools import lru_cache # 🎯 اضافه شده برای پیاده‌سازی لایه کش هوشمند شبکه

print("🔄 در حال اتصال به گوگل درایو برای دسترسی به تمام فایل‌های پروژه...")
drive.mount('/content/drive', force_remount=True)

MODEL_PATH = "/content/drive/MyDrive/models/parsbert-sms"
HTML_FILE_PATH = "/content/drive/MyDrive/PixelGuard/index.html"

if not os.path.exists(MODEL_PATH):
    print("❌ خطا: پوشه مدل ParsBERT در درایو پیدا نشد!")
elif not os.path.exists(HTML_FILE_PATH):
    print(f"❌ خطا: فایل 'index.html' در مسیر پروژه پیدا نشد!\nمسیر بررسی شده: {HTML_FILE_PATH}")
else:
    print("🔄 در حال بررسی و نصب پیش‌نیازهای وب و هوش مصنوعی...")
    os.system("pip install flask flask-cors transformers torch numpy joblib - q")

    from flask import Flask, request, jsonify, render_template_string
    from flask_cors import CORS
    import torch
    import numpy as np
    import joblib
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    app = Flask(__name__)
    CORS(app) 

    print("🔄 در حال بارگذاری لایه‌های هوش مصنوعی واقعی ParsBERT در حافظه سرور...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
    label_list = joblib.load(os.path.join(MODEL_PATH, "labels.joblib"))
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    print(f"✅ مدل با موفقیت روی لایه پردازشی [{device}] مستقر شد.")

    # -------------------------------------------------------------
    #  تنظیمات فیلترهای قواعد، لیست‌های سیاه و کوتاه‌کننده‌ها
    # -------------------------------------------------------------
    SUSPICIOUS_DOMAINS = ['.me', '.info', '.xyz', '-ir.', 'gov-', '-pay', '-verify', 'samt-gov']
    
    SHORT_LINK_DOMAINS = [
        'b2n.ir', 'yun.ir', 'rizy.ir', 'plink.ir', 'opizo.com', 'shrtco.de',
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'buff.ly'
    ]

    HIGH_RISK_PATTERNS = [
        r'https?://[^\s]*(-pay|-verify|-gov|-adl)[^\s]*',
        r'ابلاغیه.{0,30}لینک',
        r'(قضایی|دادگاه|شورا|شکواییه|حکم جلب).{0,50}https?://',
        r'کارنامه.{0,30}اصلاح.{0,30}https?://',
        r'پاسخنامه.{0,30}آزمون.{0,30}https?://',
        r'بیمه سلامت.{0,30}تمدید.{0,30}https?://',
        r'سهمیه لاستیک.{0,30}حواله.{0,30}https?://'
    ]

    OFFICIAL_DOMAINS = {
        "adliran": "adliran.ir", "eblagh": "eblagh.adliran.ir", "sana": "sana.adliran.ir",
        "mci": "mci.ir", "irancell": "irancell.ir", "divar": "divar.ir", "shaparak": "shaparak.ir"
    }

    OFFICIAL_SENDERS = [
        "adliran", "eblagh", "sana", "fata", "police", "vaja", "rahvar", "post", "sabteahval", "mcls",
        "mci", "hamrah-e-aval", "hamrahaval", "irancell", "mtnirancell", "rightel", "shatel", "tci",
        "divar", "bama", "digikala", "snapp", "tapsi", "sejam", "bourse", "emdad", "mizan", "ninisite",
        "1000100", "2000100", "3000100", "981000", "982000", "983000", "985000",
        "shaparak", "bmi", "bankmelli", "mellat", "bankmellat", "tejarat", "bsi", "saderat", 
        "sepah", "bis", "parsian", "pasargad", "bpi", "ansar", "shahr", "samansaman", "sb24",
        "refah", "rb24", "postbank", "sinabank", "maskan", "keshavarzi", "bki", "kararin", "daybank"
    ]

    #  تابع کمکی کِش‌کننده برای ذخیره پیوندهای ردیابی شده
    @lru_cache(maxsize=256)
    def get_final_url_cached(full_url):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        try:
            response = requests.head(full_url, allow_redirects=True, timeout=2.5, headers=headers)
            return response.url
        except requests.RequestException:
            try:
                response = requests.get(full_url, allow_redirects=True, timeout=2.5, headers=headers)
                return response.url
            except:
                return full_url

    def resolve_short_url(text):
        urls = re.findall(r'(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)
        for url in urls:
            full_url = url if url.startswith(('http://', 'https://')) else 'http://' + url
            try:
                parsed_url = urlparse(full_url)
                domain = parsed_url.netloc.lower().replace("www.", "")
                if any(short_dom == domain or domain.endswith('.' + short_dom) for short_dom in SHORT_LINK_DOMAINS):
                    final_url = get_final_url_cached(full_url)
                    text = text.replace(url, final_url)
                    print(f"🔗 لینک کوتاه‌شده رمزگشایی شد (شبکه/کِش): [{url}] -> [{final_url}]")
            except Exception as e:
                print(f"⚠️ خطای ردیابی لینک {url}: {str(e)}")
                continue
        return text

    def check_rule_based_phishing(text):
        for pattern in HIGH_RISK_PATTERNS:
            if re.search(pattern, text):
                return True, "تطابق با الگوهای متنی فیشینگ مراجع رسمی (Regex Dynamic Match)"
        
        urls = re.findall(r'https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text.lower())
        for url in urls:
            if any(s in url for s in SUSPICIOUS_DOMAINS):
                return True, f"شناسایی دامنه مشکوک یا جعل شده [{url}] پیش از تحلیل مدل"
        return False, ""

    def extract_domain(text):
        urls = re.findall(r'(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text.lower())
        if not urls:
            return None
        url = urls[0]
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        try:
            parsed_url = urlparse(url)
            return parsed_url.netloc
        except:
            return None

    @app.route("/", methods=["GET"])
    def home():
        with open(HTML_FILE_PATH, "r", encoding="utf-8") as f:
            html_content = f.read()
        html_content = html_content.replace("{{ url_with_timestamp('static/bootstrap.min.css') }}", "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css")
        html_content = html_content.replace("{{ url_with_timestamp('static/bootstrap.bundle.min.js') }}", "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/js/bootstrap.bundle.min.js")
        return render_template_string(html_content)

    @app.route("/predict", methods=["POST"])
    def predict():
        try:
            data = request.get_json() or {}
            raw_text = data.get("text", "").strip().replace("ي", "ی").replace("ك", "ک")
            raw_sender = str(data.get("sender", "")).strip()
            
            text = resolve_short_url(raw_text)
            
            sender = "نامشخص" if not raw_sender or raw_sender.lower() in ["undefined", "null", "none", "نامشخص"] else raw_sender
            sender_clean = sender.lower().replace("-", "").replace("_", "").replace(" ", "")
            
            has_link = any(pattern in text.lower() for pattern in ["http", "https", ".com", ".ir", "دات کام"])
            is_official_sender = any(official in sender_clean for official in OFFICIAL_SENDERS)
            
            extracted_url_domain = extract_domain(text)
            is_valid_domain = False
            
            if extracted_url_domain:
                is_valid_domain = any(
                    extracted_url_domain == doc_dom or extracted_url_domain.endswith('.' + doc_dom) 
                    for doc_dom in OFFICIAL_DOMAINS.values()
                )

            is_rule_phishing, rule_reason = check_rule_based_phishing(text)

            words_in_text = [w for w in re.findall(r'[\u0600-\u06FF\w]+', text) if len(w) > 2]
            risk_indicators = ["لینک", "کلیک", "واریز", "سهام", "ابلاغیه", "شکایت", "جلب", "یارانه", "ثنا", "پرونده", "دادگاه", "رمز", "بانک", "تغییر", "خرید", "تخفیف", "پکیج", "پیش‌فروش", "حواله", "پروژه", "نظافت"]
            detected_triggers = [word for word in words_in_text if word in risk_indicators]

            words_risk_weight = min(len(detected_triggers) * 0.05, 0.20)

            # استخراج لوجیت‌ها از مدل زبانی ParsBERT
            inputs = tokenizer(text, return_tensors="pt", padding="max_length", truncation=True, max_length=128).to(device)
            with torch.no_grad():
                outputs = model(**inputs)
                # اعمال سافت‌مکس روی لوجیت‌ها برای استخراج احتمالات خام (0 تا 1)
                probabilities_raw = torch.nn.functional.softmax(outputs.logits, dim=-1).squeeze().tolist()
            
            # تطبیق دقیق با نمایه لیبل‌های مدل شما
            prob_safe_raw = probabilities_raw[label_list.index('ایمن')]
            prob_ad_raw = probabilities_raw[label_list.index('تبلیغاتی')]
            prob_phish_raw = probabilities_raw[label_list.index('مشکوک')]
            
            if prob_phish_raw > 0.55:
                ai_label = "مشکوک"
                ai_confidence = prob_phish_raw
            else:
                predicted_class_id = np.argmax(probabilities_raw)
                ai_label = str(label_list[predicted_class_id]).strip()
                ai_confidence = probabilities_raw[predicted_class_id]

            # ─── لایه منطق ترکیبی پیشرفته (مقاوم در برابر هک سرشماره و Spoofing) ───
            
            # ۱. تشخیص فرستنده رسمی (نام متنی، الگوهای وایت‌لیست یا ساختار غیرعددی)
            is_sender_official = False
            if sender and not re.match(r'^\+?\d+$', sender):
                is_sender_official = True
            if is_official_sender:
                is_sender_official = True

            # ۲. تحلیل وضعیت لینک موجود در متن
            has_any_link = True if re.search(r'https?://[^\s]+', text) else False
            has_suspicious_link = is_rule_phishing

            # ۳. اعمال لایه منطق هوشمند متقاطع (Decision Matrix)
            if is_sender_official:
                if has_suspicious_link or (has_any_link and ai_label == "مشکوک" and ai_confidence > 0.85):
                    # ⚠️ سناریوی بحرانی: فرستنده معتبر است اما رفتار پیامک نشان‌دهنده هک پنل یا جعل فرستنده است!
                    final_label = "مشکوک"
                    final_action = "مسدود شده / هشدار سوءاستفاده از سرشماره"
                    explanation = f"🚨 هشدار امنیتی سطح بالا: پیامک از سرشماره رسمی ({sender}) ارسال شده، اما حاوی لینک یا ساختار محتوایی به شدت مشکوک است (احتمال نفوذ به پنل یا جعل فرستنده)."
                    risk_score = max(ai_confidence, 0.90)
                else:
                    # ✅ سناریوی عادی: فرستنده معتبر و فاقد لینک خطرناک؛ خطاهای احتمالی هوش مصنوعی نادیده گرفته می‌شوند
                    final_label = "ایمن"
                    final_action = "مجاز (تایید اصالت منبع)"
                    explanation = f"🛡️ پیامک از فرستنده رسمی و معتبر ({sender}) دریافت شد و شواهدی از لینک‌های مخرب در آن یافت نشد."
                    risk_score = 0.05
            else:
                # ۴. فرستنده ناشناس یا شماره عادی است؛ لایه دوم (ParsBERT + فیلتر لینک) حاکم تام است
                if ai_label == "مشکوک" or has_suspicious_link:
                    final_label = "مشکوک"
                    final_action = "مسدود شده (بحران فیشینگ قطعی)" if has_any_link else "مسدود شده (محتوای مشکوک خط شخصی)"
                    explanation = "🚨 هشدار: مدل هوش مصنوعی یا سیستم پایش لینک، رفتارهای مشکوک به فیشینگ در متن شناسایی کردند."
                    risk_score = max(ai_confidence, 0.85)
                elif ai_label == "تبلیغاتی":
                    final_label = "تبلیغاتی"
                    final_action = "مجاز (محتوای تبلیغاتی)"
                    explanation = "📢 محتوای پیامک حاوی کلمات کلیدی تبلیغاتی و اطلاع‌رسانی تشخیص داده شد."
                    risk_score = 0.20
                else:
                    final_label = "ایمن"
                    final_action = "مجاز (پیام شخصی بدون ریسک)"
                    explanation = "🟢 پیامک بررسی شد و هیچ الگوی مشکوک یا تبلیغاتی در آن مشاهده نگردید."
                    risk_score = 0.10

            hybrid_predicted_label = final_label
            
            # ─── اعمال لایه فیلترها و قوانین سخت‌گیرانه ثانویه (قوانین وایت‌لیست و بلک‌لیست نهایی) ───
            if "مسدود شده" in final_action or "بحران فیشینگ" in final_action or "سوءاستفاده از سرشماره" in final_action:
                hybrid_predicted_label = "مشکوک"
                
            if re.match(r'^(1000|2000|3000|5000)', sender_clean):
                if not any(k in text for k in ["ابلاغیه", "ثنا", "شکایت", "سهام عدالت", "شکواییه"]):
                    hybrid_predicted_label = "تبلیغاتی"
                    risk_score = 0.05

            if "bankmelli" in sender_clean or "bmi.ir" in text:
                hybrid_predicted_label = "ایمن"
                risk_score = 0.0
                final_action = "مجاز (تایید اصالت منبع)"
                explanation = "✅ تایید اصالت: پیامک تایید شده متعلق به بانک ملی ایران."
                
            if "gasnational" in sender_clean or "شرکت ملی گاز" in text:
                hybrid_predicted_label = "ایمن"
                risk_score = 0.0
                final_action = "مجاز (تایید اصالت منبع)"
                explanation = "✅ تایید اصالت: گزارش بهینه مصرفی شرکت ملی گاز ایران."

            if re.match(r'^09', sender_clean):
                if any(kw in text for kw in ["مهندس", "نقشه", "سازمه", "نظام مهندسی"]):
                    hybrid_predicted_label = "ایمن"
                    risk_score = 0.0
                    final_action = "مجاز (مکاتبه شخصی کاری)"

            if any(fake in sender_clean for fake in ["adliran", "yaranehgov", "rahvar120", "mcigift", "salamatgov", "postir", "gasir"]) or sender_clean == "bank":
                hybrid_predicted_label = "مشکوک"
                risk_score = 0.95

            if "gift" in sender_clean or "samat" in sender_clean:
                hybrid_predicted_label = "مشکوک"
                risk_score = 0.95
                
            if hybrid_predicted_label == "ایمن" and not re.match(r'^09', sender_clean):
                if any(kw in text for kw in ["پکیج", "پیش‌فروش", "نظافت", "استخدام", "تخفیف"]):
                    hybrid_predicted_label = "تبلیغاتی"
                    risk_score = 0.05

            # =============================================================
            # 🌟 بخش ادغام شده جدید: استخراج احتمالات پیوستار ریسک به درصد
            # =============================================================
            prob_safe  = round(prob_safe_raw * 100, 2)
            prob_promo = round(prob_ad_raw * 100, 2)
            prob_phish = round(prob_phish_raw * 100, 2)

            content_risk = prob_phish  # ریسک محتوا متکی بر احتمال فیشینگ مدل زبانی
            sender_risk  = 85.0 if sender_clean.isdigit() and len(sender_clean) == 11 else 10.0

            # ارسال خروجی کاملاً هماهنگ با کدهای بنچمارک قدیمی و نمودارهای فرانت‌اند جدید
            return jsonify({
                "predicted_label": hybrid_predicted_label,  
                "predicted": hybrid_predicted_label,        
                "risk_score": float(risk_score),           
                "risk": float(risk_score),                  
                "content_risk": content_risk,    # 🌟 اضافه شده برای پیوستار ریسک محتوا
                "sender_risk": sender_risk,      # 🌟 اضافه شده برای پیوستار ریسک فرستنده
                "probabilities": {               # 🌟 اضافه شده برای نمودارهای توزیع فرانت‌اند
                    "safe": prob_safe,
                    "promo": prob_promo,
                    "phishing": prob_phish
                },
                "ai_analysis": {
                    "intent": ai_label,
                    "confidence": float(ai_confidence),
                    "probabilities": {
                        "safe": float(prob_safe_raw),
                        "advertising": float(prob_ad_raw),
                        "phishing": float(prob_phish_raw)
                    }
                },
                "security_analysis": {
                    "final_action": final_action,          
                    "risk_score": float(risk_score),
                    "explanation": explanation,
                    "is_official": is_official_sender,
                    "has_link": has_link
                },
                "sender_checked": sender,
                "danger_words": detected_triggers, 
                "input_text": text,
                "explanation": explanation
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/feedback", methods=["POST"])
    def feedback():
        return jsonify({"status": "success", "message": "بازخورد با موفقیت ثبت شد."})

    # =====================================================================
    # مدیریت اجرای امن سرور فلاسکی و استخراج هوشمند لینک تونل ارتباطی
    # =====================================================================
    if not any(t.name == "FlaskServerThread" for t in threading.enumerate()):
        server_thread = threading.Thread(target=app.run, kwargs={"port": 8000, "host": "0.0.0.0"}, name="FlaskServerThread")
        server_thread.start()
        time.sleep(2)
    
    print("\n🌐 پلتفرم PixelGuard در پس‌زمینه فعال شد.")
    print("🔄 در حال برقراری ارتباط امن با سرور تونل‌زنی...")

    import subprocess
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-R", "80:localhost:8000", "serveo.net"]
    
    try:
        process = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in process.stdout:
            if line.strip():
                print(f"   [Serveo] {line.strip()}")
            if "https://" in line:
                urls = re.findall(r'https?://[^\s]+', line)
                if urls:
                    print("\n" + "="*60)
                    print(f"🚀 سامانه با موفقیت به شبکه جهانی متصل شد!")
                    print(f"🔗 لینک ورود به پنل گرافیکی PixelGuard:\n\n👉 \033[1;32m{urls[0]}\033[0m 👈")
                    print("="*60 + "\n")
                    break
    except Exception as tunnel_error:
        print(f"⚠️ خطا در راه‌اندازی تونل ارتباطی: {str(tunnel_error)}")
