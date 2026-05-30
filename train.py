import os
import numpy as np
import joblib
import torch  
from datasets import load_dataset
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    TrainingArguments, 
    Trainer,
    DataCollatorWithPadding 
)
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.utils.class_weight import compute_class_weight 


# =====================================================================
#  INITIALIZATION & DATA LOADING
# =====================================================================
MODEL_NAME = "HooshvareLab/bert-base-parsbert-uncased"
DATA_PATH = "/content/drive/MyDrive/PixelGuard/sms_dataset_final.csv"
OUTPUT_DIR = "/content/drive/MyDrive/models/parsbert-sms"
TMP_CHECKPOINT_DIR = "./results" # ذخیره چک‌پوینت‌های موقت روی هارد سریع کولب

# بارگذاری مجموعه داده متنی
raw_dataset = load_dataset("csv", data_files=DATA_PATH, split="train", on_bad_lines="skip")

# تقسیم هوشمند دیتا به آموزش و اعتبارسنجی (تست)
dataset_split = raw_dataset.train_test_split(test_size=0.15, seed=42)

#  استخراج داینامیک برچسب‌ها برای جلوگیری از خطای املایی دیتابیس
label_list = sorted(list(set(raw_dataset["label"])))
label2id = {l: i for i, l in enumerate(label_list)}
id2label = {i: l for i, l in enumerate(label_list)}

# =====================================================================
#  PREPROCESSING & TOKENIZATION
# =====================================================================
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def preprocess_function(examples):
    encodings = tokenizer(
        examples["text"],
        truncation=True,
        max_length=128
    )
    encodings["labels"] = [label2id[l] for l in examples["label"]]
    return encodings

# اعمال توکنایزر روی هر دو بخش داده
encoded_dataset = dataset_split.map(preprocess_function, batched=True, remove_columns=["text", "label"])

#  ساخت کالیتور برای پدینگ دینامیک متن‌ها در هر بچ به اندازه طولانی‌ترین متن همان بچ
data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

# =====================================================================
#  MODEL ARCHITECTURE & MULTI-CLASS METRICS
# =====================================================================
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=len(label_list),
    id2label=id2label,
    label2id=label2id
)

#  محاسبه خودکار وزن کلاس‌ها بر اساس میزان فراوانی آن‌ها در دیتای ترن
train_labels = encoded_dataset["train"]["labels"]
class_weights = compute_class_weight(
    class_weight="balanced",
    classes=np.unique(train_labels),
    y=np.array(train_labels)
)
# انتقال وزن‌ها به فرمت تنسور تورچ و فرستادن به کارت گرافیک
device = "cuda" if torch.cuda.is_available() else "cpu"
class_weights_tensor = torch.tensor(class_weights, dtype=torch.float).to(device)

#  Trainer برای جریمه بیشتر مدل در صورت اشتباه روی کلاس اقلیت
class WeightedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.get("labels")
        outputs = model(**inputs)
        logits = outputs.get("logits")
        
        # اعمال وزن‌ها در محاسبه تابع خطا (CrossEntropyLoss)
        loss_fct = torch.nn.CrossEntropyLoss(weight=class_weights_tensor)
        loss = loss_fct(logits.view(-1, self.model.config.num_labels), labels.view(-1))
        
        return (loss, outputs) if return_outputs else loss


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)

    acc = accuracy_score(labels, predictions)
    f1 = f1_score(labels, predictions, average="macro")
    precision = precision_score(labels, predictions, average="macro", zero_division=0)
    recall = recall_score(labels, predictions, average="macro", zero_division=0)

    return {
        "accuracy": acc,
        "f1_macro": f1,
        "precision_macro": precision,
        "recall_macro": recall
    }

# =====================================================================
#  HYPERPARAMETER CONFIGURATION & TRAINING
# =====================================================================
training_args = TrainingArguments(
    output_dir=TMP_CHECKPOINT_DIR,        
    eval_strategy="epoch",                
    save_strategy="epoch",                
    per_device_train_batch_size=16,       
    per_device_eval_batch_size=16,
    num_train_epochs=3,
    logging_steps=50,
    load_best_model_at_end=True,          
    metric_for_best_model="f1_macro",     
    greater_is_better=True,
    fp16=True,                           
    report_to="none"                      
)

# استفاده از کلاس وزنی سفارشی 
trainer = WeightedTrainer(
    model=model,
    args=training_args,
    train_dataset=encoded_dataset["train"],
    eval_dataset=encoded_dataset["test"], 
    data_collator=data_collator,         
    compute_metrics=compute_metrics
)

print("🚀 فاز آموزش هوشمند مدل با مانیتورینگ آنلاین و پیشگیری از تنبلی مدل آغاز شد...")
trainer.train()

# =====================================================================
#  SERIALIZATION & PERSISTENCE (FINAL DRIVE SAVE)
# =====================================================================
print(f"📦 در حال انتقال و ذخیره‌سازی نسخه نهایی برترین مدل در گوگل درایو: {OUTPUT_DIR}")
os.makedirs(OUTPUT_DIR, exist_ok=True)
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
joblib.dump(label_list, os.path.join(OUTPUT_DIR, "labels.joblib"))

print("✅ فرآیند با موفقیت پایان یافت. بهترین مدلِ متوازن‌سازی‌شده در درایو مستقر شد.")
