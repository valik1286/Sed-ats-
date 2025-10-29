import datetime
import os
import json
import re
import sys
import ast
import time
import importlib.util
import threading # Додано для input_with_timeout
import queue     # Додано для input_with_timeout

AI_NAME = "Sed"
VERSION = "1.5.2.6 beta" # Оновлена версія з урахуванням виявлених особливостей
AUTHOR = "valik1286"

ISED_LIBRARY_FILE = "ised.txt"
LEARNED_DATA_FILE = "learned_data.json"
UNKNOWN_DATA_FILE = "unknown_data.json"
ARCHIVE_FILE = os.path.join("mods", "архів.txt")
LOG_FILE = "chat_log.txt"
MODS_FOLDER = "mods"
ATSED_FILE = "atsed.txt"
SECURITY_LOG_FILE = "security_log.txt"

chat_history = []
learned_data = {}
ised_data = {}
atsed_data = {}
unknown_data = {}
mods_data = {} # Для .sed та .txt модів
code_mods = {} # Для .sed.py модів
python_modules = {} # Словник для загальних .py модулів, доступних для імпорту
sed_has_code_error = False

# --- Константи для Security Timer (як у твоїй 1.3.1 Beta) ---
TIMEOUT_BEFORE_AUTH = 120  # 5 хвилин бездіяльності перед активацією авторизації
AUTH_TIMEOUT = 300         # 5 хвилин на проходження всіх кроків авторизації
SECURITY_PASSWORD = "1486"
SECURITY_VERSION = "sed1.3.2"
SECURITY_COMMAND = "connect sed"

# --- Встановлення робочого каталогу ---
try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
except Exception as e:
    print(f"DEBUG: Помилка встановлення робочого каталогу: {e}")

# --- Функції для логування ---
def log_message(message, sender="User"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {sender}: {message}\n")
    except Exception as e:
        print(f"DEBUG: Помилка запису в лог '{LOG_FILE}': {e}")

def log_security_threat(timestamp, user_input, reason):
    """Записує інформацію про заблоковану загрозу до файлу security_log.txt."""
    try:
        with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] Загроза виявлена! Ввід: '{user_input}' | Причина: {reason}\n")
    except IOError as e:
        print(f"DEBUG: Помилка запису в лог безпеки '{SECURITY_LOG_FILE}': {e}")

# --- Функції для завантаження/збереження даних ---
def load_data(filepath, as_regex=False):
    data = {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    if as_regex:
                        data[re.compile(rf'\b{re.escape(key)}\b', re.IGNORECASE)] = value.strip()
                    else:
                        data[key] = value.strip()
    except FileNotFoundError:
        print(f"DEBUG: Файл бібліотеки '{filepath}' не знайдено. Продовжую без нього.")
    except Exception as e:
        print(f"DEBUG: Помилка завантаження '{filepath}': {e}")
    return data

def load_json(path):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except json.JSONDecodeError:
        print(f"DEBUG: Файл '{path}' пошкоджений або порожній. Створюю новий.")
    except Exception as e:
        print(f"DEBUG: Помилка завантаження JSON '{path}': {e}")
    return {}

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except IOError as e:
        print(f"DEBUG: Помилка збереження '{path}': {e}")
    except Exception as e:
        print(f"DEBUG: Невідома помилка збереження JSON '{path}': {e}")

def append_to_archive(word, meaning, explanation=""):
    """Додає нове слово та його значення до архівного файлу."""
    if not os.path.exists(MODS_FOLDER):
        os.makedirs(MODS_FOLDER)
    try:
        with open(ARCHIVE_FILE, "a", encoding="utf-8") as f:
            line = f"{word}/{meaning}"
            if explanation:
                line += f"/{explanation}"
            f.write(line + "\n")
    except Exception as e:
        print(f"DEBUG: Помилка запису в архів '{ARCHIVE_FILE}': {e}")

# --- Функції для управління модами ---
def load_mods():
    global mods_data, code_mods, python_modules
    mods_data, code_mods, python_modules = {}, {}, {} # Обнуляємо дані перед завантаженням
    if not os.path.exists(MODS_FOLDER):
        os.makedirs(MODS_FOLDER)
        print(f"DEBUG: Папку '{MODS_FOLDER}' створено.")
        return
    for fn in os.listdir(MODS_FOLDER):
        path = os.path.join(MODS_FOLDER, fn)
        if os.path.isfile(path):
            if fn.endswith(".sed") or fn.endswith(".txt"):
                print(f"DEBUG: Завантажую словниковий мод: {fn}")
                mods_data.update(load_data(path))
            elif fn.endswith(".sed.py"):
                try:
                    name = fn[:-len(".sed.py")]
                    spec = importlib.util.spec_from_file_location(name, path)
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[name] = mod
                    spec.loader.exec_module(mod)
                    if hasattr(mod, 'COMMAND_NAME') and hasattr(mod, 'run_plugin'):
                        code_mods[mod.COMMAND_NAME.lower()] = mod.run_plugin
                        print(f"DEBUG: Завантажено кодовий мод: {name}")
                except Exception as e:
                    print(f"DEBUG: Помилка завантаження кодового моду '{fn}': {e}")
            elif fn.endswith(".py"):
                try:
                    module_name = fn[:-len(".py")]
                    # Перевіряємо, чи це не .sed.py файл, який неправильно назвали .py
                    if fn.endswith(".sed.py"):
                       continue # Пропускаємо, бо це вже має бути оброблено як кодовий мод
                    
                    spec = importlib.util.spec_from_file_location(module_name, path)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                    python_modules[module_name] = module # Зберігаємо посилання на завантажений модуль
                    print(f"DEBUG: Завантажено Python-модуль: {module_name}")
                except Exception as e:
                    print(f"DEBUG: Помилка завантаження Python-модуля '{fn}': {e}")

def list_mods(mods_folder=MODS_FOLDER):
    if not mods_data and not code_mods and not python_modules:
        return "Sed: Моди не завантажено. Переконайтесь, що вони в папці 'mods'."
    
    response = "Sed: Завантажені моди:\n"
    if mods_data:
        response += "  Словникові (.sed/.txt):\n"
        loaded_dict_mods = set()
        for fn in os.listdir(MODS_FOLDER):
            path = os.path.join(MODS_FOLDER, fn)
            if os.path.isfile(path) and (fn.endswith(".sed") or fn.endswith(".txt")):
                loaded_dict_mods.add(fn)
        if loaded_dict_mods:
            for mod_name in sorted(list(loaded_dict_mods)):
                response += f"    - {mod_name}\n"
        else:
            response += "    (Немає)\n"

    if code_mods:
        response += "  Кодові (.sed.py):\n"
        for cmd_name in sorted(code_mods.keys()):
            response += f"    - {cmd_name} (команда: {cmd_name})\n"
            
    if python_modules:
        response += "  Допоміжні Python-модулі (.py):\n"
        for module_name in sorted(python_modules.keys()):
            response += f"    - {module_name}.py\n"

    return response.strip()

# --- Допоміжні функції ---
def censor(text):
    for pat, rep in atsed_data.items():
        text = pat.sub(rep, text)
    return text

# --- Функція для вводу з таймаутом (імітація input_with_timeout з твоєї 1.3.1 Beta) ---
def input_with_timeout(prompt, timeout):
    """Отримує ввід користувача з таймаутом."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    q = queue.Queue()

    def _input():
        try:
            q.put(sys.stdin.readline().strip())
        except EOFError: # Обробка Ctrl+D
            q.put(None)

    thread = threading.Thread(target=_input)
    thread.daemon = True # Дозволяє програмі вийти, навіть якщо потік не завершився
    thread.start()

    try:
        # Отримати ввід протягом періоду таймауту
        user_input = q.get(timeout=timeout)
        return user_input
    except queue.Empty:
        return None # Таймаут спрацював
    # Немає блоку finally для потоків, просто дозволяємо йому завершитись або програмі вийти

# --- ВБУДОВАНА ЛОГІКА SECURITY TIMER та авторизації (як у твоїй 1.3.1 Beta) ---
def security_authorization():
    """Проводить процедуру авторизації."""
    start_auth_time = time.time()
    
    # Крок 1: Ввід пароля
    while True:
        elapsed = time.time() - start_auth_time
        if elapsed > AUTH_TIMEOUT:
            print("Sed: ❌ Час авторизації вичерпано. Система виходить з ладу. Перезапустіть Sed.")
            sys.exit(1)
        
        # Відображення часу, що залишився
        remaining_time = max(0, AUTH_TIMEOUT - int(elapsed))
        user_input = input(f"Sed: 🔐 Введіть пароль протягом {remaining_time} секунд: ").strip()
        log_message(user_input, "User (Auth)") # Логуємо ввід під час авторизації
        if user_input == SECURITY_PASSWORD:
            break
        print("Sed: Невірний пароль.")

    # Крок 2: Ввід версії
    while True:
        elapsed = time.time() - start_auth_time
        if elapsed > AUTH_TIMEOUT:
            print("Sed: ❌ Час авторизації вичерпано. Система виходить з ладу. Перезапустіть Sed.")
            sys.exit(1)

        remaining_time = max(0, AUTH_TIMEOUT - int(elapsed))
        user_input = input(f"Sed: 📦 Введіть версію (залишилось {remaining_time} секунд): ").strip()
        log_message(user_input, "User (Auth)")
        if user_input == SECURITY_VERSION:
            break
        print("Sed: Невірна версія.")

    # Крок 3: Ввід команди
    while True:
        elapsed = time.time() - start_auth_time
        if elapsed > AUTH_TIMEOUT:
            print("Sed: ❌ Час авторизації вичерпано. Система виходить з ладу. Перезапустіть Sed.")
            sys.exit(1)
        
        remaining_time = max(0, AUTH_TIMEOUT - int(elapsed))
        user_input = input(f"Sed: 🔌 Введіть команду (залишилось {remaining_time} секунд): ").strip()
        log_message(user_input, "User (Auth)")
        if user_input == SECURITY_COMMAND:
            break
        print("Sed: Невірна команда.")
    
    print("Sed: ✅ Авторизація успішна. Система працює стабільно.")


def simulate_ats_connection_failure():
    print("Sed: Спроба підключення до АТС...")
    print("error translity\nATS перезавантажується")
    for _ in range(3):
        print("error translity signal...")
        time.sleep(0.5)
    print("no signal ATS\nATS не знайдено!\n--- Спроба завершена ---")

def simulate_reboot():
    global sed_has_code_error
    print("Sed: Перезавантаження...")
    time.sleep(0.5)
    report = ""
    try:
        with open(__file__, 'r', encoding='utf-8') as f:
            ast.parse(f.read())
        report = "Sed: Аналіз завершено. Помилок у коді не виявлено."
        sed_has_code_error = False
    except Exception as e:
        sed_has_code_error = True
        report = f"Sed: Виявлено проблему у коді: {e}"
    print("Sed: Модулі завантажено.\n" + report)
    load_mods()

def analyze_unknown_phrases():
    print("Sed: Аналіз останніх незрозумілих запитів...")
    found = []
    for entry_idx in range(len(chat_history) -1, max(-1, len(chat_history) - 21), -1):
        msg = chat_history[entry_idx].lower().strip()
        
        is_known = False
        # Перевірка на точний збіг та наявність у словниках
        for d in (ised_data, learned_data, mods_data):
            if msg in d:
                is_known = True
                break
            for k_original, v in d.items():
                if not isinstance(k_original, re.Pattern) and msg in k_original.lower(): # Запит є підрядком ключа
                    is_known = True
                    break
                search_pattern = k_original if isinstance(k_original, re.Pattern) else re.compile(rf'\b{re.escape(k_original)}\b', re.IGNORECASE)
                if search_pattern.search(msg): # Ключ є підрядком запиту
                    is_known = True
                    break
            if is_known:
                break
        
        if not is_known and msg not in unknown_data and msg not in code_mods:
            unknown_data[msg] = ""
            found.append(msg)
    
    if found:
        print("Sed: Додано нові незрозумілі запити:")
        for f in found:
            print(f"- '{f}'")
        save_json(UNKNOWN_DATA_FILE, unknown_data)
    else:
        print("Sed: Нових незрозумілих запитів не знайдено.")

def analyze_log_for_learning():
    print("Sed: Читання логу чату для автонавчання...")
    if not os.path.exists(LOG_FILE):
        print("Sed: Лог не знайдено.")
        return
    
    new_entries = 0
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            log_lines = f.readlines()
            
            for i, line in enumerate(log_lines):
                if "] User:" in line:
                    user_msg = line.split("] User:", 1)[1].strip().lower()
                    
                    if user_msg.startswith(("вийти", "допомога", "перезавантажся", "connect ats", "аналіз", 
                                            "автотренування", "навчи", "створи", "забудь", "список модів")):
                        continue

                    is_known = False
                    # Перевірка на точний збіг та наявність у словниках
                    for d in (ised_data, learned_data, mods_data):
                        if user_msg in d:
                            is_known = True
                            break
                        for k_original, v in d.items():
                            if not isinstance(k_original, re.Pattern) and user_msg in k_original.lower(): # Запит є підрядком ключа
                                is_known = True
                                break
                            search_pattern = k_original if isinstance(k_original, re.Pattern) else re.compile(rf'\b{re.escape(k_original)}\b', re.IGNORECASE)
                            if search_pattern.search(user_msg): # Ключ є підрядком запиту
                                is_known = True
                                break
                        if is_known:
                            break
                    
                    if not is_known and user_msg not in unknown_data:
                        unknown_data[user_msg] = ""
                        new_entries += 1
                        
    except Exception as e:
        print(f"DEBUG: Помилка читання логу для автонавчання: {e}")
        return
    
    if new_entries:
        print(f"Sed: Додано {new_entries} нових незрозумілих фраз із логу.")
        save_json(UNKNOWN_DATA_FILE, unknown_data)
    else:
        print("Sed: Усі фрази з логу вже опрацьовані.")


def find_approximate_response(msg):
    # Шукаємо в unknown_data, чи є там повний збіг або підрядок
    for key_unknown, val_unknown in unknown_data.items():
        if key_unknown and re.search(r'\b' + re.escape(key_unknown) + r'\b', msg, re.IGNORECASE):
            return val_unknown if val_unknown else None
    return None

def number_to_words(n):
    words = {
        0: "нуль", 1: "один", 2: "два", 3: "три", 4: "чотири", 5: "п'ять",
        6: "шість", 7: "сім", 8: "вісім", 9: "дев'ять", 10: "десять",
        11: "одинадцять", 12: "дванадцять", 13: "тринадцять", 14: "чотирнадцять",
        15: "п'ятнадцять", 16: "шістнадцять", 17: "сімнадцять", 18: "вісімнадцять",
        19: "дев'ятнадцять", 20: "двадцять"
    }
    return words.get(n, str(n))

def calculate_expression(expr):
    try:
        allowed_chars = "0123456789+-*/.() "
        if any(c not in allowed_chars for c in expr):
            return None
        result = eval(expr, {"__builtins__":None}, {})
        if isinstance(result, (int, float)):
            if int(result) == result:
                return number_to_words(int(result))
            else:
                return str(round(result, 4))
        else:
            return None
    except Exception as e:
        print(f"DEBUG: Помилка обчислення виразу '{expr}': {e}")
        return None

def is_code_safe(code_content):
    dangerous_patterns = {
        r"\bos\.remove\b": "видалення файлів (os.remove)",
        r"\bos\.system\b": "виконання системних команд (os.system)",
        r"\bshutil\.rmtree\b": "рекурсивне видалення директорій (shutil.rmtree)",
        r"\bsubprocess\.run\b": "запуск зовнішніх процесів (subprocess.run)",
        r"\bsubprocess\.call\b": "запуск зовнішніх процесів (subprocess.call)",
        r"\bsys\.exit\b": "аварійне завершення програми (sys.exit)",
        r"\bimport\s+os\b": "імпорт модуля 'os'",
        r"\bimport\s+shutil\b": "імпорт модуля 'shutil'",
        r"\bimport\s+subprocess\b": "імпорт модуля 'subprocess'",
        r"\bimport\s+sys\b": "імпорт модуля 'sys' (для sys.exit)",
        r"open\(.*['\"]w['\"].*\)": "відкриття файлу в режимі запису ('w')", 
        r"open\(.*['\"]a['\"].*\)": "відкриття файлу в режимі дозапису ('a')",
        r"open\(.*['\"]x['\"].*\)": "відкриття файлу в режимі ексклюзивного створення ('x')",
        r"\beval\(": "виконання рядка як коду (eval)",
        r"\bexec\(": "виконання рядка як коду (exec)",
    }
    
    for pattern, reason in dangerous_patterns.items():
        if re.search(pattern, code_content, re.IGNORECASE):
            if "open(" in pattern:
                # Дозволяємо open() тільки якщо є явне відкриття для читання
                if not re.search(r"open\(.*['\"]r['\"].*\)", code_content, re.IGNORECASE):
                    return False, f"Виявлено потенційно небезпечну операцію: {reason}"
            else:
                return False, f"Виявлено потенційно небезпечну операцію: {reason}"
    
    if "del os" in code_content or "del shutil" in code_content or "del subprocess" in code_content:
        return False, "Виявлено спробу видалення системного модуля."

    return True, "Код безпечний для створення."


def clear_log():
    """Очищає файл логу повністю."""
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("")  # Просто перезаписуємо файл порожнім рядком
        print("Sed: Лог успішно очищено.")
    except Exception as e:
        print(f"Sed: Помилка очищення логу: {e}")

def import_module_by_path(module_path):
    """Імпортує Python-модуль за вказаним шляхом."""
    try:
        module_name = os.path.splitext(os.path.basename(module_path))[0]
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        python_modules[module_name] = module
        print(f"Sed: Модуль '{module_name}' імпортовано з '{module_path}'.")
        return f"Sed: Модуль '{module_name}' успішно імпортовано."
    except Exception as e:
        print(f"Sed: Помилка імпорту модуля: {e}")
        return f"Sed: Помилка імпорту модуля: {e}"

def import_mod_pack(pack_path):
    """Імпортує мод-пак з папки або zip-файлу."""
    try:
        if pack_path.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(pack_path, 'r') as zip_ref:
                zip_ref.extractall(MODS_FOLDER)
            print(f"Sed: Мод-пак з '{pack_path}' розпаковано у '{MODS_FOLDER}'.")
        elif os.path.isdir(pack_path):
            import shutil
            for item in os.listdir(pack_path):
                s = os.path.join(pack_path, item)
                d = os.path.join(MODS_FOLDER, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)
            print(f"Sed: Мод-пак з папки '{pack_path}' скопійовано у '{MODS_FOLDER}'.")
        else:
            return "Sed: Неправильний формат мод-пака. Вкажіть шлях до zip або папки."
        load_mods()
        return "Sed: Мод-пак успішно імпортовано та моди перезавантажено."
    except Exception as e:
        print(f"Sed: Помилка імпорту мод-пака: {e}")
        return f"Sed: Помилка імпорту мод-пака: {e}"

def delete_mod(identifier, mods_folder="mods"):
    """Видаляє мод за номером або назвою (шукає файл у папці, навіть якщо він пошкоджений)."""
    files = [f for f in os.listdir(mods_folder) if f.endswith(".py") or f.endswith(".sed") or f.endswith(".sed.py") or f.endswith(".txt")]
    try:
        if identifier.isdigit():
            idx = int(identifier) - 1
            if 0 <= idx < len(files):
                os.remove(os.path.join(mods_folder, files[idx]))
                print(f"Мод {files[idx]} видалено.")
        else:
            if identifier in files:
                os.remove(os.path.join(mods_folder, identifier))
                print(f"Мод {identifier} видалено.")
            else:
                # Спроба видалити файл напряму, навіть якщо він не у списку
                file_path = os.path.join(mods_folder, identifier)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"Мод {identifier} видалено (знайдено напряму).")
                else:
                    print(f"Файл {identifier} не знайдено для видалення.")
    except Exception as e:
        print(f"Помилка при видаленні: {e}")

def show_mod_code(mod_name, mods_folder=MODS_FOLDER, max_lines=400):
    """Показує код мода. Якщо код > max_lines, видає помилку і кількість рядків."""
    file_path = os.path.join(mods_folder, mod_name)
    if not os.path.exists(file_path):
        return f"Sed: Файл '{mod_name}' не знайдено."
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        total_lines = len(lines)
        if total_lines > max_lines:
            return f"Sed: Код дуже великий ({total_lines} рядків). Перегляд заборонено."
        code = "".join(lines)
        return f"Sed: Код моду '{mod_name}':\n" + code
    except Exception as e:
        return f"Sed: Помилка читання файлу '{mod_name}': {e}"

def get_response(msg):
    global sed_has_code_error
    msg_l = msg.lower().strip()
    chat_history.append(msg)
    current_time_str_full = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current_time_str_short = datetime.datetime.now().strftime("%H:%M")

    # --- Додаємо розбір аргументів для системних команд ---
    tokens = msg_l.split()
    cmd = tokens[0] if tokens else ""
    args = tokens[1:] if len(tokens) > 1 else []

    if cmd == "очисти" and args and args[0] == "лог":
        clear_log()
        return "Sed: Лог очищено."

    if cmd == "список" and args and args[0] == "модів":
        return list_mods()

    if cmd == "видали" and args and args[0] == "мод":
        # Якщо є аргумент — одразу видаляємо
        if len(args) > 1:
            identifier = args[1]
            delete_mod(identifier)
            return f"Sed: Спроба видалити мод '{identifier}'."
        # Якщо аргументу немає — виводимо список
        mods_list = []
        files = [f for f in os.listdir(MODS_FOLDER) if f.endswith(".py") or f.endswith(".sed") or f.endswith(".sed.py") or f.endswith(".txt")]
        if not files:
            return "Sed: Моди не знайдено для видалення."
        mods_list.append("Список модів для видалення:")
        for i, mod in enumerate(files, 1):
            mods_list.append(f"{i}. {mod}")
        mods_list.append("\nВведіть номер або назву моду для видалення:")
        return "\n".join(mods_list)

    if cmd == "показати" and args and args[0] == "код" and len(args) > 1:
        mod_name = " ".join(args[1:])
        return show_mod_code(mod_name)

    # --- Обробка запиту, що починається з "

    # --- ПЕРШИЙ КРОК: Перевірка вводу користувача на заборонені слова (ATSED) ---
    for pattern, replacement in atsed_data.items():
        if pattern.search(msg_l):
            response = replacement
            if sed_has_code_error:
                response += " error code..."
            return censor(response)

    # --- Обробка системних команд ---
    if msg_l == "вийти":
        return "До побачення!"
    
    if msg_l == "допомога":
        help_text = (
            "Команди:\n"
            "- вийти\n"
            "- допомога\n"
            "- перезавантажся\n"
            "- аналіз (аналізує незрозумілі запити з поточної сесії)\n"
            "- автотренування (аналізує лог чату для навчання)\n"
            "- навчи [слово] це [значення] - додати нове слово до словника Sed\n"
            "- забудь [слово] - видалити вивчений запис\n"
            "- список модів - показати завантажені моди\n"
            "- створи [назва] [формат] [код] - створити новий мод (формат без крапки, наприклад, 'py', 'sedpy', 'txt', 'sed')\n"
            "- connect ats (підключити ATS-модуль)\n"
            "- очисти лог - повністю очистити лог чату\n"
            "- імпорт (шлях_до_модуля.py) - імпортувати Python-модуль за шляхом\n"
            "- імпорт мод пака [шлях_до_папки_або_zip] - імпортувати мод-пак (папка або zip)\n"
            "- видали мод [номер або назва] - видалити мод з папки mods\n"
            "- створити інтерактивно [назва] [формат] - створити файл у інтерактивному режимі\n"
            "- показати код [назва_модуля] - показати код моду (до 400 рядків)\n"
        )
        if code_mods:
            help_text += "\nДоступні команди кодових модів:\n"
            for cmd in code_mods.keys():
                help_text += f"- {cmd}\n"
        return censor(help_text)

    if msg_l == "перезавантажся":
        simulate_reboot()
        return "Sed: Перезавантаження завершено."
    
    if msg_l == "connect ats":
        simulate_ats_connection_failure()
        return "Sed: Підключення не вдалося (імітація)."
    
    if msg_l == "аналіз":
        analyze_unknown_phrases()
        return "Sed: Аналіз завершено."
    
    if msg_l == "автотренування":
        analyze_log_for_learning()
        return "Sed: Автотренування завершено."

    if msg_l == "список модів":
        return list_mods()

    # --- Обробка команди 'навчи' ---
    learn_match = re.match(r"навчи\s+(.+?)\s+це\s+(.+)", msg_l)
    if learn_match:
        word = learn_match.group(1).strip()
        meaning = learn_match.group(2).strip()
        learned_data[word] = meaning
        save_json(LEARNED_DATA_FILE, learned_data)
        append_to_archive(word, meaning)
        response = f"Sed: Зрозумів! '{word}' тепер означає '{meaning}'."
        if sed_has_code_error:
            response += " error code..."
        return censor(response)

    # --- Нова команда "забудь" ---
    forget_match = re.match(r"забудь\s+(.+)", msg_l)
    if forget_match:
        word_to_forget = forget_match.group(1).strip()
        if word_to_forget in learned_data:
            del learned_data[word_to_forget]
            save_json(LEARNED_DATA_FILE, learned_data)
            response = f"Sed: Забув '{word_to_forget}'."
        elif word_to_forget in unknown_data:
            del unknown_data[word_to_forget]
            save_json(UNKNOWN_DATA_FILE, unknown_data)
            response = f"Sed: Видалив '{word_to_forget}' зі списку незрозумілих фраз."
        else:
            response = f"Sed: '{word_to_forget}' не знайдено у вивчених або незрозумілих фразах."
        if sed_has_code_error:
            response += " error code..."
        return censor(response)

    # --- Обробка команди 'Створи' ---
    create_match = re.match(r"створи\s+([^\s]+)\s+([^\s]+)\s+(.+)", msg, re.IGNORECASE | re.DOTALL)
    if create_match:
        file_name = create_match.group(1)
        file_format_input = create_match.group(2).lower()
        content_to_save = create_match.group(3)
        
        allowed_formats = ["py", "sedpy", "txt", "sed"]
        if file_format_input not in allowed_formats:
            return f"Sed: Непідтримуваний формат файлу '{file_format_input}'. Дозволені: {', '.join(allowed_formats)}."

        full_file_name = f"{file_name}.{file_format_input}"
        file_path_for_creation = os.path.join(MODS_FOLDER, full_file_name)

        is_safe = True
        reason = "OK"

        if file_format_input in ["py", "sedpy"]:
            is_safe, reason = is_code_safe(content_to_save)

        if not is_safe:
            log_security_threat(current_time_str_full, msg, reason)
            response = f"Sed: Вибачте, але файл '{full_file_name}' неможливо зберегти через Протокол Безпеки. Причина: {reason}"
            if sed_has_code_error:
                response += " error code..."
            return censor(response)
        
        try:
            if not os.path.exists(MODS_FOLDER):
                os.makedirs(MODS_FOLDER)

            if file_format_input == "sedpy":
                final_save_name = f"{file_name}.sed.py"
                final_file_path = os.path.join(MODS_FOLDER, final_save_name)
                with open(final_file_path, "w", encoding="utf-8") as f:
                    f.write(content_to_save)
                
                # Додаткова перевірка на видалення файлів з некоректним подвійним розширенням, якщо вони існують.
                # Це випадок, коли файл може бути створений як 'мод.sed.py.py' через помилку
                # У цьому коді це вже не повинно траплятися, але як захист від старих багів.
                if os.path.exists(file_path_for_creation) and file_path_for_creation != final_file_path:
                    os.remove(file_path_for_creation)
                
                print(f"Sed: Новий кодовий мод '{final_save_name}' створено. Перезавантажую моди...")
                load_mods()
                response = f"Sed: Файл '{final_save_name}' успішно створено та завантажено. {AI_NAME} готовий до нової команди."
            else: # Для .py, .txt, .sed
                with open(file_path_for_creation, "w", encoding="utf-8") as f:
                    f.write(content_to_save)
                
                print(f"Sed: Новий файл '{full_file_name}' створено. Перезавантажую моди...")
                load_mods()
                response = f"Sed: Файл '{full_file_name}' успішно створено та завантажено. {AI_NAME} готовий до нової команди."

        except Exception as e:
            response = f"Sed: Помилка при збереженні файлу '{full_file_name}': {e}"
            print(f"DEBUG: Помилка збереження файлу {full_file_name}: {e}")

        if sed_has_code_error:
            response += " error code..."
        return censor(response)

    # --- Перевірка на арифметичний вираз і обчислення ---
    calc_result = calculate_expression(msg_l)
    if calc_result is not None:
        return calc_result

    # --- Обробка команд кодових модів (.sed.py) ---
    if msg_l in code_mods:
        try:
            return code_mods[msg_l]()
        except Exception as e:
            print(f"DEBUG: Помилка виконання кодового моду '{msg_l}': {e}")
            return f"Sed: Помилка виконання моду '{msg_l}': {e}"

    # --- Виконання функції з модулів за ім'ям ---
    run_match = re.match(r"виконай\s+([^\s]+)(.*)", msg_l)
    if run_match:
        func_name = run_match.group(1)
        func_args = run_match.group(2).strip().split() if run_match.group(2).strip() else []
        # Шукаємо функцію у всіх python_modules
        for module in python_modules.values():
            func = getattr(module, func_name, None)
            if callable(func):
                try:
                    result = func(*func_args)
                    return f"Sed: Результат виконання '{func_name}': {result}"
                except Exception as e:
                    return f"Sed: Помилка виконання '{func_name}': {e}"
        return f"Sed: Функцію '{func_name}' не знайдено у модулях."

    # --- Загальний пошук за ключами (з новою логікою пріоритетів) ---
    search_databases = [learned_data, ised_data, mods_data]
    
    # 1. Пошук точного збігу запиту з ключем
    for d in search_databases:
        if msg_l in d:
            response = d[msg_l].replace("{current_time}", current_time_str_short)
            response = response.replace("{current_date}", datetime.datetime.now().strftime("%Y-%m-%d"))
            response = response.replace("{day_of_week}", datetime.datetime.now().strftime("%A"))
            if sed_has_code_error:
                response += " error code..."
            return censor(response)

    # 2. Пошук, де запит користувача є підрядком ключа (наприклад, "моя система" в "моя система цінностей")
    for d in search_databases:
        for k_original, v in d.items():
            if not isinstance(k_original, re.Pattern) and msg_l in k_original.lower():
                response = v.replace("{current_time}", current_time_str_short)
                response = response.replace("{current_date}", datetime.datetime.now().strftime("%Y-%m-%d"))
                response = response.replace("{day_of_week}", datetime.datetime.now().strftime("%A"))
                if sed_has_code_error:
                    response += " error code..."
                return censor(response)
    
    # 3. Пошук, де ключ є підрядком запиту користувача (наприклад, "вода" в "формула води")
    for d in search_databases:
        for k_original, v in d.items():
            if isinstance(k_original, re.Pattern):
                if k_original.search(msg_l):
                    response = v.replace("{current_time}", current_time_str_short)
                    response = response.replace("{current_date}", datetime.datetime.now().strftime("%Y-%m-%d"))
                    response = response.replace("{day_of_week}", datetime.datetime.now().strftime("%A"))
                    if sed_has_code_error:
                        response += " error code..."
                    return censor(response)
            else:
                search_pattern = re.compile(rf'\b{re.escape(k_original)}\b', re.IGNORECASE)
                if search_pattern.search(msg_l):
                    response = v.replace("{current_time}", current_time_str_short)
                    response = response.replace("{current_date}", datetime.datetime.now().strftime("%Y-%m-%d"))
                    response = response.replace("{day_of_week}", datetime.datetime.now().strftime("%A"))
                    if sed_has_code_error:
                        response += " error code..."
                    return censor(response)

    # --- Пошук приблизної відповіді серед незрозумілих фраз (для підказок) ---
    approx_response = find_approximate_response(msg_l)
    if approx_response:
        response = f"(≈) {approx_response}"
        if sed_has_code_error:
            response += " error code..."
        return censor(response)

    # --- Якщо запит не зрозумілий, додаємо його до unknown_data ---
    if msg_l not in unknown_data:
        unknown_data[msg_l] = ""
        save_json(UNKNOWN_DATA_FILE, unknown_data)

    response = "Вибач, не зрозумів."
    if sed_has_code_error:
        response += " error code..."
    return censor(response)

# --- Імпорт мод-пака ---
def import_mod_pack(pack_path):
    """Імпортує мод-пак з папки або zip-файлу."""
    try:
        if pack_path.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(pack_path, 'r') as zip_ref:
                zip_ref.extractall(MODS_FOLDER)
            print(f"Sed: Мод-пак з '{pack_path}' розпаковано у '{MODS_FOLDER}'.")
        elif os.path.isdir(pack_path):
            import shutil
            for item in os.listdir(pack_path):
                s = os.path.join(pack_path, item)
                d = os.path.join(MODS_FOLDER, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)
            print(f"Sed: Мод-пак з папки '{pack_path}' скопійовано у '{MODS_FOLDER}'.")
        else:
            return "Sed: Неправильний формат мод-пака. Вкажіть шлях до zip або папки."
        load_mods()
        return "Sed: Мод-пак успішно імпортовано та моди перезавантажено."
    except Exception as e:
        print(f"Sed: Помилка імпорту мод-пака: {e}")
        return f"Sed: Помилка імпорту мод-пака: {e}"

# --- Основний цикл чату ---
def start_chat():
    global learned_data, ised_data, atsed_data, unknown_data, mods_data, code_mods, python_modules
    
    ised_data = load_data(ISED_LIBRARY_FILE)
    atsed_data = load_data(ATSED_FILE, as_regex=True)
    learned_data = load_json(LEARNED_DATA_FILE)
    unknown_data = load_json(UNKNOWN_DATA_FILE)
    load_mods()

    print(f"{AI_NAME} {VERSION} від {AUTHOR} готовий. Введи команду або 'допомога'.")
    
    while True:
        try:
            # Використовуємо input_with_timeout для виявлення бездіяльності
            user_input = input_with_timeout("Ти: ", TIMEOUT_BEFORE_AUTH)
            
            if user_input is None: # Таймаут спрацював, виявлено бездіяльність
                print("Sed: ⚠️ Виявлено несанкціоновану бездіяльність. Система переходить у режим авторизації.")
                security_authorization() # Викликаємо блокуючу функцію авторизації
                continue # Після авторизації (або виходу при таймауті) продовжуємо цикл
            
            user_input = user_input.strip()
            if not user_input:
                continue # Пропускаємо порожній ввід, якщо він не спричинив таймаут
            
            log_message(user_input, "User")
            
            resp = get_response(user_input)
            print(resp)
            log_message(resp, AI_NAME)

            if user_input.lower() == "вийти":
                break
        except KeyboardInterrupt:
            print("\nSed: Завершення роботи.")
            break
        except Exception as e:
            print(f"DEBUG: Критична помилка у головному циклі: {e}")
            print("Sed: Виникла неочікувана помилка. Будь ласка, спробуйте знову.")

if __name__ == "__main__":
    start_chat()


# ==================== SED 1.5.3 BETA EXTRA FEATURES ====================

import difflib
import subprocess

def run_error_plugin():
    """Запускає плагін асед.sed.py при помилці авторизації."""
    try:
        subprocess.run([sys.executable, "асед.sed.py"], check=False)
    except Exception as e:
        print(f"[SED SECURITY] Неможливо запустити асед.sed.py: {e}")
    sys.exit(0)

def check_authorization(password_input, correct_password, command_input, correct_command):
    """Перевірка авторизації з пасткою."""
    if password_input != correct_password or command_input != correct_command:
        run_error_plugin()
    return True

def list_mods(mods_folder=MODS_FOLDER):
    """Повертає список модів."""
    try:
        import os
        files = [f for f in os.listdir(mods_folder) if f.endswith(".py") or f.endswith(".sed") or f.endswith(".sed.py")]
        for idx, fname in enumerate(files, start=1):
            print(f"{idx}. {fname}")
        return files
    except FileNotFoundError:
        print("Папку з модами не знайдено.")
        return []

def delete_mod(identifier, mods_folder="mods"):
    """Видаляє мод за номером або назвою (шукає файл у папці, навіть якщо він пошкоджений)."""
    files = [f for f in os.listdir(mods_folder) if f.endswith(".py") or f.endswith(".sed") or f.endswith(".sed.py") or f.endswith(".txt")]
    try:
        if identifier.isdigit():
            idx = int(identifier) - 1
            if 0 <= idx < len(files):
                os.remove(os.path.join(mods_folder, files[idx]))
                print(f"Мод {files[idx]} видалено.")
        else:
            if identifier in files:
                os.remove(os.path.join(mods_folder, identifier))
                print(f"Мод {identifier} видалено.")
            else:
                # Спроба видалити файл напряму, навіть якщо він не у списку
                file_path = os.path.join(mods_folder, identifier)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"Мод {identifier} видалено (знайдено напряму).")
                else:
                    print(f"Файл {identifier} не знайдено для видалення.")
    except Exception as e:
        print(f"Помилка при видаленні: {e}")

def interactive_create(filename, file_format):
    """Інтерактивний режим створення файлу."""
    print("Введіть вміст. Натисніть Ctrl+Z (Windows) або Ctrl+D (Linux/Mac) і Enter для завершення:")
    try:
        import sys
        content = sys.stdin.read()
        with open(f"{filename}.{file_format}", "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Файл {filename}.{file_format} створено.")
    except Exception as e:
        print(f"Не вдалося створити файл: {e}")

def suggest_similar(word, known_words):
    """Пропонує схожі слова."""
    matches = difflib.get_close_matches(word, known_words, n=3, cutoff=0.6)
    if matches:
        print("Можливо, ви мали на увазі:")
        for m in matches:
            print(f"- {m}")

def archive_from_file(filepath, archive_dict):
    """Читає файл, визначає тему і додає в архів."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        # Дуже просте визначення теми: перші 5 слів
        topic = " ".join(content.strip().split()[:5])
        archive_dict[topic] = content
        print(f"Додано в архів тему '{topic}' з файлу {filepath}")
    except Exception as e:
        print(f"Не вдалося додати з файлу: {e}")

# ==================== END EXTRA FEATURES ====================
