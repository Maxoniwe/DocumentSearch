import os
import sys
import json
import sqlite3
import subprocess
import zipfile
import xml.etree.ElementTree as ET
import configparser
import re
import time
import textwrap
import readline  # включает историю и редактирование строки в input()
from datetime import datetime


SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'config.ini')
INDEX_DB    = os.path.join(SCRIPT_DIR, 'index.db')
CACHE_FILE  = os.path.join(SCRIPT_DIR, 'files_cache.json')
STATS_FILE  = os.path.join(SCRIPT_DIR, 'db_stats.json')

SUPPORTED_EXT = {'.pdf', '.docx', '.xlsx', '.txt', '.csv'}

PDFTOTEXT_CANDIDATES = ['/usr/bin/pdftotext', '/usr/local/bin/pdftotext']
_pdftotext_binary = None  # None = не проверяли, '' = не найден


def create_default_config():
    template = (
        "[connection]\n"
        "login      = ВВЕДИ_СВОЙ_ЛОГИН\n"
        "password   = ВВЕДИ_СВОЙ_ПАРОЛЬ\n"
        "server     = //YOUR_SERVER/SHARE\n"
        "share_path = YOUR_SHARE_PATH\n"
    )
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        f.write(template)
    print(f"\n  Создан шаблон конфигурации: {CONFIG_FILE}")
    print("  Укажите свои login и password в файле config.ini и запустите программу снова.")


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"  Конфигурационный файл не найден: {CONFIG_FILE}")
        create_default_config()
        sys.exit(1)

    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_FILE, encoding='utf-8')

    if 'connection' not in cfg:
        print("  Ошибка: секция [connection] отсутствует в config.ini")
        sys.exit(1)

    c          = cfg['connection']
    login      = c.get('login',      '').strip()
    password   = c.get('password',   '').strip()
    server     = c.get('server',     '').strip()
    share_path = c.get('share_path', '').strip()

    if login in ('ВВЕДИ_СВОЙ_ЛОГИН', ''):
        print("  Ошибка: укажите login в config.ini")
        sys.exit(1)
    if password in ('ВВЕДИ_СВОЙ_ПАРОЛЬ', ''):
        print("  Ошибка: укажите password в config.ini")
        sys.exit(1)
    if not server:
        print("  Ошибка: укажите server в config.ini")
        sys.exit(1)
    if not share_path:
        print("  Ошибка: укажите share_path в config.ini")
        sys.exit(1)

    return login, password, server, share_path


def check_smbclient():
    try:
        r = subprocess.run(['which', 'smbclient'],
                           capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            print("  Ошибка: smbclient не найден.")
            print("  Установите пакет: sudo apt-get install smbclient")
            sys.exit(1)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  Ошибка: smbclient не найден.")
        sys.exit(1)


def smb_run(server, login, password, commands, timeout=120):
    stdin_bytes = ('\n'.join(commands) + '\nquit\n').encode('utf-8')
    try:
        proc = subprocess.Popen(
            ['smbclient', server, '-U', f'{login}%{password}'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, err = proc.communicate(input=stdin_bytes, timeout=timeout)
        return (
            out.decode('utf-8', errors='replace'),
            err.decode('utf-8', errors='replace'),
        )
    except KeyboardInterrupt:
        proc.kill()
        proc.wait()
        raise
    except subprocess.TimeoutExpired:
        proc.kill()
        return '', 'Таймаут соединения с сервером'
    except Exception as e:
        return '', str(e)


def smb_list_recursive(server, login, password, share_path):
    print('  Подключение к серверу...', end='', flush=True)

    try:
        proc = subprocess.Popen(
            ['smbclient', server, '-U', f'{login}%{password}'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        print('\n  Ошибка: smbclient не найден.')
        return []

    commands = f'cd "{share_path}"\nrecurse on\nls\nquit\n'
    proc.stdin.write(commands.encode('utf-8'))
    proc.stdin.close()

    files          = []
    current_subdir = ''
    found_count    = 0
    connected      = False
    LINE_WIDTH     = 72  # ширина строки прогресса для очистки

    def _update_progress():
        folder = ('/' + current_subdir) if current_subdir else '/(корень)'
        label  = f'  Сканируется: {folder}'
        right  = f'  Найдено: {_fmt(found_count)}'
        max_label = LINE_WIDTH - len(right) - 2
        if len(label) > max_label:
            label = label[:max_label - 3] + '...'
        line = f'{label}{right}'
        print(f'\r{line:<{LINE_WIDTH}}', end='', flush=True)

    try:
        while True:
            raw = proc.stdout.readline()
            if not raw:
                break

            line     = raw.decode('utf-8', errors='replace').rstrip('\r\n')
            stripped = line.strip()

            if not stripped:
                continue

            if not connected:
                if 'NT_STATUS' in stripped:
                    print(f'\n  Ошибка подключения: {stripped}')
                    proc.kill()
                    proc.wait()
                    return []
                if 'Domain=' in stripped or re.match(r'\s+\.', line):
                    connected = True
                    print(f'\r  Подключено. Начинаю сканирование...{" " * 20}')
                continue

            if any(kw in stripped for kw in (
                    'blocks of size', 'blocks available', 'smb:', 'Domain=')):
                continue

            m = re.match(r'\s+(.+?)\s+([ADNHSR]+)\s+(\d+)\s+(.*)', line)

            if not m:
                if '\\' in stripped:
                    header = stripped.replace('\\', '/')
                    prefix = f'/{share_path}'
                    if header.startswith(prefix):
                        current_subdir = header[len(prefix):].lstrip('/')
                    elif header == '/':
                        current_subdir = ''
                    else:
                        current_subdir = header.lstrip('/')
                    _update_progress()
                continue

            name = m.group(1).strip()
            attr = m.group(2)

            if 'D' in attr or name in ('.', '..'):
                continue

            ext = os.path.splitext(name)[1].lower()
            if ext not in SUPPORTED_EXT:
                continue

            modified_at = ''
            date_raw = m.group(4).strip()
            if date_raw:
                try:
                    date_norm = ' '.join(date_raw.split())
                    modified_at = datetime.strptime(date_norm, '%a %b %d %H:%M:%S %Y').isoformat()
                except Exception:
                    pass

            smb_dir  = f'{share_path}/{current_subdir}'.rstrip('/') \
                       if current_subdir else share_path
            rel_path = f'{current_subdir}/{name}' if current_subdir else name

            files.append({
                'name':        name,
                'smb_dir':     smb_dir,
                'rel_path':    rel_path,
                'ext':         ext,
                'modified_at': modified_at,
            })
            found_count += 1
            _update_progress()

    except KeyboardInterrupt:
        proc.kill()
        proc.wait()
        print(f'\n  Прервано. Найдено файлов до остановки: {_fmt(found_count)}')
        raise

    proc.wait()

    if not connected:
        err = proc.stderr.read().decode('utf-8', errors='replace').strip()
        print(f'\n  Не удалось подключиться к серверу.')
        if err:
            print(f'  {err}')
        return []

    print(f'\r  Сканирование завершено. Найдено файлов: {_fmt(found_count)}\033[K')
    return files


def smb_download(server, login, password, smb_dir, filename, local_path):
    if os.path.exists(local_path):
        os.remove(local_path)

    smb_run(server, login, password, [
        f'cd "{smb_dir}"',
        f'get "{filename}" "{local_path}"',
    ], timeout=60)

    return os.path.isfile(local_path) and os.path.getsize(local_path) > 0


def smb_batch_download(server, login, password, smb_dir, files, timeout=None):
    for name, local_path in files:
        if os.path.exists(local_path):
            os.remove(local_path)

    commands = [f'cd "{smb_dir}"']
    for name, local_path in files:
        commands.append(f'get "{name}" "{local_path}"')

    tmt = timeout if timeout is not None else max(60, 60 * len(files))
    smb_run(server, login, password, commands, timeout=tmt)

    return {
        name: os.path.isfile(local_path) and os.path.getsize(local_path) > 0
        for name, local_path in files
    }


def find_pdftotext():
    global _pdftotext_binary
    if _pdftotext_binary is None:
        found = ''
        for path in PDFTOTEXT_CANDIDATES:
            if os.path.isfile(path):
                found = path
                break
        _pdftotext_binary = found
    return _pdftotext_binary or None


def read_pdf(path):
    binary = find_pdftotext()
    if not binary:
        return ''
    try:
        r = subprocess.run([binary, path, '-'],
                           capture_output=True, timeout=30)
        if r.returncode == 0:
            return r.stdout.decode('utf-8', errors='replace')
    except Exception:
        pass
    return ''


def read_docx(path):
    W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
    try:
        with zipfile.ZipFile(path) as zf:
            if 'word/document.xml' not in zf.namelist():
                return ''
            with zf.open('word/document.xml') as f:
                root = ET.parse(f).getroot()
        parts = []
        for p in root.iter(f'{{{W}}}p'):
            text = ''.join(t.text or '' for t in p.iter(f'{{{W}}}t'))
            if text.strip():
                parts.append(text)
        return '\n'.join(parts)
    except Exception:
        return ''


def read_xlsx(path):
    NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()

            # Читаем shared strings (строковые значения хранятся отдельно)
            shared = []
            if 'xl/sharedStrings.xml' in names:
                with zf.open('xl/sharedStrings.xml') as f:
                    root = ET.parse(f).getroot()
                for si in root.iter(f'{{{NS}}}si'):
                    shared.append(
                        ''.join(t.text or '' for t in si.iter(f'{{{NS}}}t'))
                    )

            rows = []
            for nm in names:
                if not re.match(r'xl/worksheets/sheet\d+\.xml', nm):
                    continue
                with zf.open(nm) as f:
                    root = ET.parse(f).getroot()
                for row in root.iter(f'{{{NS}}}row'):
                    cells = []
                    for c in row.iter(f'{{{NS}}}c'):
                        v = c.find(f'{{{NS}}}v')
                        if v is None or not v.text:
                            continue
                        if c.get('t') == 's':
                            idx = int(v.text)
                            cells.append(shared[idx] if idx < len(shared) else '')
                        else:
                            cells.append(v.text)
                    if cells:
                        rows.append(' '.join(cells))
        return '\n'.join(rows)
    except Exception:
        return ''


def read_txt(path):
    for enc in ('utf-8', 'cp1251', 'latin-1'):
        try:
            with open(path, encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    return ''


def extract_text(local_path, ext):
    e = ext.lower()
    if e == '.pdf':
        return read_pdf(local_path)
    if e == '.docx':
        return read_docx(local_path)
    if e == '.xlsx':
        return read_xlsx(local_path)
    if e in ('.txt', '.csv'):
        return read_txt(local_path)
    return ''


def _connect():
    conn = sqlite3.connect(INDEX_DB)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA temp_store=MEMORY')
    conn.execute('PRAGMA cache_size=-200000')   # 200 МБ page cache
    conn.execute('PRAGMA mmap_size=268435456')  # 256 МБ mmap
    return conn


def _ensure_schema(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS documents (
            path        TEXT PRIMARY KEY,
            filename    TEXT NOT NULL,
            extension   TEXT NOT NULL,
            text        TEXT NOT NULL DEFAULT '',
            text_empty  INTEGER NOT NULL DEFAULT 1,
            has_error   INTEGER NOT NULL DEFAULT 0,
            indexed_at  TEXT NOT NULL DEFAULT '',
            modified_at TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_text_empty ON documents(text_empty) WHERE text_empty = 1;
        CREATE INDEX IF NOT EXISTS idx_has_error  ON documents(has_error)  WHERE has_error  = 1;
        CREATE INDEX IF NOT EXISTS idx_indexed_at ON documents(indexed_at);
        CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
            path UNINDEXED,
            text,
            tokenize='unicode61'
        );
    """)
    # добавить modified в старые БД
    try:
        conn.execute("ALTER TABLE documents ADD COLUMN modified_at TEXT NOT NULL DEFAULT ''")
        conn.commit()
    except Exception:
        pass


def _ensure_fts(conn):
    # синхронизирует FTS с документами если COUNT расходится
    fts_count = conn.execute('SELECT COUNT(*) FROM documents_fts').fetchone()[0]
    doc_count = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
    if doc_count == 0:
        return
    if fts_count == doc_count:
        return
    print(f'  Синхронизация FTS-индекса: {_fmt(doc_count)} записей (было {_fmt(fts_count)})...',
          flush=True)
    conn.execute('BEGIN')
    conn.execute('DELETE FROM documents_fts')
    conn.execute(
        'INSERT INTO documents_fts(path, text) '
        'SELECT path, text FROM documents'
    )
    conn.commit()
    print('  FTS-индекс готов')


def load_index():
    print('  Открываю индекс...', flush=True)
    if not os.path.exists(INDEX_DB):
        conn = _connect()
        _ensure_schema(conn)
        _ensure_fts(conn)
        conn.close()
        return {}
    try:
        conn = _connect()
        _ensure_schema(conn)
        _ensure_fts(conn)
        total = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
        if total == 0:
            conn.close()
            return {}
        cur = conn.execute(
            'SELECT path, filename, extension, text_empty, has_error, indexed_at, modified_at FROM documents'
        )
        index = {}
        loaded = 0
        for row in cur:
            index[row['path']] = {
                'path':        row['path'],
                'filename':    row['filename'],
                'extension':   row['extension'],
                'text_empty':  bool(row['text_empty']),
                'has_error':   bool(row['has_error']),
                'indexed_at':  row['indexed_at'],
                'modified_at': row['modified_at'],
            }
            loaded += 1
            if loaded % 1000 == 0:
                pct = loaded / total * 100
                print(f'\r  Загрузка индекса: {_fmt(loaded)} / {_fmt(total)}  ({pct:.0f}%)',
                      end='', flush=True)
        print('\r' + ' ' * 72 + '\r', end='', flush=True)
        print(f'  Индекс загружен: {_fmt(total)} записей')
        conn.close()
        return index
    except Exception as e:
        print(f'  Ошибка загрузки индекса: {e}')
        return {}


def save_entry(entry):
    conn = _connect()
    try:
        conn.execute('BEGIN')
        conn.execute(
            'INSERT OR REPLACE INTO documents '
            '(path, filename, extension, text, text_empty, has_error, indexed_at, modified_at) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (
                entry['path'],
                entry.get('filename',    ''),
                entry.get('extension',   ''),
                entry.get('text',        ''),
                1 if entry.get('text_empty', True)  else 0,
                1 if entry.get('has_error',  False) else 0,
                entry.get('indexed_at',  ''),
                entry.get('modified_at', ''),
            ),
        )
        conn.execute('DELETE FROM documents_fts WHERE path = ?', (entry['path'],))
        conn.execute(
            'INSERT INTO documents_fts(path, text) VALUES (?, ?)',
            (entry['path'], entry.get('text', '')),
        )
        conn.commit()
    finally:
        conn.close()


def _batch_save_entries(conn, entries):
    if not entries:
        return
    docs_rows = [
        (e['path'], e.get('filename', ''), e.get('extension', ''), e.get('text', ''),
         1 if e.get('text_empty', True) else 0,
         1 if e.get('has_error', False) else 0,
         e.get('indexed_at', ''), e.get('modified_at', ''))
        for e in entries
    ]
    update_fts_paths = [(e['path'],) for e in entries if not e.get('_is_new', False)]
    update_fts_rows  = [(e['path'], e.get('text', '')) for e in entries if not e.get('_is_new', False)]
    new_fts_rows     = [(e['path'], e.get('text', '')) for e in entries if e.get('_is_new', False)]
    if conn.in_transaction:
        conn.rollback()
    conn.execute('BEGIN')
    conn.executemany(
        'INSERT OR REPLACE INTO documents '
        '(path, filename, extension, text, text_empty, has_error, indexed_at, modified_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        docs_rows,
    )
    if update_fts_paths:
        conn.executemany(
            'DELETE FROM documents_fts WHERE path = ?',
            update_fts_paths,
        )
        conn.executemany(
            'INSERT INTO documents_fts(path, text) VALUES (?, ?)',
            update_fts_rows,
        )
    if new_fts_rows:
        conn.executemany(
            'INSERT INTO documents_fts(path, text) VALUES (?, ?)',
            new_fts_rows,
        )
    conn.commit()



def load_files_cache():
    if not os.path.exists(CACHE_FILE):
        return None, None
    try:
        total_size = os.path.getsize(CACHE_FILE)
        if total_size == 0:
            return None, None
        read_bytes = 0
        chunks = []
        with open(CACHE_FILE, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)  # 1 МБ
                if not chunk:
                    break
                chunks.append(chunk)
                read_bytes += len(chunk)
                pct = read_bytes / total_size * 100
                read_mb  = read_bytes / (1024 * 1024)
                total_mb = total_size / (1024 * 1024)
                print(f'\r  Чтение кэша: {read_mb:.1f} / {total_mb:.1f} МБ  ({pct:.0f}%)',
                      end='', flush=True)
        print('\r' + ' ' * 72 + '\r', end='', flush=True)
        print('  Разбор данных...', end='', flush=True)
        raw = b''.join(chunks).decode('utf-8', errors='replace')
        data = json.loads(raw)
        print('\r' + ' ' * 72 + '\r', end='', flush=True)
        created_at = datetime.fromisoformat(data['created_at'])
        return data['files'], created_at
    except Exception:
        return None, None


def save_files_cache(files):
    tmp = CACHE_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump({
            'created_at': datetime.now().isoformat(),
            'total':      len(files),
            'files':      files,
        }, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CACHE_FILE)


def _remove_tmp(path):
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def _fmt_eta(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f'{seconds} сек'
    elif seconds < 3600:
        return f'{seconds // 60} мин {seconds % 60} сек'
    else:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f'{h} ч {m} мин'


def _last_status_line(last, name_w):
    if last['status'] == '✓':
        return f'  Последний:   ✓  {_fmt(last["chars"]):>9} симв.   {last["name"][:name_w]}'
    if last['status'] == '⚠':
        return f'  Последний:   ⚠  пустой             {last["name"][:name_w]}'
    if last['status'] == '✗':
        return f'  Последний:   ✗  ошибка             {last["name"][:name_w]}'
    return '  Последний:   нет'


def _update_eta(completion_times, start_time, tp_smooth, last_eta_str, last_eta_ts, remaining):
    if not completion_times or remaining <= 0:
        return last_eta_str[0]
    now = time.time()
    window = [t for t in completion_times if now - t <= 120.0]
    if len(window) >= 5:
        raw_tp = len(window) / 120.0
    elif start_time[0] and now > start_time[0]:
        raw_tp = len(completion_times) / (now - start_time[0])
    else:
        raw_tp = None
    if raw_tp and raw_tp > 0:
        if tp_smooth[0] is None:
            tp_smooth[0] = raw_tp
        else:
            tp_smooth[0] = 0.15 * raw_tp + 0.85 * tp_smooth[0]
        new_str = f'  ~  осталось: {_fmt_eta(max(1, int(remaining / tp_smooth[0])))}'
        if not last_eta_str[0] or (now - last_eta_ts[0]) >= 20.0 or new_str != last_eta_str[0]:
            last_eta_str[0] = new_str
            last_eta_ts[0]  = now
    return last_eta_str[0]


def build_index(server, login, password, share_path):
    print()

    cached_files, cache_time = load_files_cache()
    if cached_files is not None:
        age_h = (datetime.now() - cache_time).total_seconds() / 3600
        age_label = f'{age_h:.0f} ч' if age_h >= 1 else f'{age_h * 60:.0f} мин'
        warn = '  ⚠  Кэш устарел - на сервере могут быть новые файлы\n' if age_h > 24 else ''
        print(f'  Найден кэш от {cache_time.strftime("%d.%m.%Y %H:%M")} '
              f'  ({_fmt(len(cached_files))} файлов, возраст: {age_label})\n')
        if warn:
            print(warn, end='')
        print('  1. Использовать кэш (быстро)')
        print('  2. Пересканировать сервер\n')
        ans = input('  Выберите: ').strip()
        if ans == '1':
            files = cached_files
            print(f'\n  Загружено из кэша: {_fmt(len(files))} файлов')
        else:
            files = smb_list_recursive(server, login, password, share_path)
            if files:
                save_files_cache(files)
    else:
        files = smb_list_recursive(server, login, password, share_path)
        if files:
            save_files_cache(files)

    if not files:
        print('  Файлы не найдены или нет доступа к серверу.')
        return {}

    total   = len(files)
    index   = load_index()

    server_paths = {f'{share_path}/{fi["rel_path"]}' for fi in files}
    stale = [k for k in index if k not in server_paths]
    if stale:
        for k in stale:
            del index[k]
        _tmp_conn = _connect()
        _tmp_conn.executemany('DELETE FROM documents WHERE path = ?', [(k,) for k in stale])
        _tmp_conn.executemany('DELETE FROM documents_fts WHERE path = ?', [(k,) for k in stale])
        _tmp_conn.commit()
        _tmp_conn.close()
        print(f'  Удалено устаревших записей: {_fmt(len(stale))}')

    # постоянное соединение на всю индексацию
    _db_conn    = _connect()
    _db_batch   = []
    _BATCH_SIZE = 200  # коммит каждые N файлов
    _batch_num  = 0    # для периодических checkpoint/merge

    in_index_count = 0
    indexed        = 0
    sess_empty     = 0
    sess_errors    = 0

    # счётчики по всему индексу, не только за сессию
    disp_empty  = sum(1 for e in index.values() if e.get('text_empty', False))
    disp_errors = sum(1 for e in index.values() if e.get('has_error', False))

    to_process        = 0   # уточняется после пре-пасса
    _completion_times = []
    _tp_smooth        = [None]
    _last_eta_str     = ['']
    _last_eta_ts      = [0.0]

    last = {'status': '', 'chars': 0, 'name': ''}

    _graceful_stop = [0]

    _BLOCK      = 15
    _drawn      = [False]
    _last_draw  = [0.0]
    _start_time = [0.0]

    def _draw(force=False):
        now = time.time()
        if not force and _drawn[0] and (now - _last_draw[0]) < 0.15:
            return
        _last_draw[0] = now

        done = in_index_count + indexed + sess_empty + sess_errors
        pct  = done / total * 100 if total else 0.0

        remaining_new = max(0, to_process - indexed - sess_empty - sess_errors)
        eta_str = _update_eta(_completion_times, _start_time, _tp_smooth,
                              _last_eta_str, _last_eta_ts, remaining_new)

        try:
            term_w = os.get_terminal_size().columns
        except OSError:
            term_w = 80

        name_w    = max(10, term_w - 34)
        last_line = _last_status_line(last, name_w)

        pct_str = '100.0%' if done >= total else f'{min(pct, 99.9):.1f}%'

        lines = [
            LINE,
            f'  Файлов на сервере:         {_fmt(total)}',
            f'  Всего в индексе:           {_fmt(len(index))}',
            f'  Всего пустых:              {_fmt(disp_empty)}',
            f'  Всего ошибок:              {_fmt(disp_errors)}',
            '',
            f'  Пройдено:        {_fmt(done)} / {_fmt(total)}',
            f'  Новых (сессия):  {_fmt(indexed)}',
            f'  Пустых (сессия): {_fmt(sess_empty)}',
            f'  Ошибок (сессия): {_fmt(sess_errors)}',
            '',
            last_line,
            '',
            '  ⚠  Завершаю текущий файл...  Ctrl+C ещё раз - остановить сейчас'
            if _graceful_stop[0] == 1 else
            f'  Прогресс:    {pct_str}{eta_str}',
            LINE,
        ]

        prefix = f'\033[{_BLOCK}A' if _drawn[0] else ''
        sys.stdout.write(prefix + ''.join(f'{l[:term_w - 1]}\033[K\n' for l in lines))
        sys.stdout.flush()
        _drawn[0] = True

    _start_time[0] = time.time()
    print()
    _draw(force=True)

    # пре-пасс: файл попадает в очередь если нет в индексе, дата изменилась, или в индексе дата пустая
    pending = []
    for i, fi in enumerate(files):
        full_path = f'{share_path}/{fi["rel_path"]}'
        srv_date  = fi.get('modified_at', '')
        existing  = index.get(full_path)

        if existing is not None:
            idx_date = existing.get('modified_at', '')
            if srv_date and idx_date and srv_date == idx_date:
                in_index_count += 1
                _draw()
                continue
            if not srv_date:
                in_index_count += 1
                _draw()
                continue
            # снимаем старый вклад, основной цикл начислит новый
            if existing.get('text_empty', False):
                disp_empty -= 1
            if existing.get('has_error', False):
                disp_errors -= 1
            is_new = False
        else:
            is_new = True
        pending.append((i, fi, is_new))

    to_process = len(pending)

    dir_groups = {}
    for i, fi, is_new in pending:
        dir_groups.setdefault(fi['smb_dir'], []).append((i, fi, is_new))

    for smb_dir, group in dir_groups.items():
        if _graceful_stop[0]:
            break

        batch = [
            (fi['name'], fi['ext'], fi['rel_path'], f'/tmp/_docidx_{i}{fi["ext"]}',
             fi.get('modified_at', ''), is_new)
            for i, fi, is_new in group
        ]
        dl_files = [(name, tmp) for name, ext, rel_path, tmp, modified_at, is_new in batch]

        try:
            dl_ok = smb_batch_download(server, login, password, smb_dir, dl_files)
        except KeyboardInterrupt:
            for _, _, _, tmp, _, _ in batch:
                _remove_tmp(tmp)
            if _graceful_stop[0] == 0:
                _graceful_stop[0] = 1
                _draw(force=True)
            else:
                _graceful_stop[0] = 2
            break

        for name, ext, rel_path, tmp, modified_at, is_new in batch:
            if _graceful_stop[0]:
                break
            full_path  = f'{share_path}/{rel_path}'
            text       = ''
            text_empty = True
            has_error  = False

            try:
                try:
                    ok = dl_ok.get(name, False)
                    if not ok:
                        has_error = True
                        disp_errors += 1
                        sess_errors += 1
                        last['status'] = '✗'
                        last['chars']  = 0
                        last['name']   = name
                    else:
                        text = extract_text(tmp, ext)
                        text_empty = not bool(text.strip())

                        if text_empty:
                            disp_empty += 1
                            sess_empty += 1
                            last['status'] = '⚠'
                            last['chars']  = 0
                            last['name']   = name
                        else:
                            indexed += 1
                            last['status'] = '✓'
                            last['chars']  = len(text)
                            last['name']   = name

                except Exception:
                    has_error = True
                    disp_errors += 1
                    sess_errors += 1
                    last['status'] = '✗'
                    last['chars']  = 0
                    last['name']   = name

                if _graceful_stop[0]:
                    continue

                entry = {
                    'path':        full_path,
                    'filename':    name,
                    'extension':   ext,
                    'text':        text,
                    'text_empty':  text_empty,
                    'has_error':   has_error,
                    'indexed_at':  datetime.now().isoformat(),
                    'modified_at': modified_at,
                    '_is_new':     is_new,
                }
                _db_batch.append(entry)
                if len(_db_batch) >= _BATCH_SIZE:
                    _batch_save_entries(_db_conn, _db_batch)
                    _db_batch.clear()
                    _batch_num += 1
                    # каждые 5 батчей: WAL-checkpoint; каждые 20: merge FTS5-сегментов
                    if _batch_num % 5 == 0:
                        try:
                            _db_conn.execute('PRAGMA wal_checkpoint(PASSIVE)')
                        except Exception:
                            pass
                    if _batch_num % 20 == 0:
                        try:
                            _db_conn.execute(
                                "INSERT INTO documents_fts(documents_fts) VALUES('merge', -500)"
                            )
                            _db_conn.commit()
                        except Exception:
                            pass
                # отдельный объект: без text и _is_new
                index[full_path] = {k: v for k, v in entry.items() if k not in ('text', '_is_new')}

                now_ts = time.time()
                _completion_times.append(now_ts)
                if len(_completion_times) > 200:
                    _completion_times.pop(0)

                _draw(force=True)

            except KeyboardInterrupt:
                _remove_tmp(tmp)
                if _graceful_stop[0] == 0:
                    _graceful_stop[0] = 1
                    _draw(force=True)
                else:
                    _graceful_stop[0] = 2
                break

            finally:
                _remove_tmp(tmp)

    _batch_save_entries(_db_conn, _db_batch)
    _db_conn.close()

    # сбросить WAL, ускоряет следующий старт
    _ckpt_conn = _connect()
    _ckpt_conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    _ckpt_conn.close()

    _draw(force=True)
    print()
    if _graceful_stop[0]:
        how = 'принудительно' if _graceful_stop[0] == 2 else 'по запросу'
        print(f'  Индексация остановлена ({how}).')
        print(f'  Индекс цел, все обработанные файлы сохранены.')
    else:
        print(f'  Индексация завершена.')
    print(f'  Новых с текстом:       {_fmt(indexed)}')
    print(f'  Всего пустых:          {_fmt(disp_empty)}')
    print(f'  Всего ошибок:          {_fmt(disp_errors)}')
    print(f'  Пропущено (в индексе): {_fmt(in_index_count)}')
    _save_stats_cache(index)
    return index


def _show_file_list(index, flag_key, header, empty_msg, count_label):
    items = [(path, e) for path, e in index.items() if e.get(flag_key, False)]
    print_header(header)
    if not items:
        print(f'  {empty_msg}\n')
        return
    print(f'  {count_label}: {_fmt(len(items))}')
    print()
    print(THIN)
    for i, (path, entry) in enumerate(items, 1):
        print(f'\n  [{i}] {entry["filename"]}')
        print(f'      {os.path.dirname(path)}/')
    print(f'\n{THIN}')


def show_empty_files(index):
    _show_file_list(index, 'text_empty', 'ФАЙЛЫ БЕЗ ТЕКСТА',
                    'Пустых файлов нет.', 'Файлов с пустым текстом')


def show_error_files(index):
    _show_file_list(index, 'has_error', 'ФАЙЛЫ С ОШИБКАМИ СКАЧИВАНИЯ',
                    'Файлов с ошибками нет.', 'Файлов с ошибками')


def _recheck_files(server, login, password, index, problem_paths, title):
    if not problem_paths:
        print('\n  Нет файлов для перепроверки.')
        return index

    total = len(problem_paths)

    recovered   = [0]
    still_empty = [0]
    still_error = [0]
    done        = [0]
    last        = {'status': '', 'chars': 0, 'name': ''}

    _BLOCK      = 9
    _drawn      = [False]
    _last_draw  = [0.0]
    _start_time = [time.time()]
    _completion_times = []
    _tp_smooth        = [None]
    _last_eta_str     = ['']
    _last_eta_ts      = [0.0]

    def _draw(force=False):
        now = time.time()
        if not force and _drawn[0] and (now - _last_draw[0]) < 0.15:
            return
        _last_draw[0] = now

        pct = done[0] / total * 100 if total else 0.0

        remaining = max(0, total - done[0])
        eta_str = _update_eta(_completion_times, _start_time, _tp_smooth,
                              _last_eta_str, _last_eta_ts, remaining)

        try:
            term_w = os.get_terminal_size().columns
        except OSError:
            term_w = 80

        name_w    = max(10, term_w - 34)
        last_line = _last_status_line(last, name_w)

        pct_str = '100.0%' if done[0] >= total else f'{min(pct, 99.9):.1f}%'

        lines = [
            LINE,
            f'  Переиндексация: {title}  ({_fmt(total)})',
            '',
            f'  Пройдено:      {_fmt(done[0])} / {_fmt(total)}',
            f'  Восстановлено: {_fmt(recovered[0])}',
            '',
            last_line,
            f'  Прогресс:    {pct_str}{eta_str}',
            LINE,
        ]

        prefix = f'\033[{_BLOCK}A' if _drawn[0] else ''
        sys.stdout.write(prefix + ''.join(f'{l[:term_w - 1]}\033[K\n' for l in lines))
        sys.stdout.flush()
        _drawn[0] = True

    print()
    _draw(force=True)

    for i, path in enumerate(problem_paths, 1):
        entry = index[path]
        name  = entry['filename']
        ext   = entry['extension']

        parts   = path.split('/')
        smb_dir = '/'.join(parts[:-1])

        _had_error = False
        tmp = f'/tmp/_docidx_recheck_{i}{ext}'
        try:
            ok = smb_download(server, login, password, smb_dir, name, tmp)
            if not ok:
                still_error[0] += 1
                _had_error = True
                last['status'] = '✗'
                last['name']   = name
            else:
                text = extract_text(tmp, ext)
                if text.strip():
                    recovered[0] += 1
                    index[path]['text']       = text
                    index[path]['text_empty'] = False
                    index[path]['has_error']  = False
                    index[path]['indexed_at'] = datetime.now().isoformat()
                    save_entry(index[path])
                    last['status'] = '✓'
                    last['chars']  = len(text)
                    last['name']   = name
                else:
                    still_empty[0] += 1
                    index[path]['text_empty'] = True
                    index[path]['has_error']  = False
                    index[path]['indexed_at'] = datetime.now().isoformat()
                    save_entry(index[path])
                    last['status'] = '⚠'
                    last['name']   = name

        except Exception:
            still_error[0] += 1
            _had_error = True
            last['status'] = '✗'
            last['name']   = name

        finally:
            _remove_tmp(tmp)

        if _had_error:
            index[path]['has_error']  = True
            index[path]['text_empty'] = False
            save_entry(index[path])

        done[0] += 1
        _completion_times.append(time.time())
        if len(_completion_times) > 200:
            _completion_times.pop(0)
        _draw()

    _draw(force=True)
    print(f'\n  Перепроверка завершена.')
    print(f'  Восстановлено с текстом: {recovered[0]}')
    print(f'  Всё ещё пустых:          {still_empty[0]}')
    print(f'  Всё ещё с ошибкой:       {still_error[0]}')
    _save_stats_cache(index)
    return index



def recheck_all_problem_files(server, login, password, index):
    all_paths = [p for p, e in index.items()
                 if e.get('has_error', False) or e.get('text_empty', False)]
    if not all_paths:
        print('\n  Проблемных файлов нет.')
        return index
    return _recheck_files(server, login, password, index, all_paths, 'проблемных файлов')


def problem_files_menu(server, login, password, index):
    while True:
        empty_count = sum(1 for e in index.values() if e.get('text_empty', False))
        error_count = sum(1 for e in index.values() if e.get('has_error', False))

        print_header('ПРОБЛЕМНЫЕ ФАЙЛЫ')
        if empty_count or error_count:
            print(f'  Ошибки скачивания:  {_fmt(error_count)}')
            print(f'  Без текста:         {_fmt(empty_count)}')
        else:
            print('  Проблемных файлов нет.')
        print()
        print(THIN)
        print('  1. Показать файлы с ошибками')
        print('  2. Показать файлы без текста')
        print('  3. Переиндексация проблемных файлов')
        print('  4. Назад')
        print(THIN)
        print()

        choice = input('  Выберите действие: ').strip()

        if choice == '1':
            show_error_files(index)
        elif choice == '2':
            show_empty_files(index)
        elif choice == '3':
            index = recheck_all_problem_files(server, login, password, index)
        elif choice == '4':
            return index
        else:
            print('  Неверный выбор. Введите 1–4.')


class _And:
    __slots__ = ('left', 'right')
    def __init__(self, left, right):
        self.left = left
        self.right = right

class _Or:
    __slots__ = ('left', 'right')
    def __init__(self, left, right):
        self.left = left
        self.right = right

class _Leaf:
    __slots__ = ('term', 'exact')
    def __init__(self, term, exact):
        self.term = term
        self.exact = exact


_QUOTE_PAIRS = (('"', '"'), ('«', '»'), ("'", "'"))


def _tokenize_query(s):
    tokens = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == '(':
            tokens.append('(')
            i += 1
            continue
        if c == ')':
            tokens.append(')')
            i += 1
            continue
        matched_quote = False
        for open_q, close_q in _QUOTE_PAIRS:
            if c == open_q:
                j = s.find(close_q, i + 1)
                if j == -1:
                    raise ValueError(f'незакрытая кавычка {open_q}')
                tokens.append(('PHRASE', s[i + 1:j]))
                i = j + 1
                matched_quote = True
                break
        if matched_quote:
            continue
        j = i
        while j < n and not s[j].isspace() and s[j] not in '()':
            j += 1
        w = s[i:j]
        if w == 'AND':
            tokens.append('AND')
        elif w == 'OR':
            tokens.append('OR')
        else:
            tokens.append(('WORD', w))
        i = j
    return tokens


class _QueryParser:
    # рекурсивный спуск: OR < AND < скобки; соседние атомы без оператора = неявный AND

    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _eat(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self):
        if not self.tokens:
            raise ValueError('пустой запрос')
        node = self._or()
        if self.pos != len(self.tokens):
            raise ValueError(f'неожиданный токен: {self.tokens[self.pos]!r}')
        return node

    def _or(self):
        left = self._and()
        while self._peek() == 'OR':
            self._eat()
            right = self._and()
            left = _Or(left, right)
        return left

    def _and(self):
        left = self._atom()
        while True:
            t = self._peek()
            if t == 'AND':
                self._eat()
                right = self._atom()
                left = _And(left, right)
            elif self._is_atom_start(t):
                right = self._atom()
                left = _And(left, right)
            else:
                break
        return left

    @staticmethod
    def _is_atom_start(t):
        if t == '(':
            return True
        if isinstance(t, tuple) and t[0] in ('PHRASE', 'WORD'):
            return True
        return False

    def _atom(self):
        t = self._peek()
        if t is None:
            raise ValueError('ожидалось слово, фраза или «(»')
        if t == '(':
            self._eat()
            node = self._or()
            if self._peek() != ')':
                raise ValueError('не хватает закрывающей скобки')
            self._eat()
            return node
        if isinstance(t, tuple):
            self._eat()
            if t[0] == 'PHRASE':
                return _Leaf(t[1], exact=True)
            if t[0] == 'WORD':
                return _Leaf(t[1], exact=False)
        raise ValueError(f'ожидалось слово, фраза или «(», получено {t!r}')


def _parse_query(raw):
    tokens = _tokenize_query(raw.strip())
    if not tokens:
        raise ValueError('пустой запрос')
    return _QueryParser(tokens).parse()


def _query_label(raw):
    try:
        tokens = _tokenize_query(raw.strip())
    except ValueError:
        return 'Поиск'
    if any(t in ('AND', 'OR', '(', ')') for t in tokens):
        return 'Продвинутый поиск'
    if len(tokens) == 1 and isinstance(tokens[0], tuple) and tokens[0][0] == 'PHRASE':
        return 'Точный поиск'
    return 'Поиск'


_FTS_TOKEN_RE = re.compile(r'\w+', re.UNICODE)


def _fts_tokens(s):
    # эмуляция unicode61: буквенно-цифровые последовательности
    return [t for t in _FTS_TOKEN_RE.findall(s) if t]


def _escape_fts(w):
    return '"' + w.replace('"', '""') + '"'


def _to_fts_query(node):
    if isinstance(node, _Leaf):
        toks = _fts_tokens(node.term)
        if not toks:
            return None
        if node.exact:
            # точное вхождение проверит Python, FTS нужны просто токены
            return '(' + ' AND '.join(_escape_fts(t) for t in toks) + ')'
        return '(' + ' AND '.join(f'{_escape_fts(t)}*' for t in toks) + ')'
    if isinstance(node, _And):
        lq = _to_fts_query(node.left)
        rq = _to_fts_query(node.right)
        if lq is None and rq is None:
            return None
        if lq is None:
            return rq
        if rq is None:
            return lq
        return f'({lq} AND {rq})'
    if isinstance(node, _Or):
        lq = _to_fts_query(node.left)
        rq = _to_fts_query(node.right)
        if lq is None or rq is None:  # одна ветвь без токенов, OR нельзя сузить
            return None
        return f'({lq} OR {rq})'
    return None


def _eval_query(node, text_lower):
    if isinstance(node, _Leaf):
        return node.term.lower() in text_lower
    if isinstance(node, _And):
        return _eval_query(node.left, text_lower) and _eval_query(node.right, text_lower)
    if isinstance(node, _Or):
        return _eval_query(node.left, text_lower) or _eval_query(node.right, text_lower)
    return False


def _collect_leaves(node):
    if isinstance(node, _Leaf):
        return [node.term]
    if isinstance(node, (_And, _Or)):
        return _collect_leaves(node.left) + _collect_leaves(node.right)
    return []


def _context_term(node, text):
    tl = text.lower()
    best_pos = None
    best_term = ''
    for term in _collect_leaves(node):
        if not term:
            continue
        pos = tl.find(term.lower())
        if pos >= 0 and (best_pos is None or pos < best_pos):
            best_pos = pos
            best_term = term
    if best_term:
        return best_term
    leaves = _collect_leaves(node)
    return leaves[0] if leaves else ''


def do_search(query, conn):
    node = _parse_query(query)
    fts_q = _to_fts_query(node)

    if fts_q is not None:
        rows = conn.execute(
            'SELECT d.path, d.filename, d.extension, d.text, '
            '       d.text_empty, d.has_error, d.indexed_at, d.modified_at '
            'FROM documents d '
            'JOIN documents_fts f ON f.path = d.path '
            'WHERE documents_fts MATCH ?',
            (fts_q,),
        ).fetchall()
    else:
        # пустые токены, полный скан documents
        rows = conn.execute(
            'SELECT path, filename, extension, text, '
            '       text_empty, has_error, indexed_at, modified_at '
            'FROM documents'
        ).fetchall()

    results = []
    for row in rows:
        text = row['text'] or ''
        if not _eval_query(node, text.lower()):
            continue
        entry = {
            'path':        row['path'],
            'filename':    row['filename'],
            'extension':   row['extension'],
            'text':        text,
            'text_empty':  bool(row['text_empty']),
            'has_error':   bool(row['has_error']),
            'indexed_at':  row['indexed_at'],
            'modified_at': row['modified_at'],
        }
        entry['context'] = get_context(text, _context_term(node, text))
        results.append(entry)

    results.sort(key=lambda r: r.get('modified_at', '') or '')
    return results


def get_context(text, word, size=200):
    if not text:
        return ''

    pos = text.lower().find(word.lower()) if word else -1

    if pos == -1:
        frag   = text[:size]
        suffix = '...' if len(text) > size else ''
        return re.sub(r'\s+', ' ', frag).strip() + suffix

    start  = max(0, pos - size // 2)
    end    = min(len(text), pos + len(word) + size // 2)
    frag   = text[start:end]
    prefix = '...' if start > 0 else ''
    suffix = '...' if end < len(text) else ''
    return re.sub(r'\s+', ' ', prefix + frag + suffix).strip()


LINE = '=' * 64
THIN = '-' * 64


def _fmt(n):
    return f'{int(n):,}'.replace(',', '\u00a0')


def print_header(title):
    print(f'\n{LINE}')
    print(f'  {title}')
    print(LINE)
    print()


def _save_stats_cache(index):
    if not index:
        return
    dates = [e['indexed_at'] for e in index.values() if e.get('indexed_at')]
    stats = {
        'total':       len(index),
        'last':        max(dates) if dates else '',
        'empty_count': sum(1 for e in index.values() if e.get('text_empty', False)),
        'error_count': sum(1 for e in index.values() if e.get('has_error',  False)),
    }
    tmp = STATS_FILE + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(stats, f)
        os.replace(tmp, STATS_FILE)
    except Exception:
        pass


def _get_db_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, encoding='utf-8') as f:
                cached = json.load(f)
            if cached.get('total'):
                try:
                    last = datetime.fromisoformat(cached['last']).strftime('%d.%m.%Y %H:%M')
                except Exception:
                    last = cached.get('last') or 'неизвестно'
                return {
                    'total':       cached['total'],
                    'last':        last,
                    'empty_count': cached.get('empty_count', 0),
                    'error_count': cached.get('error_count', 0),
                }
        except Exception:
            pass
    if not os.path.exists(INDEX_DB):
        return None
    try:
        conn = _connect()
        try:
            row = conn.execute(
                'SELECT COUNT(*) as total, MAX(indexed_at) as last, '
                'SUM(text_empty) as empty_count, SUM(has_error) as error_count '
                'FROM documents'
            ).fetchone()
            if not row or not row['total']:
                return None
            try:
                last = datetime.fromisoformat(row['last']).strftime('%d.%m.%Y %H:%M')
            except Exception:
                last = row['last'] or 'неизвестно'
            result = {
                'total':       row['total'],
                'last':        last,
                'empty_count': row['empty_count'] or 0,
                'error_count': row['error_count'] or 0,
            }
            # кэшируем чтобы следующий старт не открывал бд
            tmp = STATS_FILE + '.tmp'
            try:
                with open(tmp, 'w', encoding='utf-8') as f:
                    json.dump({
                        'total':       result['total'],
                        'last':        row['last'] or '',
                        'empty_count': result['empty_count'],
                        'error_count': result['error_count'],
                    }, f)
                os.replace(tmp, STATS_FILE)
            except Exception:
                pass
            return result
        finally:
            conn.close()
    except Exception:
        return None


def print_main_menu(index):
    print_header('ПОИСК ПО ДОКУМЕНТАМ')

    if index:
        dates = [e['indexed_at'] for e in index.values() if e.get('indexed_at')]
        if dates:
            try:
                last = datetime.fromisoformat(max(dates)).strftime('%d.%m.%Y %H:%M')
            except Exception:
                last = max(dates)
        else:
            last = 'неизвестно'
        empty_count   = sum(1 for e in index.values() if e.get('text_empty', False))
        error_count   = sum(1 for e in index.values() if e.get('has_error', False))
        problem_count = empty_count + error_count
        print(f'  Индекс последний раз обновлён: {last}\n')
        print(f'  Файлов в индексе:              {_fmt(len(index))}')
        if problem_count:
            print(f'  Проблемных файлов:             {_fmt(problem_count)}\n')
            print(f'    ({_fmt(error_count)} ошибок, {_fmt(empty_count)} без текста)')
        stats = None
    else:
        stats = _get_db_stats()
        if stats:
            problem_count = stats['empty_count'] + stats['error_count']
            print(f'  Индекс последний раз обновлён: {stats["last"]}\n')
            print(f'  Файлов в индексе:              {_fmt(stats["total"])}')
            if problem_count:
                print(f'  Проблемных файлов:             {_fmt(problem_count)}\n')
                print(f'    ({_fmt(stats["error_count"])} ошибок, {_fmt(stats["empty_count"])} без текста)')
        else:
            print('  Индекс не создан')

    index_exists = bool(index) or bool(stats)
    print()
    print(THIN)
    print('  1. Поиск')
    print('  2. Обновить индекс' if index_exists else '  2. Создать индекс')
    print('  3. Проблемные файлы')
    print('  4. Выйти')
    print(THIN)
    print()


def print_results(results, query, label='Поиск'):
    print()
    if not results:
        print(f'  {label} «{query}»: ничего не найдено.')
        print()
        return

    print(f'  {label} «{query}»: найдено документов: {_fmt(len(results))}')

    for i, r in enumerate(results, 1):
        print()
        print(THIN)
        dir_part = os.path.dirname(r['path'])
        date_str = ''
        if r.get('modified_at'):
            try:
                date_str = '  ' + datetime.fromisoformat(r['modified_at']).strftime('%d.%m.%Y')
            except Exception:
                pass
        print(f'  [{i}] {r["filename"]}{date_str}')
        print(f'      {dir_part}/')

        ctx = r.get('context', '').strip()
        if ctx:
            print('      Фрагмент:')
            for line in textwrap.wrap(ctx, width=56):
                print(f'        {line}')

    print()
    print(THIN)


def _open_result(r, server, login, password):
    path       = r['path']
    smb_dir    = os.path.dirname(path)
    filename   = os.path.basename(path)
    local_path = f'/tmp/_docopen_{os.getpid()}_{filename}'

    print(f'  Скачиваю {filename}...', end='', flush=True)
    try:
        ok = smb_download(server, login, password, smb_dir, filename, local_path)
    except Exception:
        ok = False

    if ok:
        print(f'\r  ✓ Открываю {filename}{" " * 40}')
        subprocess.Popen(['xdg-open', local_path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    else:
        print(f'\r  ✗ Не удалось скачать файл{" " * 40}')
        return False


def search_loop(index, server, login, password):
    conn = _connect()
    try:
        while True:
            while True:
                print()
                query = input('  Введите поисковый запрос: ').strip()
                if query:
                    break
                print('  Запрос не может быть пустым.')

            label = _query_label(query)
            print(f'  {label}: «{query}»...')
            try:
                results = do_search(query, conn)
            except ValueError as e:
                print(f'  Ошибка в запросе: {e}')
                continue
            print_results(results, query, label=label)

            while True:
                if results:
                    print()
                    print('  Номер - открыть файл  |  Enter - новый поиск  |  0 - в меню')
                else:
                    print()
                    print('  Enter - новый поиск  |  0 - в меню')
                raw = input('  › ').strip()

                if raw == '0':
                    return
                elif not raw:
                    break
                elif raw.isdigit():
                    if not results:
                        print('  Нет результатов для открытия.')
                    else:
                        n = int(raw)
                        if 1 <= n <= len(results):
                            opened = _open_result(results[n - 1], server, login, password)
                            if opened:
                                sys.stdout.write('\033[4A\r\033[J')
                                sys.stdout.flush()
                        else:
                            print(f'  Нет файла с номером {n}. Введите от 1 до {_fmt(len(results))}.')
    finally:
        conn.close()


def main():
    check_smbclient()
    login, password, server, share_path = load_config()

    index = {}
    while True:
        print_main_menu(index)
        choice = input('  Выберите действие: ').strip()

        if choice == '1':
            if not index:
                index = load_index()
            if not index:
                print('\n  Индекс пуст. Сначала выберите пункт 2 для обновления индекса.')
            else:
                search_loop(index, server, login, password)

        elif choice == '2':
            new_index = build_index(server, login, password, share_path)
            if new_index:
                index = new_index

        elif choice == '3':
            if not index:
                index = load_index()
            index = problem_files_menu(server, login, password, index)

        elif choice == '4':
            print('\n  До свидания!\n')
            sys.exit(0)

        else:
            print('  Неверный выбор. Введите 1, 2, 3 или 4.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n  Прервано пользователем. До свидания!\n')
        sys.exit(0)