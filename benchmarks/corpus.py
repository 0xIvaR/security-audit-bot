"""Synthetic evaluation corpus containing 580 test cases for security auditing.

This corpus validates:
1. AST True-Positive Rate (TPR) >= 96.4%
2. False-Positive Reduction >= 74% vs. naive regex-only baseline
3. Secret Leak Rate = 0.0% (100% recall on credentials)
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkCase:
    """Represents a single benchmark test case in the evaluation corpus."""

    case_id: str
    category: str  # "AST_OWASP", "SQL_INJECTION", "SECRET", "DEPENDENCY"
    rule_id: str | None
    code: str
    is_vulnerable: bool
    description: str
    file_path: str = "app/sample.py"


def generate_corpus() -> list[BenchmarkCase]:
    """Generate the standardized 580 test case evaluation corpus."""
    cases: list[BenchmarkCase] = []

    # =========================================================================
    # 1. AST OWASP Execution Sinks (AST-001, AST-002, AST-003, AST-005, AST-006)
    # 80 Vuln, 80 Safe = 160 cases
    # =========================================================================

    # --- AST-001: eval() / exec() Vulnerable (32 cases) ---
    eval_vuln_patterns = [
        "eval(user_input)",
        "eval(request.GET['expr'])",
        "eval(payload, {'__builtins__': {}})",
        "res = eval(f'{expr}')",
        "result = eval(raw_code)",
        "output = eval(dynamic_str)",
        "val = eval(user_data.get('formula'))",
        "calculated = eval(untrusted_calc)",
        "answer = eval(math_string)",
        "return eval(expression)",
        "eval(request.form['calculation'])",
        "eval(compile(source, '<string>', 'eval'))",
        "eval(json.loads(data)['script'])",
        "eval(b64decode(encoded_payload))",
        "res = [eval(item) for item in raw_items]",
        "eval(func_name + '()')",
    ]
    for i, pat in enumerate(eval_vuln_patterns, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"AST-VULN-EVAL-{i:03d}",
                category="AST_OWASP",
                rule_id="AST-001",
                code=pat,
                is_vulnerable=True,
                description=f"Direct vulnerable eval sink #{i}",
            )
        )

    exec_vuln_patterns = [
        "exec(user_code)",
        "exec(request.POST['code'])",
        "exec(f'import {module_name}')",
        "exec(script_body, globals_dict)",
        "exec(user_script)",
        "exec(payload)",
        "exec(code_str)",
        "exec(b64decode(blob))",
        "exec(compile(raw_src, 'dynamic', 'exec'))",
        "exec(request.data.decode('utf-8'))",
        "exec('def dynamic_fn(): pass')",
        "exec(untrusted_input)",
        "exec(module_code, scope)",
        "exec(f'x = {dynamic_val}')",
        "exec(uploaded_file.read())",
        "exec(config.get('custom_logic'))",
    ]
    for i, pat in enumerate(exec_vuln_patterns, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"AST-VULN-EXEC-{i:03d}",
                category="AST_OWASP",
                rule_id="AST-001",
                code=pat,
                is_vulnerable=True,
                description=f"Direct vulnerable exec sink #{i}",
            )
        )

    # --- AST-003: Command Injection Vulnerable (16 cases) ---
    cmd_vuln_patterns = [
        "os.system(user_command)",
        "os.system('ping ' + host)",
        "os.system(f'rm -rf {target_dir}')",
        "os.system(request.GET['cmd'])",
        "os.popen(f'cat {file_name}')",
        "os.popen('ls ' + user_folder)",
        "subprocess.Popen(cmd, shell=True)",
        "subprocess.Popen(f'echo {msg}', shell=True)",
        "subprocess.Popen('bash ' + script, shell=True)",
        "subprocess.run(command_str, shell=True)",
        "subprocess.run(f'git clone {repo_url}', shell=True)",
        "subprocess.run(user_input, shell=True)",
        "subprocess.call(cmd_line, shell=True)",
        "subprocess.call(f'curl {url}', shell=True)",
        "subprocess.check_call(cmd, shell=True)",
        "subprocess.check_output(f'tar -xzf {archive}', shell=True)",
    ]
    for i, pat in enumerate(cmd_vuln_patterns, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"AST-VULN-CMD-{i:03d}",
                category="AST_OWASP",
                rule_id="AST-003",
                code=pat,
                is_vulnerable=True,
                description=f"Command injection sink #{i}",
            )
        )

    # --- AST-002: Insecure Deserialization Vulnerable (16 cases) ---
    deser_vuln_patterns = [
        "pickle.loads(user_payload)",
        "pickle.loads(request.body)",
        "pickle.loads(b64decode(raw_token))",
        "pickle.load(uploaded_stream)",
        "pickle.load(socket_file)",
        "_pickle.loads(serialized_data)",
        "cPickle.loads(untrusted_blob)",
        "yaml.load(user_yaml, Loader=yaml.Loader)",
        "yaml.load(raw_config, Loader=yaml.CLoader)",
        "yaml.load(payload, Loader=yaml.UnsafeLoader)",
        "yaml.load(uploaded_text)",
        "yaml.load(stream)",
        "yaml.load(config_file.read())",
        "pickle.loads(redis_client.get('session'))",
        "pickle.load(open('untrusted.pkl', 'rb'))",
        "yaml.load(request.data)",
    ]
    for i, pat in enumerate(deser_vuln_patterns, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"AST-VULN-DESER-{i:03d}",
                category="AST_OWASP",
                rule_id="AST-002",
                code=pat,
                is_vulnerable=True,
                description=f"Insecure deserialization sink #{i}",
            )
        )

    # --- AST-006: Weak Cryptographic Hash Function Vulnerable (16 cases) ---
    crypto_vuln_patterns = [
        "hashlib.md5(user_password.encode())",
        "hashlib.md5(b'secret_key').hexdigest()",
        "token_hash = hashlib.md5(data).digest()",
        "pwd_hash = hashlib.md5(raw_pwd)",
        "hashlib.sha1(user_password.encode())",
        "hashlib.sha1(b'sensitive_data').hexdigest()",
        "signature = hashlib.sha1(data).digest()",
        "hashlib.md5(salt + password)",
        "hashlib.sha1(auth_token)",
        "digest = hashlib.md5(f'{user}:{pwd}'.encode())",
        "checksum = hashlib.md5(file_content).hexdigest()",
        "api_hash = hashlib.sha1(request.body).digest()",
        "h = hashlib.md5()",
        "h_sha1 = hashlib.sha1()",
        "pwd_md5 = hashlib.md5(b'test').hexdigest()",
        "data_sha1 = hashlib.sha1(b'input').hexdigest()",
    ]
    for i, pat in enumerate(crypto_vuln_patterns, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"AST-VULN-CRYPTO-{i:03d}",
                category="AST_OWASP",
                rule_id="AST-006",
                code=pat,
                is_vulnerable=True,
                description=f"Weak cryptographic hash sink #{i}",
            )
        )

    # --- AST Benign / Negative Cases (80 cases) ---
    # These trigger false alarms in naive regex-only scanners!
    ast_safe_comments = [
        "# Avoid using eval(user_input) in production code",
        "# exec(code) is disabled for security reasons",
        "# TODO: replace os.system(cmd) with subprocess.run",
        "# Do not use subprocess.Popen(cmd, shell=True)",
        "# pickle.loads(data) should be replaced with json.loads",
        "# Note: yaml.load without Loader is deprecated and unsafe",
        "# Deprecated: hashlib.md5 is vulnerable to collision attacks",
        "# Never use hashlib.sha1 for password hashing",
        "# Old logic was: eval(expression)",
        "# Refactored: removed exec(script)",
        "# Audit: check if os.system is invoked anywhere",
        "# subprocess.call(cmd, shell=True) was flagged in penetration test",
        "# Migrated away from pickle.loads to msgpack",
        "# Replaced yaml.load(data, Loader=yaml.Loader) with safe_load",
        "# Security policy forbids hashlib.md5 for signatures",
        "# Removed hashlib.sha1 from authentication flow",
        "# Reminder: sanitize inputs before eval",
        "# Comment: os.popen is discouraged",
        "# Verification: do not call pickle.load on socket",
        "# Safety note: avoid exec() in templates",
    ]
    for i, pat in enumerate(ast_safe_comments, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"AST-SAFE-COMMENT-{i:03d}",
                category="AST_OWASP",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Comment mentioning security sink #{i}",
            )
        )

    ast_safe_docstrings = [
        '"""Safely evaluates expressions using ast.literal_eval, never eval()."""',
        '"""Executes workflow tasks. Do not call exec() dynamically."""',
        '"""Spawns system process via subprocess.run with shell=False."""',
        '"""Deserializes JSON payloads. Replaces unsafe pickle.loads."""',
        '"""Loads YAML configurations safely using yaml.safe_load."""',
        '"""Calculates secure password hashes using bcrypt, avoiding hashlib.md5."""',
        '"""Helper function: document why eval is forbidden."""',
        '"""Runs command safely without os.system."""',
        '"""Processes serialized models without pickle."""',
        '"""Verifies SHA-256 integrity, rejecting weak hashlib.sha1."""',
        '"""Docstring note on subprocess shell=True vulnerability."""',
        '"""Explains safe evaluation strategies for formulas."""',
        '"""Parses user input without calling exec()."""',
        '"""Security guidelines: always pass Loader=yaml.SafeLoader."""',
        '"""Data pipeline: hashing with sha256 rather than md5."""',
        '"""Safe execution wrapper preventing shell injection."""',
        '"""Serialization utility: use json or protobuf."""',
        '"""Cryptographic hashing standard for the application."""',
        '"""Docstring: why pickle.loads is unsafe on network streams."""',
        '"""Avoid dynamic exec in authorization layer."""',
    ]
    for i, pat in enumerate(ast_safe_docstrings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"AST-SAFE-DOCSTRING-{i:03d}",
                category="AST_OWASP",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Docstring mentioning security sink #{i}",
            )
        )

    ast_safe_patterns = [
        "subprocess.run(['ls', '-la'])",
        "subprocess.run(['git', 'status'], check=True)",
        "subprocess.Popen(['python', 'script.py'], shell=False)",
        "subprocess.Popen(['docker', 'build', '.'])",
        "subprocess.call(['npm', 'test'])",
        "subprocess.check_output(['cat', '/etc/hosts'])",
        "subprocess.run(['kubectl', 'get', 'pods'], capture_output=True)",
        "subprocess.Popen(['pytest', '-v'], shell=False)",
        "subprocess.run(['pip', 'list'])",
        "subprocess.run(['make', 'build'])",
        "yaml.safe_load(raw_yaml_string)",
        "yaml.safe_load(config_file.read())",
        "yaml.load(user_stream, Loader=yaml.SafeLoader)",
        "yaml.load(config_data, Loader=yaml.CSafeLoader)",
        "yaml.safe_load(request.body)",
        "hashlib.sha256(password.encode()).hexdigest()",
        "hashlib.sha512(sensitive_blob).digest()",
        "hashlib.sha256(salt + data)",
        "hashlib.sha384(payload.encode())",
        "ast.literal_eval(safe_str_literal)",
        "ast.literal_eval(config_dict_str)",
        "json.loads(user_payload)",
        "json.loads(request.body)",
        "evaluation_score = 98.5",
        "evaluation_metric = 'accuracy'",
        "evaluate_performance(model, test_data)",
        "execution_timer = time.time()",
        "system_status = 'OPERATIONAL'",
        "os_name = os.name",
        "md5_checksum = 'legacy_record'",
        "sha1_fingerprint = 'legacy_cert'",
        "user_eval_count = 10",
        "system_load_avg = os.getloadavg()",
        "exec_count = len(executed_tasks)",
        "task_executor = TaskExecutor()",
        "crypto_backend = 'cryptography'",
        "safe_shell_runner(['echo', 'hello'])",
        "yaml_parser = YamlParser()",
        "md5_label = 'algorithm_name'",
        "sha1_label = 'hash_type'",
    ]
    for i, pat in enumerate(ast_safe_patterns, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"AST-SAFE-CODE-{i:03d}",
                category="AST_OWASP",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Safe code pattern not triggering AST sinks #{i}",
            )
        )

    # =========================================================================
    # 2. AST SQL Injection (AST-004) — 80 Vuln, 80 Safe = 160 cases
    # =========================================================================

    sqli_vuln_fstrings = [
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        "db.execute(f\"SELECT name, email FROM accounts WHERE role = '{role}'\")",
        "session.execute(f\"DELETE FROM sessions WHERE token = '{token}'\")",
        "connection.execute(f\"UPDATE users SET email = '{new_email}' WHERE id = {uid}\")",
        "cursor.execute(f\"INSERT INTO audit_log VALUES ('{event}', {timestamp})\")",
        'cursor.execute(f"SELECT * FROM orders WHERE customer_id = {cid}")',
        "db.raw(f\"SELECT balance FROM wallets WHERE user = '{username}'\")",
        "cursor.execute(f\"SELECT * FROM products WHERE category = '{cat}'\")",
        "session.execute(f\"UPDATE inventory SET qty = {qty} WHERE sku = '{sku}'\")",
        'connection.execute(f"DELETE FROM tokens WHERE user_id = {uid}")',
        'cursor.execute(f"SELECT hash FROM passwords WHERE user_id = {uid}")',
        "db.execute(f\"INSERT INTO comments (post_id, body) VALUES ({pid}, '{body}')\")",
        'cursor.execute(f"SELECT * FROM transactions WHERE amount > {min_amt}")',
        "session.execute(f\"SELECT status FROM tasks WHERE id = '{task_id}'\")",
        "connection.execute(f\"UPDATE settings SET val = '{val}' WHERE key = '{k}'\")",
        "cursor.execute(f\"SELECT * FROM items WHERE name LIKE '%{search}%'\")",
        'db.raw(f"SELECT count(*) FROM users WHERE org_id = {org_id}")',
        "cursor.execute(f\"DELETE FROM carts WHERE session_id = '{session_id}'\")",
        "session.execute(f\"SELECT * FROM files WHERE path = '{path}'\")",
        "connection.execute(f\"INSERT INTO roles (user_id, role) VALUES ({uid}, '{role}')\")",
    ]
    for i, pat in enumerate(sqli_vuln_fstrings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SQLI-VULN-FSTR-{i:03d}",
                category="SQL_INJECTION",
                rule_id="AST-004",
                code=pat,
                is_vulnerable=True,
                description=f"Vulnerable f-string SQL query #{i}",
            )
        )

    sqli_vuln_percent = [
        "cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % user_name)",
        'db.execute("SELECT * FROM accounts WHERE id = %d" % account_id)',
        "session.execute(\"DELETE FROM sessions WHERE id = '%s'\" % session_id)",
        "connection.execute(\"UPDATE users SET active = 1 WHERE email = '%s'\" % email)",
        "cursor.execute(\"INSERT INTO logs VALUES ('%s')\" % message)",
        'db.raw("SELECT balance FROM accounts WHERE user_id = %s" % uid)',
        'cursor.execute("SELECT * FROM products WHERE price < %f" % max_price)',
        "session.execute(\"SELECT * FROM items WHERE category = '%s'\" % cat)",
        'connection.execute("DELETE FROM cart_items WHERE cart_id = %d" % cid)',
        "cursor.execute(\"SELECT token FROM auth WHERE username = '%s'\" % user)",
        "db.execute(\"UPDATE profile SET bio = '%s' WHERE id = %d\" % (bio, uid))",
        "cursor.execute(\"SELECT * FROM orders WHERE status = '%s'\" % status)",
        "session.execute(\"INSERT INTO messages (text) VALUES ('%s')\" % text)",
        "connection.execute(\"SELECT count(*) FROM members WHERE team = '%s'\" % team)",
        "cursor.execute(\"DELETE FROM blacklisted_ips WHERE ip = '%s'\" % ip)",
        'db.raw("SELECT * FROM employees WHERE dept_id = %d" % dept_id)',
        "cursor.execute(\"UPDATE servers SET state = '%s' WHERE id = %d\" % (st, sid))",
        "session.execute(\"SELECT * FROM keys WHERE label = '%s'\" % label)",
        "connection.execute(\"SELECT id FROM documents WHERE title = '%s'\" % title)",
        "cursor.execute(\"DELETE FROM expired_codes WHERE code = '%s'\" % code)",
    ]
    for i, pat in enumerate(sqli_vuln_percent, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SQLI-VULN-MOD-{i:03d}",
                category="SQL_INJECTION",
                rule_id="AST-004",
                code=pat,
                is_vulnerable=True,
                description=f"Vulnerable % formatted SQL query #{i}",
            )
        )

    sqli_vuln_format = [
        "cursor.execute(\"SELECT * FROM users WHERE id = '{}'\".format(user_id))",
        "db.execute(\"SELECT email FROM accounts WHERE role = '{}'\".format(role))",
        "session.execute(\"DELETE FROM sessions WHERE token = '{}'\".format(tok))",
        "connection.execute(\"UPDATE users SET status = '{}' WHERE id = {}\".format(s, uid))",
        "cursor.execute(\"INSERT INTO events (name) VALUES ('{}')\".format(name))",
        'db.raw("SELECT * FROM transactions WHERE cid = {}".format(cid))',
        "cursor.execute(\"SELECT * FROM items WHERE cat = '{0}'\".format(category))",
        "session.execute(\"SELECT * FROM profiles WHERE username = '{u}'\".format(u=username))",
        "connection.execute(\"DELETE FROM cache WHERE key = '{}'\".format(cache_key))",
        'cursor.execute("SELECT hash FROM creds WHERE id = {}".format(uid))',
        "db.execute(\"UPDATE config SET val = '{}' WHERE param = '{}'\".format(val, p))",
        "cursor.execute(\"SELECT * FROM bookings WHERE date = '{}'\".format(booking_date))",
        "session.execute(\"INSERT INTO audit (action) VALUES ('{}')\".format(act))",
        "connection.execute(\"SELECT count(*) FROM logs WHERE level = '{}'\".format(lvl))",
        "cursor.execute(\"DELETE FROM otps WHERE phone = '{}'\".format(phone))",
        "db.raw(\"SELECT * FROM customers WHERE region = '{}'\".format(reg))",
        "cursor.execute(\"UPDATE nodes SET healthy = {} WHERE ip = '{}'\".format(h, ip))",
        "session.execute(\"SELECT * FROM certificates WHERE cn = '{}'\".format(cn))",
        "connection.execute(\"SELECT id FROM articles WHERE slug = '{}'\".format(slug))",
        'cursor.execute("DELETE FROM deadlocks WHERE pid = {}".format(pid))',
    ]
    for i, pat in enumerate(sqli_vuln_format, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SQLI-VULN-FMT-{i:03d}",
                category="SQL_INJECTION",
                rule_id="AST-004",
                code=pat,
                is_vulnerable=True,
                description=f"Vulnerable .format() SQL query #{i}",
            )
        )

    sqli_vuln_concat = [
        "cursor.execute('SELECT * FROM users WHERE id = ' + str(user_id))",
        "db.execute('SELECT email FROM accounts WHERE name = \\'' + name + '\\'')",
        "session.execute('DELETE FROM sessions WHERE token = \\'' + token + '\\'')",
        "connection.execute('UPDATE users SET role = \\'' + role + '\\' WHERE id = 1')",
        "cursor.execute('INSERT INTO logs (msg) VALUES (\\'' + message + '\\')')",
        "db.raw('SELECT * FROM data WHERE tag = \\'' + tag + '\\'')",
        "cursor.execute('SELECT * FROM items WHERE cat = \\'' + category + '\\'')",
        "session.execute('SELECT * FROM orders WHERE cust = \\'' + customer + '\\'')",
        "connection.execute('DELETE FROM tokens WHERE jti = \\'' + jti + '\\'')",
        "cursor.execute('SELECT balance FROM accounts WHERE num = \\'' + acc + '\\'')",
        "db.execute('UPDATE settings SET theme = \\'' + theme + '\\'') ",
        "cursor.execute('SELECT * FROM posts WHERE author = \\'' + author + '\\'')",
        "session.execute('INSERT INTO notes (body) VALUES (\\'' + note + '\\')')",
        "connection.execute('SELECT count(*) FROM visits WHERE ip = \\'' + ip + '\\'')",
        "cursor.execute('DELETE FROM temp_files WHERE name = \\'' + fname + '\\'')",
        "db.raw('SELECT * FROM telemetry WHERE sensor = \\'' + sname + '\\'')",
        "cursor.execute('UPDATE jobs SET status = \\'' + status + '\\' WHERE id = 5')",
        "session.execute('SELECT * FROM devices WHERE mac = \\'' + mac + '\\'')",
        "connection.execute('SELECT id FROM categories WHERE slug = \\'' + slug + '\\'')",
        "cursor.execute('DELETE FROM sessions WHERE cookie = \\'' + cookie + '\\'')",
    ]
    for i, pat in enumerate(sqli_vuln_concat, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SQLI-VULN-CONCAT-{i:03d}",
                category="SQL_INJECTION",
                rule_id="AST-004",
                code=pat,
                is_vulnerable=True,
                description=f"Vulnerable concatenation SQL query #{i}",
            )
        )

    # --- SQL Benign / Parameterized Cases (80 cases) ---
    sqli_safe_parameterized = [
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "cursor.execute('SELECT email, name FROM accounts WHERE role = %s', (role,))",
        "session.execute('DELETE FROM sessions WHERE token = :token', {'token': tok})",
        "connection.execute('UPDATE users SET email = %s WHERE id = %s', (new_email, uid))",
        "cursor.execute('INSERT INTO audit_log VALUES (?, ?)', (event, timestamp))",
        "db.execute('SELECT * FROM products WHERE price < :max_p', {'max_p': price})",
        "session.execute('SELECT * FROM items WHERE category = %s', (category,))",
        "connection.execute('DELETE FROM carts WHERE user_id = :uid', {'uid': user_id})",
        "cursor.execute('SELECT hash FROM passwords WHERE user_id = ?', (uid,))",
        "db.execute('INSERT INTO comments (pid, body) VALUES (%s, %s)', (pid, body))",
        "cursor.execute('SELECT * FROM transactions WHERE amount > %s', (min_amt,))",
        "session.execute('SELECT status FROM tasks WHERE id = :id', {'id': tid})",
        "connection.execute('UPDATE settings SET val = %s WHERE key = %s', (val, k))",
        "cursor.execute('SELECT * FROM items WHERE name LIKE %s', (search_pattern,))",
        "cursor.execute('DELETE FROM carts WHERE session_id = %s', (sess_id,))",
        "session.execute('SELECT * FROM files WHERE path = :p', {'p': filepath})",
        "connection.execute('INSERT INTO roles (uid, r) VALUES (?, ?)', (uid, role))",
        "cursor.execute('SELECT count(*) FROM logs WHERE level = %s', (level,))",
        "db.execute('UPDATE accounts SET active = %s WHERE id = %s', (True, aid))",
        "cursor.execute('SELECT * FROM customers WHERE org_id = %s', (org_id,))",
    ]
    for i, pat in enumerate(sqli_safe_parameterized, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SQLI-SAFE-PARAM-{i:03d}",
                category="SQL_INJECTION",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Safe parameterized SQL query #{i}",
            )
        )

    sqli_safe_static = [
        "cursor.execute('SELECT id, name FROM users WHERE active = 1')",
        "db.execute('DELETE FROM sessions WHERE expired_at < NOW()')",
        "session.execute('SELECT count(*) FROM products')",
        "connection.execute('UPDATE settings SET maintenance = 0')",
        "cursor.execute('SELECT 1')",
        "db.execute('VACUUM ANALYZE')",
        "cursor.execute('SHOW TABLES')",
        "session.execute('SELECT * FROM categories ORDER BY name ASC')",
        "connection.execute('DELETE FROM error_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)')",
        "cursor.execute('SELECT version()')",
        "db.execute('OPTIMIZE TABLE telemetry')",
        "cursor.execute('SELECT id FROM admins WHERE superuser = true')",
        "session.execute('SELECT min(price), max(price) FROM inventory')",
        "connection.execute('UPDATE counters SET views = views + 1 WHERE id = 1')",
        "cursor.execute('SELECT * FROM schema_migrations')",
        "db.execute('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE')",
        "cursor.execute('SELECT now()')",
        "session.execute('SELECT count(distinct user_id) FROM visits')",
        "connection.execute('TRUNCATE TABLE temp_buffer')",
        "cursor.execute('SELECT current_user')",
    ]
    for i, pat in enumerate(sqli_safe_static, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SQLI-SAFE-STATIC-{i:03d}",
                category="SQL_INJECTION",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Safe static SQL query #{i}",
            )
        )

    sqli_safe_comments = [
        "# cursor.execute(f'SELECT * FROM users WHERE id = {user_id}') - DO NOT USE",
        "# Vulnerable SQL: cursor.execute('SELECT * FROM users WHERE name = %s' % name)",
        "# Note: avoid f'SELECT * FROM {table}' in dynamic queries",
        "# SELECT * FROM orders WHERE customer_id = 123",
        "# UPDATE accounts SET balance = balance + 100",
        "# DELETE FROM users WHERE id = 5",
        "# INSERT INTO audit_log VALUES ('LOGIN', NOW())",
        "# Example SQL: SELECT count(*) FROM sessions",
        "# Legacy query: cursor.execute('SELECT * FROM items WHERE id = ' + item_id)",
        "# Review: ensure cursor.execute uses parameterized tuple",
        "# Todo: migrate cursor.execute to sqlalchemy orm",
        "# Query plan: SELECT * FROM products JOIN categories ON products.cat_id = categories.id",
        "# Warning: string formatting in cursor.execute leads to SQL injection",
        "# Documentation: cursor.execute(query, params) binds parameters safely",
        "# SELECT email FROM users WHERE confirmed = 1",
        "# Fix: replaced execute('SELECT ' + col) with whitelist",
        "# SQL snippet for migration: ALTER TABLE users ADD COLUMN age INT",
        "# Stored procedure: CALL update_balances()",
        "# DROP TABLE test_db; -- sample comment",
        "# SELECT id, title FROM posts WHERE published = true",
    ]
    for i, pat in enumerate(sqli_safe_comments, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SQLI-SAFE-COMMENT-{i:03d}",
                category="SQL_INJECTION",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Comment mentioning SQL query #{i}",
            )
        )

    sqli_safe_docstrings_and_vars = [
        '"""Executes SELECT queries with parameterized filters."""',
        '"""Performs database INSERT operations safely."""',
        '"""Updates user profile records in PostgreSQL."""',
        '"""Deletes expired auth tokens from the sessions table."""',
        '"""Database helper: executes raw SQL statements with tuple binding."""',
        "log_msg = f'SELECT query started for user {user_id}'",
        "metric_label = 'SELECT_QUERY_COUNT'",
        "status_text = 'INSERT operation completed successfully'",
        "error_str = f'DELETE failed for entity: {entity_name}'",
        "description = 'UPDATE transaction balances'",
        "sql_keyword = 'SELECT'",
        "allowed_verbs = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']",
        "query_summary = f'Total SELECT calls today: {count}'",
        "db_action_type = 'SELECT_USER'",
        "prompt = 'Enter your SQL query for database inspection:'",
        "user_role_sql_view = 'v_user_roles'",
        "selected_item = 'SELECT_ALL'",
        "select_dropdown_options = ['Option 1', 'Option 2']",
        "select_button_label = 'Select Item'",
        "action_name = 'select_account'",
    ]
    for i, pat in enumerate(sqli_safe_docstrings_and_vars, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SQLI-SAFE-NONCODE-{i:03d}",
                category="SQL_INJECTION",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Non-database code with SQL keywords #{i}",
            )
        )

    # =========================================================================
    # 3. Hybrid Secret Scanner (SEC-001 - SEC-007) — 100 Vuln, 100 Safe = 200 cases
    # =========================================================================

    # --- Secrets Vulnerable (100 cases, 100% recall required!) ---
    # SEC-001: AWS Access Key (15 cases)
    aws_keys = [
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7ABCD123"',
        'aws_key = "AKIA1234567890ABCDEF"',
        'AWS_KEY="AKIAI44QH8DHB9876543"',
        's3_access_key = "AKIAJ6R4Z9P2L1567890"',
        'export AWS_ACCESS_KEY_ID="AKIAQWERTYUIOPASDFGH"',
        'access_key: "AKIAZXCVBNMASDFGHJKL"',
        '"aws_access_key": "AKIA9876543210POIUYT"',
        'AWS_ACCESS_KEY = "AKIAABCD1234EFGH5678"',
        'creds = {"key": "AKIAFEDCBA9876543210"}',
        'CLIENT_KEY = "AKIA1122334455667788"',
        'aws_token_id = "AKIA9988776655443322"',
        'os.environ["AWS_KEY"] = "AKIAAAABBBBCCCCDDDDE"',
        'AWS_ID = "AKIAZZZZYYYYXXXXWWWW"',
        'backup_key = "AKIA5555444433332222"',
        'PRIMARY_AWS_KEY = "AKIA6666777788889999"',
    ]
    for i, pat in enumerate(aws_keys, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-VULN-AWS-{i:03d}",
                category="SECRET",
                rule_id="SEC-001",
                code=pat,
                is_vulnerable=True,
                description=f"AWS Access Key ID secret #{i}",
            )
        )

    # SEC-002: AWS Secret Access Key (15 cases)
    aws_secrets = [
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY1234567890"',
        'aws_secret_key = "v9k3L+Z8yR2mN0qP4sT6uV8wX0yZ2aB4cD6eF8gH"',
        'AWS_SECRET = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+abc"',
        'secret_key: "9a8b7c6d5e4f3g2h1i0jK+L/M=N+O/P=Q+R/S=T+"',
        'export AWS_SECRET_ACCESS_KEY="1234567890abcdefghijklmnopqrstuvwx/yz+"',
        'aws_secret = "q1w2e3r4t5y6u7i8o9p0A+B/C=D+E/F=G+H/I=J+"',
        '"aws_secret_access_key": "Z9Y8X7W6V5U4T3S2R1Q0P/O+N=M+L/K=J+I/H="',
        'AWS_SECRET_KEY = "h4k8L2n6P0r4T8v2Z6b0D4f8H2j6L0n4P8r2T6v0"',
        's3_secret = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"',
        'AWS_SECRET_KEY = "xK9#mP2$vL5&nQ8*wR1!zT4^yU7%bE0@cD3+fG6="',
        's3_client_secret = "J8mN2qP4sT6uV8wX0yZ2aB4cD6eF8gH0jK2lM4n6"',
        'aws_sec = "K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0"',
        'SECRET_KEY_ID = "vL5nQ8wR1zT4yU7bE0cD3fG6hI9jK2lM4n6pP8r0"',
        'aws_master_secret = "X0yZ2aB4cD6eF8gH0jK2lM4n6pP8r0t2V4w6X8z0"',
        'AWS_SECRET_ACCESS_KEY = "P8r2T6v0X4z8B2d6F0h4J8l2N6p0R4t8V2x6Z0b4"',
    ]
    for i, pat in enumerate(aws_secrets, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-VULN-AWS-SEC-{i:03d}",
                category="SECRET",
                rule_id="SEC-002",
                code=pat,
                is_vulnerable=True,
                description=f"AWS Secret Key assignment #{i}",
            )
        )

    # SEC-003: GitHub Personal Access Tokens (15 cases)
    github_pats = [
        'GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"',
        'gh_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"',
        'pat: "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"',
        'export GITHUB_PAT="ghp_Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2"',
        '"github_token": "ghp_9876543210ZYXWVUTSRQPONMLKJIHGFEDCBA"',
        'GH_PAT = "ghp_token1234567890abcdefghijklmnopqrstuv"',
        'bot_token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"',
        'GITHUB_API_KEY = "ghp_secureTokenStringForGitHubApiAuditBot123"',
        'ci_token = "ghp_0123456789abcdefghijklmnopqrstuvwx"',
        'gh_pat_admin = "ghp_adminTokenForRepoAuditingAndDeploying12"',
        'GITHUB_FINE_GRAINED = "github_pat_11A2B3C4D01234567890abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"',
        'fine_pat = "github_pat_11QWERTYUIOP0123456789abcdefghijklmnopqrstuvwxyz_0123456789ABCDEFGHIJKLMNOPQRSTUV"',
        'GH_SECRET = "ghp_k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8"',
        'GITHUB_ACCESS_TOKEN = "ghp_prodTokenForAuditBotScanning1234567890"',
        'RELEASE_TOKEN = "ghp_ReleaseAutomationTokenForGitHubActionCI12"',
    ]
    for i, pat in enumerate(github_pats, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-VULN-GHPAT-{i:03d}",
                category="SECRET",
                rule_id="SEC-003",
                code=pat,
                is_vulnerable=True,
                description=f"GitHub PAT credential #{i}",
            )
        )

    # SEC-004: Private Key Headers (15 cases)
    priv_keys = [
        'SSL_KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0"',
        'PEM_HEADER = "-----BEGIN PRIVATE KEY-----"',
        'ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----"',
        'dsa_key = "-----BEGIN DSA PRIVATE KEY-----"',
        'ec_key = "-----BEGIN EC PRIVATE KEY-----"',
        'CERT_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----"',
        'private_pem = "-----BEGIN RSA PRIVATE KEY-----"',
        'TLS_PRIVATE = "-----BEGIN PRIVATE KEY-----"',
        'SERVER_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----"',
        'KEY_DATA = "-----BEGIN EC PRIVATE KEY-----"',
        'CLIENT_PEM = "-----BEGIN RSA PRIVATE KEY-----"',
        'SIGNING_KEY = "-----BEGIN PRIVATE KEY-----"',
        'AUTH_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----"',
        'CA_KEY = "-----BEGIN RSA PRIVATE KEY-----"',
        'ROOT_KEY = "-----BEGIN PRIVATE KEY-----"',
    ]
    for i, pat in enumerate(priv_keys, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-VULN-KEY-{i:03d}",
                category="SECRET",
                rule_id="SEC-004",
                code=pat,
                is_vulnerable=True,
                description=f"Private key header #{i}",
            )
        )

    # SEC-005: JWT Tokens (15 cases)
    jwt_tokens = [
        'JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"',
        'auth_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCIsImF1ZCI6ImFwaSIsInN1YiI6InVzZXJfMTIzIn0.dozS87q7z6aB4cD6eF8gH0jK2lM4n6pP8r0t2V4w6X8z0"',
        'bearer_token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjQyLCJyb2xlIjoiYWRtaW4ifQ.k9L2mN4pP6r8t0V2x4Z6b8D0f2H4j6L8n0P2r4T6v8"',
        'user_token = "eyJhbGciOiJFUzI1NiJ9.eyJ1c2VyIjoidGVzdCJ9.X0yZ2aB4cD6eF8gH0jK2lM4n6pP8r0t2V4w6X8z0"',
        'id_token = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"',
        'session_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzZXNzaW9uX2lkIjoiOTk5OSJ9.c1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6s7t8u9v0"',
        'access_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMDAxfQ.m9N0pP2r4T6v8X0z2B4d6F8h0J2l4N6p8R0t2V4"',
        'refresh_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCJ9.r8T0v2X4z6B8d0F2h4J6l8N0p2R4t6V8x0Z2b4"',
        'app_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJhcHBfaWQiOiJzZWN1cml0eS1ib3QifQ.q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9"',
        'admin_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc19hZG1pbiI6dHJ1ZX0.z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1"',
        'oauth_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzY29wZSI6InJlYWQ6d3JpdGUifQ.b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"',
        'service_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdmMiOiJhdWRpdC1ib3QifQ.d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2"',
        'worker_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ3b3JrZXIiOiIxMiJ9.f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4"',
        'client_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJjbGllbnQiOiJ3ZWIifQ.h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6"',
        'gateway_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJndyI6ImFwaS1nYXRld2F5In0.j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8"',
    ]
    for i, pat in enumerate(jwt_tokens, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-VULN-JWT-{i:03d}",
                category="SECRET",
                rule_id="SEC-005",
                code=pat,
                is_vulnerable=True,
                description=f"Hardcoded JWT token #{i}",
            )
        )

    # SEC-006: Slack Webhooks / Bot Tokens (15 cases)
    slack_tokens = [
        'SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"',
        'slack_hook = "https://hooks.slack.com/services/T12345678/B12345678/aBcDeFgHiJkLmNoPqRsTuVwX"',
        'webhook_url = "https://hooks.slack.com/services/T99999999/B88888888/1234567890abcdefghijklmn"',
        'SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"',
        'slack_token = "xoxp-987654321098-9876543210987-zyxwvutsrqponmlkjihgfedc"',
        'SLACK_USER_TOKEN = "xoxa-112233445566-1122334455667-aabbccddeeffgghhiijjkkll"',
        'slack_api_token = "xoxr-123456789012-1234567890123-abcdef1234567890abcdef1234567890"',
        'hook: "https://hooks.slack.com/services/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"',
        'alert_hook = "https://hooks.slack.com/services/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"',
        'SLACK_API = "xoxb-555555555555-4444444444444-1234567890abcdef12345678"',
        'SLACK_SIGNING = "xoxr-666666666666-7777777777777-abcdefabcdefabcdefabcdef"',
        'notification_url = "https://hooks.slack.com/services/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"',
        'incident_hook = "https://hooks.slack.com/services/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"',
        'SLACK_OAUTH = "xoxb-222233334444-5555666677778-testtokenfortestingsecscanner"',
        'SLACK_SECRET_URL = "https://hooks.slack.com/services/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"',
    ]
    for i, pat in enumerate(slack_tokens, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-VULN-SLACK-{i:03d}",
                category="SECRET",
                rule_id="SEC-006",
                code=pat,
                is_vulnerable=True,
                description=f"Slack webhook or token #{i}",
            )
        )

    # SEC-007: Shannon Entropy Tokens (10 cases)
    # Using high entropy base64/unstructured strings > 4.5 bits/char that are not suppressed
    entropy_tokens = [
        'api_secret_token = "dGhpcy1pcy1hLXJhbmRvbS1zdHJpbmctd2l0aC1lbnRyb3B5IQ=="',
        'STRIPE_LIVE_KEY = "sk_live_51NzQ8wR1zT4yU7bE0cD3fG6hI9jK2lM4n6pP8r0t2V4w6X8z0"',
        'SENDGRID_API_KEY = "SG.vL5nQ8wR1zT4yU7bE0cD3f.G6hI9jK2lM4n6pP8r0t2V4w6X8z0aB4cD6eF8gH"',
        'DATADOG_APP_KEY = "datadog_app_key_9f8e7d6c5b4a3928170f1e2d3c4b5a69788796a5_QWERTYUIOP"',
        'TWILIO_AUTH_TOKEN = "twilio_token_7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e_AbCdEfGhIjKlMnOp"',
        'OCTOKIT_AUTH = "gho_16C7e42F292c6912E7710c838347Ae178B4a"',
        'PAGERDUTY_TOKEN = "u+wR1zT4yU7bE0cD3fG6hI9jK2lM4n6p"',
        'NEW_RELIC_LICENSE = "eu01xx9a8b7c6d5e4f3g2h1i0jK+L/M=N+O/P"',
        'CLOUDFLARE_API_KEY = "b64_cf_token_4c9b8a7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2_XyZ+WvUtSrQp"',
        'SENTRY_AUTH_TOKEN = "sntrys_eyJpYXQiOjE2ODAwMDAwMDAsInNpZyI6ImF1ZGl0LWJvdCJ9"',
    ]
    for i, pat in enumerate(entropy_tokens, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-VULN-ENTROPY-{i:03d}",
                category="SECRET",
                rule_id="SEC-007",
                code=pat,
                is_vulnerable=True,
                description=f"High entropy secret token #{i}",
            )
        )

    # --- Secrets Benign / Allowlist Cases (100 cases) ---
    english_strings = [
        'welcome_msg = "Please enter your username and password to log in"',
        'description = "This application provides continuous security auditing for GitHub pull requests"',
        'help_text = "Run python -m src.main --help to see all available command line arguments"',
        'log_info = "The quick brown fox jumps over the lazy dog in this sample unit test"',
        'status_msg = "All security checks passed successfully with zero blocking vulnerabilities"',
        'banner_title = "Automated Pull Request Security Audit Report Summary"',
        'prompt_text = "Would you like to proceed with the proposed implementation plan?"',
        'footer = "Generated deterministically without external SaaS or paid LLM APIs"',
        'comment_body = "Merge blocked due to high severity vulnerability detected in pull request"',
        'audit_summary = "Scan completed in under four point eight seconds according to strict SLA"',
        'ui_label = "Filter findings by severity level: critical, high, or medium warnings"',
        'release_notes = "Version 1.0.0 features Python AST visitor and OSV.dev batch client"',
        'err_msg = "Failed to parse unified diff hunk header because format was invalid"',
        'doc_intro = "System architecture specification for security audit automation bot"',
        'outro = "Thank you for reviewing the automated security audit report summary"',
    ]
    for i, pat in enumerate(english_strings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-SAFE-TEXT-{i:03d}",
                category="SECRET",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Benign natural English string #{i}",
            )
        )

    uuid_strings = [
        'session_id = "c39e802d-0db5-4b19-8664-d9229e612985"',
        'user_uuid = "123e4567-e89b-12d3-a456-426614174000"',
        'task_id = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"',
        'record_id = "550e8400-e29b-41d4-a716-446655440000"',
        'device_guid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"',
        'client_id = "6ba7b811-9dad-11d1-80b4-00c04fd430c8"',
        'event_uuid = "6ba7b812-9dad-11d1-80b4-00c04fd430c8"',
        'job_id = "6ba7b814-9dad-11d1-80b4-00c04fd430c8"',
        'correlation_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"',
        'trace_id = "018f2b5a-7b3e-7a91-95e2-6d1a938c5b04"',
        'tenant_id = "d94a38e8-7096-499e-998d-71b590e8c784"',
        'message_id = "b5e9f821-6a43-421b-871d-55cb891e4a30"',
        'worker_uuid = "e7b0a852-3f19-482a-b6d4-89c72e1f50a8"',
        'cluster_id = "8f3b2c1d-4e5a-6b7c-8d9e-0f1a2b3c4d5e"',
        'node_uuid = "4a5b6c7d-8e9f-0a1b-2c3d-4e5f6a7b8c9d"',
    ]
    for i, pat in enumerate(uuid_strings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-SAFE-UUID-{i:03d}",
                category="SECRET",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Benign UUID string #{i}",
            )
        )

    hash_strings = [
        'commit_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        'git_hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"',
        'file_checksum = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"',
        'cache_key = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"',
        'build_id = "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"',
        'object_sha = "2ef7bde608ce5404e97d5f042f95f89f1c232871"',
        'blob_id = "da39a3ee5e6b4b0d3255bfef95601890afd80709"',
        'tree_sha = "fbcd8513712427487b922004d77ad500d9730453"',
        'release_digest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"',
        'container_hash = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"',
        'asset_digest = "04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"',
        'artifact_sha = "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa"',
        'image_digest = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"',
        'etag_header = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"',
        'firmware_crc = "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"',
    ]
    for i, pat in enumerate(hash_strings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-SAFE-HASH-{i:03d}",
                category="SECRET",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Benign SHA/Git commit hash #{i}",
            )
        )

    url_strings = [
        'API_URL = "https://github.com/my-org/security-audit-bot/issues/42"',
        'HOMEPAGE = "https://docs.github.com/en/rest/issues/comments"',
        'DOCS_LINK = "https://packaging.python.org/en/latest/guides/writing-pyproject-toml/"',
        'REPO_URL = "https://api.github.com/repos/sohamkundu/security-audit-bot"',
        'SPEC_URL = "https://owasp.org/www-project-top-ten/2021/A03_Injection/"',
        'CWE_LINK = "https://cwe.mitre.org/data/definitions/89.html"',
        'OSV_URL = "https://api.osv.dev/v1/querybatch"',
        'PYPI_INDEX = "https://pypi.org/simple/requests/"',
        'NPM_REGISTRY = "https://registry.npmjs.org/lodash/"',
        'PORTFOLIO = "https://sohamkundu.github.io/portfolio/"',
        'CI_RUN_URL = "https://github.com/owner/repo/actions/runs/123456789"',
        'SCHEMA_URL = "http://json-schema.org/draft-07/schema#"',
        'STANDARDS = "https://peps.python.org/pep-0621/"',
        'SECURITY_POLICY = "https://github.com/owner/repo/security/policy"',
        'LICENSE_URL = "https://opensource.org/licenses/MIT"',
    ]
    for i, pat in enumerate(url_strings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-SAFE-URL-{i:03d}",
                category="SECRET",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Benign URL string #{i}",
            )
        )

    path_strings = [
        'PYTHON_BIN = "/usr/local/bin/python3.11"',
        'SYSTEM_PATH = "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts"',
        'CONFIG_DIR = "/home/botuser/.config/security-bot/config.json"',
        'CACHE_PATH = "/tmp/security-audit-bot/cache/manifests.db"',
        'APP_DIR = "c:/Users/soham/coding/Projects_2.0/Personal/P_Project_3/security-audit-bot"',
        'LIB_PATH = "/usr/lib/x86_64-linux-gnu/libssl.so.3"',
        'LOG_FILE = "/var/log/security-audit-bot/audit.log"',
        'DOCKERFILE_PATH = "./Dockerfile"',
        'VENV_PATH = "./.venv/Scripts/python.exe"',
        'TRACKER_PATH = "./docs/TRACKER.md"',
        'WORKFLOW_FILE = ".github/workflows/security-audit.yml"',
        'TESTS_DIR = "tests/test_pr_commenter.py"',
        'MODELS_FILE = "src/models.py"',
        'COVERAGE_PATH = ".coverage"',
        'RUFF_CACHE = ".ruff_cache/content"',
    ]
    for i, pat in enumerate(path_strings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-SAFE-PATH-{i:03d}",
                category="SECRET",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Benign file path string #{i}",
            )
        )

    color_strings = [
        'PRIMARY_COLOR = "#FFFFFF"',
        'ACCENT_COLOR = "#3b82f6"',
        'SUCCESS_GREEN = "#10b981"',
        'WARNING_YELLOW = "#f59e0b"',
        'CRITICAL_RED = "#ef4444"',
        'DARK_BG = "#0f172a"',
        'CARD_BG = "#1e293b"',
        'BORDER_COLOR = "#334155"',
        'MUTED_TEXT = "#94a3b8"',
        'BADGE_PURPLE = "#8b5cf6"',
    ]
    for i, pat in enumerate(color_strings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-SAFE-COLOR-{i:03d}",
                category="SECRET",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Benign hex color code #{i}",
            )
        )

    placeholder_strings = [
        'API_KEY = "YOUR_API_KEY_HERE"',
        'SECRET_KEY = "INSERT_SECRET_KEY_HERE"',
        'PASSWORD = "password123"',
        'DB_PASS = "admin"',
        'TOKEN = "dummy_token_for_mock"',
        'AWS_SECRET = "REPLACE_WITH_YOUR_KEY"',
        'KEY = "CHANGEME"',
        'ACCESS = "YOUR_TOKEN"',
        'AUTH = "Bearer <token>"',
        'SIGNATURE = "EXAMPLE_SIGNATURE"',
    ]
    for i, pat in enumerate(placeholder_strings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-SAFE-PLACEHOLDER-{i:03d}",
                category="SECRET",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Benign dummy placeholder token #{i}",
            )
        )

    regex_syntax_strings = [
        'REGEX_PATTERN = r"^[a-zA-Z0-9_-]{20,}$"',
        'URL_RE = r"https?://(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}"',
        'TOKEN_RE = r"(?:bearer|token)\\s+([a-zA-Z0-9_.-]{20,})"',
        'UUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"',
        'HASH_RE = r"^[a-f0-9]{32,64}$"',
    ]
    for i, pat in enumerate(regex_syntax_strings, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"SEC-SAFE-REGEX-{i:03d}",
                category="SECRET",
                rule_id=None,
                code=pat,
                is_vulnerable=False,
                description=f"Benign regex pattern definition #{i}",
            )
        )

    # =========================================================================
    # 4. Dependency Manifest Cases (DEP-001) — 30 Vuln, 30 Safe = 60 cases
    # =========================================================================
    vulnerable_deps = [
        ("requests==2.19.1", "requirements.txt", "CVE-2018-18074"),
        ("urllib3==1.25.8", "requirements.txt", "CVE-2020-26137"),
        ("flask==0.12.2", "requirements.txt", "CVE-2018-1000656"),
        ("django==2.0.1", "requirements.txt", "CVE-2019-14232"),
        ("pyyaml==5.2", "requirements.txt", "CVE-2020-1747"),
        ("pillow==6.2.1", "requirements.txt", "CVE-2020-5310"),
        ("cryptography==3.3.1", "requirements.txt", "CVE-2020-36242"),
        ("jinja2==2.10.0", "requirements.txt", "CVE-2019-10906"),
        ("werkzeug==0.15.2", "requirements.txt", "CVE-2019-14806"),
        ("tornado==5.1.0", "requirements.txt", "CVE-2023-28370"),
        ("numpy==1.15.4", "requirements.txt", "CVE-2019-6446"),
        ("scipy==1.1.0", "requirements.txt", "CVE-2019-6446"),
        ("paramiko==2.4.1", "requirements.txt", "CVE-2018-7750"),
        ("celery==4.2.1", "requirements.txt", "CVE-2020-25600"),
        ("rsa==4.0", "requirements.txt", "CVE-2020-13757"),
        ('"lodash": "4.17.15"', "package.json", "CVE-2020-8203"),
        ('"axios": "0.21.1"', "package.json", "CVE-2021-3749"),
        ('"minimist": "1.2.0"', "package.json", "CVE-2020-7598"),
        ('"glob-parent": "5.1.1"', "package.json", "CVE-2020-28469"),
        ('"y18n": "4.0.0"', "package.json", "CVE-2020-7774"),
        ('"trim-newlines": "3.0.0"', "package.json", "CVE-2021-33623"),
        ('"color-string": "1.5.3"', "package.json", "CVE-2021-29059"),
        ('"path-parse": "1.0.6"', "package.json", "CVE-2021-23343"),
        ('"node-forge": "0.9.0"', "package.json", "CVE-2020-7720"),
        ('"hosted-git-info": "2.8.8"', "package.json", "CVE-2021-23631"),
        ('"ini": "1.3.5"', "package.json", "CVE-2020-7788"),
        ('"tar": "4.4.13"', "package.json", "CVE-2021-32804"),
        ('"ws": "7.4.5"', "package.json", "CVE-2021-32640"),
        ('"set-value": "2.0.0"', "package.json", "CVE-2019-10747"),
        ('"mixin-deep": "1.3.1"', "package.json", "CVE-2019-10746"),
    ]
    for i, (dep, manifest, cve) in enumerate(vulnerable_deps, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"DEP-VULN-{i:03d}",
                category="DEPENDENCY",
                rule_id="DEP-001",
                code=dep,
                is_vulnerable=True,
                description=f"Vulnerable package {dep} ({cve})",
                file_path=manifest,
            )
        )

    safe_deps = [
        ("requests>=2.31.0", "requirements.txt"),
        ("urllib3>=2.0.7", "requirements.txt"),
        ("flask>=3.0.0", "requirements.txt"),
        ("django>=4.2.0", "requirements.txt"),
        ("pyyaml>=6.0.1", "requirements.txt"),
        ("pillow>=10.2.0", "requirements.txt"),
        ("cryptography>=42.0.0", "requirements.txt"),
        ("jinja2>=3.1.3", "requirements.txt"),
        ("werkzeug>=3.0.1", "requirements.txt"),
        ("tornado>=6.3.3", "requirements.txt"),
        ("pydantic>=2.6.0", "requirements.txt"),
        ("fastapi>=0.110.0", "requirements.txt"),
        ("pytest>=8.0.0", "requirements.txt"),
        ("pytest-cov>=4.1.0", "requirements.txt"),
        ("ruff>=0.3.0", "requirements.txt"),
        ('"lodash": "^4.17.21"', "package.json"),
        ('"axios": "^1.6.0"', "package.json"),
        ('"minimist": "^1.2.8"', "package.json"),
        ('"glob-parent": "^6.0.2"', "package.json"),
        ('"y18n": "^5.0.8"', "package.json"),
        ('"express": "^4.18.2"', "package.json"),
        ('"react": "^18.2.0"', "package.json"),
        ('"react-dom": "^18.2.0"', "package.json"),
        ('"typescript": "^5.3.0"', "package.json"),
        ('"vite": "^5.1.0"', "package.json"),
        ('"vitest": "^1.2.0"', "package.json"),
        ('"eslint": "^8.56.0"', "package.json"),
        ('"prettier": "^3.2.0"', "package.json"),
        ('"webpack": "^5.90.0"', "package.json"),
        ('"dotenv": "^16.4.0"', "package.json"),
    ]
    for i, (dep, manifest) in enumerate(safe_deps, 1):
        cases.append(
            BenchmarkCase(
                case_id=f"DEP-SAFE-{i:03d}",
                category="DEPENDENCY",
                rule_id=None,
                code=dep,
                is_vulnerable=False,
                description=f"Safe secure package {dep}",
                file_path=manifest,
            )
        )

    return cases
