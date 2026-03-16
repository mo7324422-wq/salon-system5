const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

class Database {
    constructor() {
        this.db = new sqlite3.Database(
            path.join(__dirname, 'database.sqlite'),
            sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
            (err) => {
                if (err) {
                    console.error('❌ خطأ في الاتصال بقاعدة البيانات:', err);
                } else {
                    console.log('✅ تم الاتصال بقاعدة البيانات بنجاح');
                    this.init();
                }
            }
        );
    }

    async init() {
        const queries = [
            `CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'employee',
                permissions TEXT,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            )`,

            `CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT NOT NULL,
                client_phone TEXT NOT NULL,
                date DATE NOT NULL,
                time TIME NOT NULL,
                status TEXT DEFAULT 'active',
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME,
                cancelled_at DATETIME,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )`,

            `CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`
        ];

        return new Promise((resolve, reject) => {
            this.db.serialize(() => {
                try {
                    for (let query of queries) {
                        this.db.run(query);
                    }

                    const salt = bcrypt.genSaltSync(10);
                    const hash = bcrypt.hashSync('admin123', salt);
                    
                    this.db.get(
                        "SELECT id FROM users WHERE username = ?",
                        ['admin'],
                        (err, row) => {
                            if (!row) {
                                this.db.run(
                                    `INSERT INTO users (username, password, full_name, role, permissions) 
                                     VALUES (?, ?, ?, ?, ?)`,
                                    ['admin', hash, 'المدير العام', 'admin', JSON.stringify(['all'])]
                                );
                            }
                        }
                    );

                    const today = new Date();
                    const eidStart = new Date(today);
                    eidStart.setDate(today.getDate() + 3);
                    const eidEnd = new Date(eidStart);
                    eidEnd.setDate(eidStart.getDate() + 4);

                    const defaultSettings = [
                        ['eid_start', eidStart.toISOString().split('T')[0]],
                        ['eid_end', eidEnd.toISOString().split('T')[0]],
                        ['work_start', '09:00'],
                        ['work_end', '23:00']
                    ];

                    defaultSettings.forEach(([key, value]) => {
                        this.db.get(
                            "SELECT id FROM settings WHERE key = ?",
                            [key],
                            (err, row) => {
                                if (!row) {
                                    this.db.run(
                                        "INSERT INTO settings (key, value) VALUES (?, ?)",
                                        [key, value]
                                    );
                                }
                            }
                        );
                    });

                    console.log('✅ تم تهيئة قاعدة البيانات بنجاح');
                    resolve();
                } catch (error) {
                    console.error('❌ خطأ في تهيئة قاعدة البيانات:', error);
                    reject(error);
                }
            });
        });
    }

    async query(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    async run(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                if (err) reject(err);
                else resolve({ id: this.lastID, changes: this.changes });
            });
        });
    }

    async get(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }
}

module.exports = new Database();