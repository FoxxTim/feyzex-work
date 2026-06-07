const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class Database {
    constructor() {
        this.db = new sqlite3.Database(
            path.join(__dirname, 'users.db'),
            (err) => {
                if (err) {
                    console.error('Ошибка подключения к БД:', err.message);
                } else {
                    console.log('Подключение к SQLite установлено');
                }
            }
        );
        
        this.init();
    }

    init() {
        this.db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                display_name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active BOOLEAN DEFAULT 1
            )
        `);

        this.db.run('CREATE INDEX IF NOT EXISTS idx_username ON users(username)');
        this.db.run('CREATE INDEX IF NOT EXISTS idx_email ON users(email)');
        
        console.log('База данных инициализирована');
    }

    registerUser(userData) {
        return new Promise((resolve, reject) => {
            const { displayName, username, email, passwordHash } = userData;

            this.db.get(
                'SELECT id FROM users WHERE username = ? OR email = ?',
                [username, email],
                (err, row) => {
                    if (err) {
                        reject(new Error('Ошибка базы данных'));
                        return;
                    }

                    if (row) {
                        reject(new Error('Пользователь с таким логином или email уже существует'));
                        return;
                    }

                    this.db.run(
                        `INSERT INTO users (display_name, username, email, password_hash)
                         VALUES (?, ?, ?, ?)`,
                        [displayName, username, email, passwordHash],
                        function(err) {
                            if (err) {
                                reject(new Error('Ошибка при создании пользователя: ' + err.message));
                            } else {
                                resolve({
                                    success: true,
                                    message: 'Регистрация успешна!',
                                    userId: this.lastID
                                });
                            }
                        }
                    );
                }
            );
        });
    }

    // Поиск пользователя по логину или email (для входа)
    findUserByLoginOrEmail(login) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT * FROM users WHERE username = ? OR email = ? AND is_active = 1`,
                [login, login],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });
    }

    // Поиск пользователя по ID
    findUserById(id) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT id, display_name, username, email, created_at, last_login, is_active 
                 FROM users WHERE id = ?`,
                [id],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    // Обновление времени последнего входа
    updateLastLogin(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                [userId],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    getUserInfo(username) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT id, display_name, username, email, created_at, last_login, is_active 
                 FROM users WHERE username = ?`,
                [username],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    checkEmail(email) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT id FROM users WHERE email = ?',
                [email],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(!!row);
                }
            );
        });
    }

    getAllUsers() {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT id, display_name, username, email, created_at, last_login, is_active 
                 FROM users ORDER BY created_at DESC`,
                [],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    close() {
        this.db.close((err) => {
            if (err) {
                console.error('Ошибка при закрытии БД:', err.message);
            } else {
                console.log('Соединение с БД закрыто');
            }
        });
    }
}

module.exports = Database;