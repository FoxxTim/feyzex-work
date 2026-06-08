const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const flash = require('connect-flash');
const Database = require('./database');

const app = express();
const db = new Database();
const PORT = process.env.PORT || 3000;

// Настройка EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Настройка сессий и flash-сообщений
app.use(session({
    secret: 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 3600000, // 1 час
        secure: false // В продакшене поставьте true с HTTPS
    }
}));
app.use(flash());

// Middleware для проверки авторизации
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    }
    req.flash('error_msg', 'Пожалуйста, войдите в систему');
    res.redirect('/login');
};

// Делаем flash-сообщения и пользователя доступными во всех шаблонах
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.errors = req.flash('errors');
    res.locals.formData = req.flash('formData')[0] || {};
    res.locals.user = req.session.user || null;
    next();
});

// ============ СТРАНИЦА РЕГИСТРАЦИИ ============
app.get('/', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('register', {
        title: 'Регистрация - Neon UI',
        formData: res.locals.formData
    });
});

app.get('/register', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('register', {
        title: 'Регистрация - Neon UI',
        formData: res.locals.formData
    });
});

// Обработка регистрации
app.post('/register', async (req, res) => {
    try {
        const { displayName, login, email, password } = req.body;
        req.flash('formData', { displayName, login, email });

        const validationErrors = validateInput({ displayName, login, email, password });
        if (validationErrors.length > 0) {
            req.flash('errors', validationErrors);
            req.flash('error_msg', 'Пожалуйста, исправьте ошибки в форме');
            return res.redirect('/register');
        }

        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const result = await db.registerUser({
            displayName,
            username: login,
            email,
            passwordHash
        });

        if (result.success) {
            req.flash('success_msg', 'Регистрация прошла успешно! Теперь вы можете войти.');
            res.redirect('/login');
        }

    } catch (error) {
        console.error('Ошибка регистрации:', error);
        req.flash('error_msg', error.message || 'Произошла ошибка при регистрации');
        res.redirect('/register');
    }
});

// ============ СТРАНИЦА ВХОДА ============
app.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('login', {
        title: 'Вход - Neon UI',
        formData: res.locals.formData
    });
});

// Обработка входа
app.post('/login', async (req, res) => {
    try {
        const { login, password } = req.body;
        
        // Сохраняем логин для повторного отображения
        req.flash('formData', { login });

        // Валидация
        if (!login || !password) {
            req.flash('error_msg', 'Пожалуйста, заполните все поля');
            return res.redirect('/login');
        }

        // Поиск пользователя по логину или email
        const user = await db.findUserByLoginOrEmail(login);
        
        if (!user) {
            req.flash('error_msg', 'Пользователь с таким логином или email не найден');
            return res.redirect('/login');
        }

        // Проверка пароля
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        
        if (!isPasswordValid) {
            req.flash('error_msg', 'Неверный пароль');
            return res.redirect('/login');
        }

        // Обновление времени последнего входа
        await db.updateLastLogin(user.id);

        // Создание сессии
        req.session.user = {
            id: user.id,
            displayName: user.display_name,
            username: user.username,
            email: user.email
        };

        req.flash('success_msg', `Добро пожаловать, ${user.display_name}!`);
        res.redirect('/dashboard');

    } catch (error) {
        console.error('Ошибка входа:', error);
        req.flash('error_msg', 'Произошла ошибка при входе');
        res.redirect('/login');
    }
});

// ============ ЗАЩИЩЕННЫЕ СТРАНИЦЫ ============

// Дашборд (только для авторизованных)
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', {
        title: 'Личный кабинет',
        user: req.session.user
    });
});

// Профиль пользователя
app.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile', {
        title: 'Профиль пользователя',
        user: req.session.user
    });
});

// Выход из системы
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Ошибка при выходе:', err);
        }
        res.redirect('/login');
    });
});

// ============ API ENDPOINTS ============

// API для регистрации (AJAX)
app.post('/api/register', async (req, res) => {
    try {
        const { displayName, login, email, password } = req.body;
        const validationErrors = validateInput({ displayName, login, email, password });
        
        if (validationErrors.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Ошибка валидации',
                errors: validationErrors
            });
        }

        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const result = await db.registerUser({
            displayName,
            username: login,
            email,
            passwordHash
        });

        res.status(201).json(result);

    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(400).json({
            success: false,
            message: error.message || 'Ошибка регистрации'
        });
    }
});

// API для входа (AJAX)
app.post('/api/login', async (req, res) => {
    try {
        const { login, password } = req.body;

        if (!login || !password) {
            return res.status(400).json({
                success: false,
                message: 'Пожалуйста, заполните все поля'
            });
        }

        const user = await db.findUserByLoginOrEmail(login);
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Неверный логин или пароль'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Неверный логин или пароль'
            });
        }

        await db.updateLastLogin(user.id);

        req.session.user = {
            id: user.id,
            displayName: user.display_name,
            username: user.username,
            email: user.email
        };

        res.json({
            success: true,
            message: 'Вход выполнен успешно',
            user: req.session.user
        });

    } catch (error) {
        console.error('Ошибка входа:', error);
        res.status(500).json({
            success: false,
            message: 'Внутренняя ошибка сервера'
        });
    }
});

// API для проверки доступности username
app.get('/api/check-username/:username', async (req, res) => {
    try {
        const user = await db.getUserInfo(req.params.username);
        res.json({ available: !user });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// API для проверки доступности email
app.get('/api/check-email/:email', async (req, res) => {
    try {
        const exists = await db.checkEmail(req.params.email);
        res.json({ available: !exists });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Страница со списком пользователей
app.get('/users', async (req, res) => {
    try {
        const users = await db.getAllUsers();
        res.render('users', {
            title: 'Список пользователей',
            users: users
        });
    } catch (error) {
        req.flash('error_msg', 'Ошибка при загрузке пользователей');
        res.redirect('/');
    }
});

// Функция валидации
function validateInput(data) {
    const errors = [];
    const { displayName, login, email, password } = data;

    if (!displayName || displayName.trim().length < 2) {
        errors.push('Отображаемое имя должно содержать минимум 2 символа');
    }

    if (!login || login.trim().length < 3) {
        errors.push('Логин должен содержать минимум 3 символа');
    } else if (!/^[a-zA-Z0-9_]+$/.test(login)) {
        errors.push('Логин может содержать только буквы, цифры и подчеркивания');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        errors.push('Некорректный email адрес');
    }

    if (!password || password.length < 8) {
        errors.push('Пароль должен содержать минимум 8 символов');
    } else if (!/[A-Z]/.test(password)) {
        errors.push('Пароль должен содержать хотя бы одну заглавную букву');
    } else if (!/[a-z]/.test(password)) {
        errors.push('Пароль должен содержать хотя бы одну строчную букву');
    } else if (!/[0-9]/.test(password)) {
        errors.push('Пароль должен содержать хотя бы одну цифру');
    }

    return errors;
}

// Обработка ошибок
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('error', {
        title: 'Ошибка',
        message: 'Внутренняя ошибка сервера'
    });
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nЗавершение работы...');
    db.close();
    process.exit(0);
});

app.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});