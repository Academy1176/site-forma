const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const app = express();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');

const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'views')));
app.use(cookieParser());

// Настройка подключения к MySQL
const connection = mysql.createConnection({
    host: 'localhost', // имя сервера
    user: 'root', // имя пользователя
    password: '', // пароль к подключению к БД
    database: 'conf' // название БД
});

// Главная страница
app.get('/', (req, res) => {
    const session_id = req.cookies['session_id'];
    if (!session_id) {
        res.redirect('/unauthorized');
    } else {
        // Проверка существования сессии
        connection.query('SELECT * FROM logged_in_users WHERE session_id = ?', [session_id], (err, sessions) => {
            if (err || sessions.length === 0) {
                res.redirect('/unauthorized');
            } else {
                res.sendFile(path.join(__dirname, 'views', 'index.html'));
            }
        });
    }
});

app.get('/unauthorized', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'unauthorized.html'));
});

// Страница регистрации
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'signup.html'));
});

// Страница авторизации
app.get('/signin', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'signin.html'));
});

app.post('/submit_registration', async (req, res) => {
    const {
        first_name,
        last_name,
        gender,
        nationality,
        organization,
        position,
        date_of_birth,
        email,
        password,
        confirm_password
    } = req.body;

    let errors = {};

    // Валидация каждого поля
    if (!first_name) errors.first_name = "Имя не может быть пустым.";
    if (!last_name) errors.last_name = "Фамилия не может быть пустой.";
    if (!gender) errors.gender = "Пол не может быть пустым.";
    if (!nationality) errors.nationality = "Национальность не может быть пустой.";
    if (!organization) errors.organization = "Название организации не может быть пустым.";
    if (!position) errors.position = "Должность не может быть пустой.";
    if (!email) errors.email = "Email не может быть пустым.";
    if (!password) errors.password = "Пароль не может быть пустым.";
    if (password !== confirm_password) errors.confirm_password = "Пароли не совпадают.";
    if (date_of_birth && !/\d{4}-\d{2}-\d{2}/.test(date_of_birth)) {
        errors.date_of_birth = "Некорректный формат даты.";
    }

    if (Object.keys(errors).length > 0) {
        return res.status(400).json(errors);
    }

    connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Ошибка при запросе к базе данных:', err);
            return res.status(500).json({ serverError: 'Ошибка сервера при проверке email' });
        }

        if (results.length > 0) {
            return res.status(400).json({ email: 'Пользователь с таким email уже существует' });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const query = 'INSERT INTO users (first_name, last_name, gender, nationality, organization, position, date_of_birth, email, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
        connection.query(query, [first_name, last_name, gender, nationality, organization, position, date_of_birth ? new Date(date_of_birth) : null, email, hashedPassword], async (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ serverError: 'Ошибка сервера при регистрации пользователя.' });
            }
        
            const user_id = result.insertId;
            const session_id = uuidv4();
        
            connection.query('INSERT INTO logged_in_users (user_id, login_time, session_id) VALUES (?, ?, ?)', [user_id, new Date().toISOString().slice(0, 19).replace('T', ' '), session_id], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ serverError: 'Ошибка сервера при создании сессии.' });
                }
                res.cookie('session_id', session_id, { httpOnly: true });
                res.redirect('/index.html');
            });
        });
    });
});

app.get('/get_users', (req, res) => {
    const session_id = req.cookies['session_id'];

    connection.query('SELECT * FROM logged_in_users WHERE session_id = ?', [session_id], (err, sessions) => {
        if (err || sessions.length === 0) {
            return res.status(403).send('Доступ запрещен');
        }
        // Запрос на получение данных пользователей
        connection.query('SELECT id, first_name, last_name, organization, email FROM users', (err, users) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Ошибка сервера');
            }
            // Добавление редактирования для пользователя
            const user_id = sessions[0].user_id;
            const modifiedUsers = users.map(user => ({
                ...user,
                isEditable: user.id === user_id
            }));
            res.json(modifiedUsers);
        });
    });
});

// Получение данных пользователя
app.get('/get_user/:id', (req, res) => {
    const userId = req.params.id;
    connection.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Ошибка при запросе к базе данных:', err);
            return res.status(500).send('Ошибка сервера');
        }

        if (results.length === 0) {
            return res.status(404).send('Пользователь не найден');
        }

        res.json(results[0]);
    });
});

// Обработка запроса на редактирование пользователя
app.post('/edit_user', (req, res) => {
    const { 
        id, 
        first_name, 
        last_name, 
        gender, 
        nationality, 
        organization, 
        position, 
        date_of_birth, 
        email 
    } = req.body;

    connection.query('UPDATE users SET first_name = ?, last_name = ?, gender = ?, nationality = ?, organization = ?, position = ?, date_of_birth = ?, email = ? WHERE id = ?', 
    [first_name, last_name, gender, nationality, organization, position, date_of_birth, email, id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Ошибка сервера при обновлении данных пользователя');
        }
        res.send('Данные пользователя обновлены');
    });
});

// Обработка запроса авторизации
app.post('/submit_login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email и пароль обязательны для заполнения');
    }

    // Проверка пользователя в базе данных
    connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Ошибка при запросе к базе данных:', err);
            return res.status(500).send('Ошибка сервера');
        }

        if (results.length === 0) {
            return res.status(404).send('Пользователь не найден');
        }

        const user = results[0];
        // Сравнение хешированных паролей
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).send('Неверный пароль');
        }
        // Если пароль совпадает, создаем сессию для пользователя
        const session_id = uuidv4();
        connection.query('INSERT INTO logged_in_users (user_id, login_time, session_id) VALUES (?, ?, ?)', 
                         [user.id, new Date().toISOString().slice(0, 19).replace('T', ' '), session_id], (err, result) => {
            if (err) {
                console.error('Ошибка при создании сессии:', err);
                return res.status(500).send('Ошибка сервера при создании сессии.');
            }

            res.cookie('session_id', session_id, { httpOnly: true });
            res.redirect('/index.html');
        });
    });
});

app.listen(7777, () => {
    console.log('http://localhost:7777/');
});
