# Cайт-форма регистрации на вымышленную конференцию

## Описание проекта

Данный проект представляет собой сайт-форму регистрации на вымышленную конференцию.

## Технологии
- Backend: Node.js, Express.js
- Frontend: HTML, CSS, JavaScript, Bootstrap
- База данных: MySQL
- Дополнительные библиотеки: bcrypt для хеширования паролей, uuid для генерации уникальных идентификаторов сессий

## Установка и запуск
Для работы приложения необходимо установить [Node.js](https://nodejs.org/en/) и [MySQL](https://www.mysql.com/).
1. Настроить подключение к MySQL в файле `app.js`, указав нужные параметры (имя пользователя, пароль, название базы данных).
   ```
   // Настройка подключения к MySQL
   const connection = mysql.createConnection({
      host: 'localhost', // имя сервера
      user: 'root', // имя пользователя
      password: '', // пароль к подключению к БД
      database: 'conf' // название БД
   });
   ```

   2. Запустить сервер:
   ```
   nodemon app.js
   ```
   Или, если `nodemon` не установлен:
   ```
   node app.js
   ```
   3. Открыть в браузере `http://localhost:7777/`

**Функционал**
Backend (`app.js`)
- `/`: Главная страница со списком участников (требуется авторизация).
- `/signup`: Страница регистрации нового пользователя.
- `/signin`: Страница авторизации.
- `/unauthorized`: Страница ошибки при попытке доступа без авторизации.
- API для регистрации, авторизации, получения данных пользователей и их редактирования.

Frontend
- `index.html`: Главная страница со списком зарегистрированных участников.
- `signup.html`: Форма регистрации.
- `signin.html`: Форма авторизации.
- `unauthorized.html`: Сообщение об ошибке доступа.
- Стили `css/style.css` и `bootstrap`.
- Интерактивность с помощью JavaScript и jQuery.

**Примечание**
Перед запуском нужно убедится, что MySQL сервер запущен и настроен. Для работы функционала сайта необходимо 
создать таблицы в базе данных согласно файлу `db/CREATE.txt`, так же необходимо указать данные для подключения в `app.js`.
