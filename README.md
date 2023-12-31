
## Документация к веб-приложению "UserEdit"

### Введение

Веб-приложение "UserEdit" предназначено для управления базой данных пользователей. Приложение позволяет создавать, просматривать, редактировать и удалять записи пользователей.

### Технологии

- **Python**: Язык программирования, на котором написано приложение.
- **Flask**: Фреймворк для создания веб-приложений на Python.
- **SQLAlchemy**: ORM для работы с базой данных.
- **SQLite**: СУБД, используемая для хранения данных приложения.

### Структура приложения

#### Файлы и директории

- `user_editor/`: Основная директория приложения.
  - `app.py`: Основной файл приложения, содержащий маршруты и обработчики запросов.
  - `db.py`: Файл для работы с базой данных через SQLAlchemy.
  - `models/`: Директория с моделями данных.
    - `user.py`: Файл с моделью пользователя.
  - `templates/`: Директория с HTML-шаблонами для отображения веб-страниц.
  - `migrations/`: Директория с файлами миграций базы данных.

#### Основные маршруты

- `/`: Главная страница с описанием функционала приложения.
- `/register`: Страница регистрации нового пользователя.
- `/login`: Страница входа в систему.
- `/users`: Страница с списком всех пользователей (доступна только администраторам).
- `/users/add`: Страница для добавления нового пользователя (доступна только администраторам).
- `/users/edit/<int:id>`: Страница для редактирования данных пользователя (доступна только администраторам).
- `/users/delete/<int:id>`: Маршрут для удаления пользователя (доступен только администраторам).

### Работа с приложением

#### Установка и запуск

1. Клонируйте репозиторий с GitHub.
2. Установите необходимые зависимости, используя `poetry install`.
3. Запустите приложение, используя команду `poetry run python user_editor/app.py`.

#### Регистрация и вход

- **Регистрация**: Перейдите на страницу регистрации и заполните форму, указав имя пользователя, адрес электронной почты и пароль.
- **Вход**: Перейдите на страницу входа и введите имя пользователя и пароль, указанные при регистрации.

#### Управление пользователями

- **Просмотр списка пользователей**: Перейдите на страницу со списком пользователей, чтобы просмотреть всех пользователей в системе (только для администраторов).
- **Добавление нового пользователя**: Перейдите на страницу добавления нового пользователя и заполните форму (только для администраторов).
- **Редактирование данных пользователя**: На странице со списком пользователей нажмите на кнопку "Редактировать" рядом с выбранным пользователем, чтобы отредактировать его данные (только для администраторов).
- **Удаление пользователя**: На странице со списком пользователей нажмите на кнопку "Удалить" рядом с выбранным пользователем, чтобы удалить его из системы (только для администраторов).
