# QuickFact

**QuickFact** — это пет-проект, демонстрирующий реализацию защиты публичного API с помощью протокола challenge-response (подробности [здесь](https://gist.github.com/lordcod/142c90a1c7d30ebee39669d532f8303a)).  
Вместе с этим проект показывает случайный факт с поддержкой нескольких языков.

---

## Структура проекта

- **Backend**: [FastAPI](https://fastapi.tiangolo.com/) — REST API, реализующее защищённый по challenge-response протоколу доступ к данным.  
- **Frontend**: [Next.js](https://nextjs.org/) — React-приложение с мультиязычной поддержкой, которое запрашивает факты с backend и отображает их пользователю.

---

## Основные возможности

- Защищённый публичный API с challenge-response протоколом для предотвращения неавторизованного доступа  
- Запрос случайного факта с локализацией по выбранному языку  
- UI с переключателем языков и плавной анимацией загрузки  
- Современный дизайн с использованием Tailwind CSS и framer-motion  
- Разделение frontend и backend для гибкости деплоя

---

## Запуск проекта локально

### 1. Backend (FastAPI)

```bash
cd backend
poetry install
uvicorn app.main:app --reload --port 8000
```

API будет доступен по адресу `http://localhost:8000`

### 2. Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev
```

Приложение откроется на `http://localhost:3000`

---

## Технологии

* FastAPI
* Next.js (React, Next Intl)
* Tailwind CSS
* Framer Motion
* challenge-response API protection protocol

---

## Ссылки

* [Протокол challenge-response](https://gist.github.com/lordcod/142c90a1c7d30ebee39669d532f8303a)
* [FastAPI Documentation](https://fastapi.tiangolo.com/)
* [Next.js Documentation](https://nextjs.org/docs)

---

## Лицензия

MIT

---

Спасибо за использование QuickFact! Если есть вопросы или идеи — открывайте issue или pull request.
