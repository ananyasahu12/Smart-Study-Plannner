# Focus Forge — Smart Study Planner

Focus Forge is a full-stack web app for the Smart Study Planner project. The browser interface talks to a dependency-free Node.js backend. The backend stores accounts and each user's subjects, tasks, preferences, and reminders in `data/studyflow.json`.

## Start the app

1. Install Node.js 18 or later if it is not already installed.
2. Open PowerShell in this folder.
3. Run `node server.js`.
4. Open [http://127.0.0.1:4173](http://127.0.0.1:4173) and create an account.

The backend uses port `4173` by default. Set the `PORT` environment variable to use a different port. Stop the app with Ctrl+C. User records remain in the local `data` directory after the server stops. To store data in another directory, set `STUDYFLOW_DATA_DIR`.

## Features

- Account registration and sign-in. Passwords are stored as salted scrypt hashes; planner data is isolated by account.
- Create, rename, and delete subjects; add, edit, complete, reopen, mark missed, or delete study topics, assignments, and examinations.
- Set deadlines, estimated time, difficulty, importance, and an optional reminder time.
- Rank tasks with the milestone formula: urgency × 0.5 + difficulty × 0.3 + importance × 0.2. Urgency ranges from 1 for no deadline or one more than two weeks away to 5 for overdue or due today.
- Get a next-task recommendation and a seven-day plan based on priority, deadlines, and the student's daily available minutes.
- Track total completion percentage, study time, streak, and completion progress for each subject in the Performance section.
- Reschedule overdue or missed tasks individually to tomorrow, or use Backlog Rescue Mode to spread them across the coming days.
- Use Backlog Rescue Mode to spread overdue and missed work across upcoming days.
- Review completed and pending work, overdue counts, study hours, points, and study streaks.
- Enable browser reminders. Notifications appear while the app is open and the browser has granted notification permission.
- Switch between pink/violet light and dark themes; the selected theme is remembered on the device.
- Ask the AI study coach to suggest a focused plan using Google Gemini. It sends subjects, unfinished task details, deadlines, daily study time, and the optional question only after the user presses **Create my plan**; it does not send account name or email.
- Use the interface on desktop, tablet, and mobile layouts.

## Enable the AI study coach

Create a free-tier API key with [Google AI Studio](https://aistudio.google.com/apikey), then put it in a `.env` file in this folder:

```text
GEMINI_API_KEY=your-key
```

Restart `node server.js` after changing the key. The `.env` file is excluded from Git. The app uses Google's `gemini-3.8-flash` model. Keep the key on the server, never in `app.js`, `index.html`, or a public repository. Free-tier quotas apply; quota errors stop the request, with no automatic paid fallback. For a strict no-charge setup, don't link billing to the Google project. Gemini's free tier may use submitted content to improve Google products, so don't send sensitive information.

## Backend API

The server serves the frontend and JSON API from the same origin. It exposes account registration, sign-in, sign-out, and session routes under `/api/auth`; per-user planner data at `GET /api/planner`; subject create, rename, and delete routes under `/api/subjects`; task create, edit, status, delete, and individual rescheduling routes under `/api/tasks`; preference updates at `PUT /api/preferences`; backlog rescheduling at `POST /api/planner/rescue`; and the optional AI endpoint at `POST /api/coach/plan`.

## Current limits

This prototype stores data in one JSON file, so use one server instance and persistent storage when hosting it. A managed database such as PostgreSQL is a better choice before scaling to multiple instances. Reminder notifications require the app to remain open. Password reset, email verification, and external calendar integration are not included in the milestones' first version.

## Share it as a website (Render)

1. Create a private GitHub repository and upload this project folder. Do not upload API keys or private data. The local `data` folder is ignored by Git.
2. In Render, create a **New → Web Service** and connect that repository. Use the Node runtime, leave the build command empty, and set the start command to `node server.js`.
3. Add a persistent disk mounted at `/opt/render/project/src/data`. Add the environment variable `STUDYFLOW_DATA_DIR=/opt/render/project/src/data` so planner accounts survive redeploys. Render documents persistent disks for paid services; its default service filesystem is temporary.
4. Add `NODE_ENV=production` and `GEMINI_API_KEY` as a secret environment variable. Use a key from a free-tier project and don't link billing if you need a strict no-charge setup.
5. Deploy. Render gives the service a public `https://<service-name>.onrender.com` address that you can share. Anyone with the URL can create an account; each account has separate planner data.

This JSON-file prototype is intended for one service instance. Before broad public use, move the database to managed PostgreSQL and add operational safeguards such as backups and rate limits.
