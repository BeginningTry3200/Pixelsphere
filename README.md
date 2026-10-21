# Pixelsphere

**Pixelsphere** is a minimal, lightweight, zero-dependency, self-hosted photo-sharing web application built with Python and modern Web technologies.

It provides a slick, modern social interface with client-side image compression, user authentication, customizable profile logos, and persistent storage—all powered by Python's standard library.

---

## Features

- 🚀 **Zero External Server Dependencies:** Runs entirely using Python 3 standard library modules. No `pip install` required.
- 📱 **Modern Responsive UI:** Dark-mode interface powered by Tailwind CSS with client-side image resizing and cropped previews.
- 🔒 **Authentication:** Simple registration and login with PBKDF2-hashed passwords and secure session handling.
- 🖼️ **Photo Sharing & Likes:** Upload photos, add captions, view a real-time chronological feed, and like posts.
- 👤 **Customizable Profiles:** Customizable avatars, bios, usernames, and dynamic profile logo accent colors.
- 💾 **Local Data Storage:** All user profile data, sessions, and uploads are safely stored in a local `./data` directory.

---

## Tech Stack

- **Backend:** Python 3.8+ (`http.server`, `json`, `hashlib`, `sqlite`/file storage)
- **Frontend:** HTML5, Modern JavaScript (ES6+), Tailwind CSS (via CDN)
- **Image Processing:** Browser Canvas API (Client-side JPEG optimization before upload)

---

## Getting Started

### Prerequisites

- Python 3.8 or higher installed on your machine.

### Installation & Running

1. **Clone the repository:**
   ```bash
   git clone https://github.com/BeginningTry3200/Pixelsphere.git
   cd Pixelsphere
   ```

2. **Start the server:**
   
   To run locally (default port `8080`):
   ```bash
   python main.py
   ```

   To allow access from other devices on your local network:
   ```bash
   python main.py --host 0.0.0.0 --port 8080
   ```

3. **Open in browser:**
   Navigate to [http://localhost:8080](http://localhost:8080) to register an account and start sharing photos!

---

## Project Structure

```text
Pixelsphere/
├── main.py          # Lightweight HTTP server & REST API
├── static/
│   └── index.html   # Single-page app frontend
├── data/            # (Auto-generated on first run) Stores JSON databases & uploaded images
└── README.md
```

---

## License

This project is open-source and available under the [LGPL License](LICENSE).
