# ChatBox
[C++ / Windows ONLY] 

**A lightweight LAN chat & file transfer tool for Windows – no server needed.**

ChatBox enables instant text messaging and file sharing among all users on your local network. It uses UDP broadcasts for presence and messages, and direct TCP connections for reliable multi‑receiver file delivery. All credentials are stored with AES‑32 encryption, and the UI supports rich text, clickable file links, auto‑detected subnet broadcast, and persistent chat history.

---

## Features

- 💬 **Instant messaging** – broadcast text to all online peers.
- 📁 **File transfer** – send any file; all online recipients receive it simultaneously over TCP.
- 👥 **User presence** – automatically detects who’s online; shows online count in title bar.
- 📜 **Chat history** – per‑chatroom logs saved locally and reloaded on startup.
- 🔐 **Encrypted credentials** – user passwords encrypted with AES‑32 (optional).
- ✨ **Rich‑text chat area** – supports clickable file links, timestamp grouping, adjustable font size.
- 🌐 **Auto‑detected broadcast address** – works on any subnet without hardcoding.
- 🔒 **Single instance** – prevents multiple copies from running.
- 📂 **Organised file storage** – received files saved in `Chatbox\File\YYYY-MM\` with automatic duplicate handling.
- 🧹 **Auto‑cleanup** – temporary download folder cleared on start/exit.

---

## Usage

### First Launch

- A login dialog appears.
- If no user exists, enter a username and optional password to **register**.
- If credentials exist, enter your password to log in.
- On successful login, the main window opens.

### Chatting

- Type a message in the bottom input field.
- Press **Enter** (without Shift) or click the **Send** button.
- The message is broadcast to all online users.

### Sending a File

1. Click the **File** button and select a file.
2. The file name and size appear in the status bar.
3. Click **Send**.
4. Confirm the file transfer in the pop‑up dialog.
5. The file is sent via TCP to all currently online users.
6. A clickable link to your local file appears in the chat window.
7. Recipients will automatically start receiving the file – once complete, a link appears in their chat.

### Receiving a File

- Incoming files are saved to `Chatbox\File\YYYY-MM\` (monthly subfolders).
- If a file with the same name exists, it is saved as `filename_1.ext`, `filename_2.ext`, etc.
- After download, a clickable link appears in the chat – click to open.
- You can enable **auto‑open** in the *Settings* menu to open files immediately after download.

### Menu Options

| Menu | Item | Description |
|------|------|-------------|
| **Chat** | Received files | Opens the folder where received files are stored. |
| | Font size | Small / Medium / Large – changes chat text size. |
| **Setting** | Auto open received files | Toggle automatic opening of downloaded files. |
| **Debug** | User List | Shows all currently online users (IP and name). |
| | Log | Shows the debug log file. |
| **Help** | About | Version and author info. |
| | Help | Quick usage guide. |

---

## File Structure

```
Chatbox\
├── History\          # Chat logs per room (plain text)
├── File\             # Received files, organised by month
│   └── YYYY-MM\
├── Temp\             # Temporary download buffer (cleaned on start/exit)
├── App\              # Settings and user credentials
│   ├── Settings.ini  # User preferences
│   └── User.user     # Encrypted username & password
└── Log.log           # Debug log
```

---

## Network Details

- **UDP port**: `1145` – for broadcast messages (presence, chat).
- **TCP port**: `1146` – for file transfers.
- **Broadcast address**: automatically detected from the active network adapter; falls back to `255.255.255.255` if detection fails.
- **File transfer timeout**: 60 seconds (no active receivers → abort).

---

## License

This project is licensed under the **MIT License** – see the [LICENSE] file for details.

---

## Author

**Elias** – [GitHub](https://github.com/LittleElias)

---

## Version

- **v1.4.4** – 
  - Multi‑receiver TCP file transfer (accept loop).  
  - Auto‑detect subnet broadcast address.  
  - Show selected file info in status bar.  
  - Clean temp folder on startup/exit.  
  - Enter key sends message (without Shift).  
  - Extended listener timeout to 60s.  
  - Removed unused SHA‑256 code.

---

## Known Issues

- The AES‑32 library must be available at compile time – no fallback encryption is provided.
- On networks with multiple active adapters, the broadcast address may be detected from the first matching IP; ensure your network adapter is correctly configured.


(AI Generated)
---

**Happy chatting!** 🚀
