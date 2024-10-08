# Tasks

## Web Server

- [ ] Add encryption/password(s) to the database
- [x] Add optional name/nickname for clients
- [ ] Add SSL encryption support

## Web UI

- [x] Login page
- [ ] Overview (with permissions)
- [ ] Team/groups chat page
- [ ] Account settings page
- [ ] Add account (admin)
- [ ] C2 client list page (select also via nickname or other filters)
- [ ] Specific C2 client control page
- [x] Group permissions
- [x] User permissions
- [ ] Change permissions page - show groups that give the user (if applicable) specified permissions
- [x] Settings page
- [ ] Edit user groups
- [x] Delete users (by self or admin)
- [x] Delete groups
- [ ] Good looking UI
- [ ] Instant messaging between teams & private messages
- [ ] Anything else we can think of

## HTTP C2 Server

- [x] Client contact + Database register
- [x] Task rollout
- [x] Response recieve
- [ ] AES-256 bit encryption on all task/other request/response sending and recieving
- [ ] Anything else we can think of

## TCP C2 Server

- [ ] Client connection
- [ ] Task stuff
- [ ] Anything else we can think of

## HTTP C2 Client

- [x] Setup
- [x] Save paths & tokens in registry
- [x] Load paths & tokens
- [x] Check if paths are old/unused
- [x] Grab tasks from server via path
- [x] Execute tasks
- [x] Return task results via path
- [ ] Persistence
- [ ] Multi-threaded task running/ running multiple tasks at once

## TCP C2 Client

- [ ] Setup
- [ ] Connect to server
- [ ] Execute and respond
- [ ] Persistence
