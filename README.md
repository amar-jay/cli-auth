I was just curious how CLI authentication works.
This is a simple workflow demo of authentication methods using Go, Argon2 for token hashing, and a local HTTP server.
It works as expected and demonstrates the common flows you’d see in a real system, but in a simplified way.

## Notes

- This is just a demo, not production code.
- The salt is fixed (`SALT` constant) for simplicity.
- In production, each user should have their own random salt.
- Access tokens are hashed with Argon2 before storage, and only the
  plaintext is given once to the client.
