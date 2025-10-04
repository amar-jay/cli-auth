package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/argon2"
)

func green(s string) string {
	return "\033[32m" + s + "\033[0m"
}

func red(s string) string {
	return "\033[31m" + s + "\033[0m"
}

func yellow(s string) string {
	return "\033[33m" + s + "\033[0m"
}

func blue(s string) string {
	return "\033[34m" + s + "\033[0m"
}

const SALT = "TIMELY_SENSITIVE_BOMBOCLAS_DOWN_THE_WC"

func HashToken(password string) string {
	// Parameters: (password, salt, iterations, memory, parallelism, keyLen)
	hash := argon2.IDKey([]byte(password), []byte(SALT), 1, 64*1024, 4, 32)
	encoded := base64.RawStdEncoding.EncodeToString(hash)
	return encoded
}

func VerifyToken(password, encoded string) bool {
	hash := argon2.IDKey([]byte(password), []byte(SALT), 1, 64*1024, 4, 32)
	expected := base64.RawStdEncoding.EncodeToString(hash)
	return expected == encoded
}

// User represents a user in the system
type User struct {
	Name              string    `json:"name"`
	UserID            string    `json:"user_id"`
	Email             string    `json:"email"`
	ValidationKey     string    `json:"validation_key"`
	ValidationExpiry  time.Time `json:"validation_expiry"`
	APIKey            string    `json:"api_key"`
	RefreshToken      string    `json:"refresh_token"`
	AccessTokenHash   string    `json:"access_token_hash"` // Now stores HASH only
	LastAccessToken   string    `json:"-"`                 // Temporary plaintext for polling (not persisted)
	AccessTokenExpiry time.Time `json:"access_token_expiry"`
	IsVerified        bool      `json:"is_verified"`
}

// Session stores the current authenticated session
type Session struct {
	UserID      string    `json:"user_id"`
	AccessToken string    `json:"access_token"` // Client stores plaintext
	ExpiresAt   time.Time `json:"expires_at"`
}

var users = []User{
	{
		Name:            "amar-jay",
		UserID:          "user_24680",
		Email:           "amar@example.com",
		AccessTokenHash: HashToken("forbidden_monkey"), // Store hash of initial token
		APIKey:          "api_key_amar_secret_12345",
		IsVerified:      true,
	},
	{
		Name:            "Alice",
		UserID:          "user_12345",
		Email:           "alice@example.com",
		AccessTokenHash: HashToken("ultimate_giant"), // Store hash of initial token
		APIKey:          "api_key_alice_secret_67890",
		IsVerified:      true,
	},
	{
		Name:            "Bob",
		UserID:          "user_11111",
		Email:           "bob@example.com",
		APIKey:          "api_key_bob_secret_99999",
		AccessTokenHash: HashToken("mysterious_beast"), // Store hash of initial token
		IsVerified:      false,
	},
}

var currentSession *Session

// JSON response helper
func JSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// Generate a cryptographically random token
func generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// Generate access token (now uses random generation)
func generateAccessToken() (string, error) {
	return generateToken(32)
}

// HTTP Handlers

func validatingHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	verificationKey := r.URL.Query().Get("verification_key")

	if userID == "" || verificationKey == "" {
		JSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing user_id or verification_key",
		})
		return
	}

	for i := range users {
		if users[i].UserID == userID {
			// Check if validation key has expired
			if !users[i].ValidationExpiry.IsZero() && time.Now().After(users[i].ValidationExpiry) {
				users[i].ValidationKey = ""
				JSON(w, http.StatusUnauthorized, map[string]string{
					"status": "failed",
					"error":  "Verification key has expired",
				})
				return
			}

			if users[i].ValidationKey == verificationKey {
				// Generate NEW random access token
				accessToken, err := generateAccessToken()
				if err != nil {
					JSON(w, http.StatusInternalServerError, map[string]string{
						"error": "Failed to generate access token",
					})
					return
				}

				// Generate refresh token
				refreshToken, err := generateToken(32)
				if err != nil {
					JSON(w, http.StatusInternalServerError, map[string]string{
						"error": "Failed to generate refresh token",
					})
					return
				}

				// Clear validation key
				users[i].ValidationKey = ""
				// Store HASH of access token on server
				users[i].AccessTokenHash = HashToken(accessToken)
				users[i].LastAccessToken = accessToken // Store plaintext temporarily for polling
				users[i].AccessTokenExpiry = time.Now().Add(1 * time.Hour)
				users[i].RefreshToken = refreshToken
				users[i].IsVerified = true

				// Clear the temporary token after 30 seconds (for polling window)
				go func(idx int) {
					time.Sleep(30 * time.Second)
					users[idx].LastAccessToken = ""
				}(i)

				// Send PLAINTEXT token to client (only time they get it)
				JSON(w, http.StatusOK, map[string]any{
					"status":        "verified",
					"user_id":       userID,
					"message":       fmt.Sprintf("User %s verified successfully", users[i].Name),
					"access_token":  accessToken, // Send plaintext!
					"refresh_token": refreshToken,
					"expires_in":    3600,
				})
				return
			}

			JSON(w, http.StatusUnauthorized, map[string]string{
				"status": "failed",
				"error":  "Invalid verification key",
			})
			return
		}
	}

	JSON(w, http.StatusNotFound, map[string]string{
		"error": "User not found",
	})
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	if userID == "" {
		JSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing user_id",
		})
		return
	}

	for _, user := range users {
		if user.UserID == userID {
			response := map[string]any{
				"user_id":     userID,
				"name":        user.Name,
				"email":       user.Email,
				"is_verified": user.IsVerified,
			}

			if user.ValidationKey == "" {
				response["status"] = "not in verification state"
				if user.AccessTokenHash != "" && time.Now().Before(user.AccessTokenExpiry) {
					response["authenticated"] = true
					response["token_expires_in"] = int(time.Until(user.AccessTokenExpiry).Seconds())
					// Include access token if recently verified (for polling clients)
					if user.LastAccessToken != "" {
						response["access_token"] = user.LastAccessToken
					}
				} else {
					response["authenticated"] = false
				}
			} else {
				verifyURL := fmt.Sprintf("http://localhost:8080/verify-http-verification?user_id=%s&verification_key=%s",
					userID, user.ValidationKey)
				response["status"] = "pending verification"
				response["verification_url"] = verifyURL
				response["expires_at"] = user.ValidationExpiry.Format(time.RFC3339)
			}

			JSON(w, http.StatusOK, response)
			return
		}
	}

	JSON(w, http.StatusNotFound, map[string]string{
		"error": "User not found",
	})
}

func senderHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	if userID == "" {
		JSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing user_id",
		})
		return
	}

	for i := range users {
		if users[i].UserID == userID {
			// Generate random validation key
			validationKey, err := generateToken(32)
			if err != nil {
				JSON(w, http.StatusInternalServerError, map[string]string{
					"error": "Failed to generate validation key",
				})
				return
			}

			users[i].ValidationKey = validationKey
			users[i].ValidationExpiry = time.Now().Add(5 * time.Minute)

			fmt.Fprintf(w, "Logging in as %s (%s)\nClick to complete: http://localhost:8080/verify-http-verification?user_id=%s&verification_key=%s\nThis link expires in 5 minutes.",
				users[i].Name, users[i].Email, userID, validationKey)
			return
		}
	}

	JSON(w, http.StatusNotFound, map[string]string{
		"error": "User not found",
	})
}

func apiKeyAuthHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		apiKey = r.URL.Query().Get("api_key")
	}

	if apiKey == "" {
		JSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing API key",
		})
		return
	}

	for i := range users {
		if users[i].APIKey == apiKey {
			// Generate NEW random access token
			accessToken, err := generateAccessToken()
			if err != nil {
				JSON(w, http.StatusInternalServerError, map[string]string{
					"error": "Failed to generate access token",
				})
				return
			}

			// Store HASH on server
			users[i].AccessTokenHash = HashToken(accessToken)
			users[i].AccessTokenExpiry = time.Now().Add(1 * time.Hour)

			// Send PLAINTEXT to client
			JSON(w, http.StatusOK, map[string]any{
				"status":       "authenticated",
				"user_id":      users[i].UserID,
				"name":         users[i].Name,
				"access_token": accessToken, // Send plaintext!
				"expires_in":   3600,
			})
			return
		}
	}

	JSON(w, http.StatusUnauthorized, map[string]string{
		"error": "Invalid API key",
	})
}

func tokenAuthHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	token := r.URL.Query().Get("token")

	if userID == "" || token == "" {
		JSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing user_id or token",
		})
		return
	}

	for i := range users {
		// Client sends plaintext token, verify against stored hash
		if users[i].UserID == userID && VerifyToken(token, users[i].AccessTokenHash) {
			// Check if token expired
			if time.Now().After(users[i].AccessTokenExpiry) {
				JSON(w, http.StatusUnauthorized, map[string]string{
					"error": "Access token has expired",
				})
				return
			}

			// Generate NEW token for this session
			newAccessToken, err := generateAccessToken()
			if err != nil {
				JSON(w, http.StatusInternalServerError, map[string]string{
					"error": "Failed to generate access token",
				})
				return
			}

			users[i].AccessTokenHash = HashToken(newAccessToken)
			users[i].AccessTokenExpiry = time.Now().Add(1 * time.Hour)

			JSON(w, http.StatusOK, map[string]any{
				"status":       "authenticated",
				"user_id":      userID,
				"name":         users[i].Name,
				"access_token": newAccessToken, // Send new plaintext token
				"expires_in":   3600,
			})
			return
		}
	}

	JSON(w, http.StatusUnauthorized, map[string]string{
		"error": "Invalid user_id or token",
	})
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Header.Get("X-Refresh-Token")
	if refreshToken == "" {
		refreshToken = r.URL.Query().Get("refresh_token")
	}

	if refreshToken == "" {
		JSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing refresh token",
		})
		return
	}

	for i := range users {
		if users[i].RefreshToken == refreshToken {
			// Generate NEW access token
			accessToken, err := generateAccessToken()
			if err != nil {
				JSON(w, http.StatusInternalServerError, map[string]string{
					"error": "Failed to generate access token",
				})
				return
			}

			// Store hash, send plaintext
			users[i].AccessTokenHash = HashToken(accessToken)
			users[i].AccessTokenExpiry = time.Now().Add(1 * time.Hour)

			JSON(w, http.StatusOK, map[string]any{
				"status":       "token_refreshed",
				"user_id":      users[i].UserID,
				"access_token": accessToken, // Send plaintext!
				"expires_in":   3600,
			})
			return
		}
	}

	JSON(w, http.StatusUnauthorized, map[string]string{
		"error": "Invalid refresh token",
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	if userID == "" {
		JSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing user_id",
		})
		return
	}

	for i := range users {
		if users[i].UserID == userID {
			users[i].AccessTokenHash = ""
			users[i].RefreshToken = ""
			users[i].ValidationKey = ""

			JSON(w, http.StatusOK, map[string]string{
				"status":  "logged_out",
				"user_id": userID,
				"message": fmt.Sprintf("User %s logged out successfully", users[i].Name),
			})
			return
		}
	}

	JSON(w, http.StatusNotFound, map[string]string{
		"error": "User not found",
	})
}

func server(port int) {
	http.HandleFunc("/verify-http-verification", validatingHandler)
	http.HandleFunc("/status-http-verification", statusHandler)
	http.HandleFunc("/send-http-verification", senderHandler)
	http.HandleFunc("/auth/api-key", apiKeyAuthHandler)
	http.HandleFunc("/auth/token", tokenAuthHandler)
	http.HandleFunc("/auth/refresh", refreshTokenHandler)
	http.HandleFunc("/auth/logout", logoutHandler)

	fmt.Printf("Starting server at port %d...\n", port)
	fmt.Println("\nAvailable endpoints:")
	fmt.Println("  - " + yellow("POST") + " /auth/api-key (with X-API-Key header)")
	fmt.Println("  - " + yellow("POST") + " /auth/token?user_id=X&token=Y")
	fmt.Println("  - " + yellow("POST") + " /auth/refresh (with X-Refresh-Token header)")
	fmt.Println("  - " + yellow("GET") + "  /send-http-verification?user_id=X")
	fmt.Println("  - " + yellow("GET") + "  /verify-http-verification?user_id=X&verification_key=Y")
	fmt.Println("  - " + yellow("GET") + "  /status-http-verification?user_id=X")
	fmt.Println("  - " + yellow("POST") + " /auth/logout?user_id=X\n")

	err := http.ListenAndServe(":"+strconv.Itoa(port), nil)
	if err != nil {
		log.Fatal("Error starting server:", err)
	}
}

// Save session to file
func saveSession(session *Session) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sessionFile := homeDir + "/.cli_auth_session"
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	fmt.Printf("Saving session to: %s\n", sessionFile)

	return os.WriteFile(sessionFile, data, 0600)
}

// Load session from file
func loadSession() (*Session, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	sessionFile := homeDir + "/.cli_auth_session"
	data, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	return &session, nil
}

// Clear session
func clearSession() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sessionFile := homeDir + "/.cli_auth_session"
	return os.Remove(sessionFile)
}

func authCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "https",
			Usage: "Authenticate via HTTPS verification link",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				userID := ""
				prompt := &survey.Input{
					Message: "Enter your user ID:",
				}
				if err := survey.AskOne(prompt, &userID); err != nil {
					return err
				}

				resp, err := http.Get("http://localhost:8080/send-http-verification?user_id=" + userID)
				if err != nil {
					return fmt.Errorf("failed to send verification: %w", err)
				}
				defer resp.Body.Close()

				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				content := string(body)
				if strings.Contains(content, "error") {
					message := map[string]string{}
					json.Unmarshal(body, &message)
					fmt.Println(red("Authentication Failed : " + message["error"]))
					return nil
				}

				fmt.Println("\n" + content)
				fmt.Println(green("\nVerification link sent! Click the link above to complete authentication."))

				// Poll for verification
				fmt.Println("\nWaiting for verification...")
				for range 60 {
					time.Sleep(2 * time.Second)

					statusResp, err := http.Get("http://localhost:8080/status-http-verification?user_id=" + userID)
					if err != nil {
						continue
					}

					var statusData map[string]any
					json.NewDecoder(statusResp.Body).Decode(&statusData)
					statusResp.Body.Close()

					if authenticated, ok := statusData["authenticated"].(bool); ok && authenticated {
						// Get the access token from the response
						if token, ok := statusData["access_token"].(string); ok && token != "" {
							session := &Session{
								UserID:      userID,
								AccessToken: token,
								ExpiresAt:   time.Now().Add(1 * time.Hour),
							}
							saveSession(session)
							currentSession = session
							fmt.Println(green("Authentication successful! Session saved."))
							return nil
						}
						fmt.Println(yellow("Authentication detected but token not available yet. Retrying..."))
						continue
					}
				}

				fmt.Println(red("Verification timeout. Please try again."))
				return nil
			},
		},
		{
			Name:  "token",
			Usage: "Authenticate using a static token",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				userID := ""
				token := ""

				questions := []*survey.Question{
					{
						Name:   "userid",
						Prompt: &survey.Input{Message: "Enter your user ID:"},
					},
					{
						Name:   "token",
						Prompt: &survey.Password{Message: "Enter your token:"},
					},
				}

				answers := struct {
					UserID string `survey:"userid"`
					Token  string `survey:"token"`
				}{}

				if err := survey.Ask(questions, &answers); err != nil {
					return err
				}

				userID = answers.UserID
				token = answers.Token

				url := fmt.Sprintf("http://localhost:8080/auth/token?user_id=%s&token=%s", userID, token)
				resp, err := http.Post(url, "application/json", nil)
				if err != nil {
					return fmt.Errorf("authentication failed: %w", err)
				}
				defer resp.Body.Close()

				var result map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					return err
				}

				if resp.StatusCode == http.StatusOK {
					fmt.Println(green("\nAuthentication successful!"))
					fmt.Printf("  User: %s\n", result["name"])
					fmt.Printf("  User ID: %s\n", result["user_id"])

					// Save session with NEW token from server
					if accessToken, ok := result["access_token"].(string); ok {
						session := &Session{
							UserID:      userID,
							AccessToken: accessToken, // Save plaintext token
							ExpiresAt:   time.Now().Add(1 * time.Hour),
						}
						saveSession(session)
						currentSession = session
					}
				} else {
					fmt.Printf(red("Authentication failed: %s\n"), result["error"])
				}

				return nil
			},
		},
		{
			Name:  "api-key",
			Usage: "Authenticate using an API key",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				apiKey := ""
				prompt := &survey.Password{
					Message: "Enter your API key:",
				}
				if err := survey.AskOne(prompt, &apiKey); err != nil {
					return err
				}

				client := &http.Client{}
				req, err := http.NewRequest("POST", "http://localhost:8080/auth/api-key", nil)
				if err != nil {
					return err
				}
				req.Header.Set("X-API-Key", apiKey)

				resp, err := client.Do(req)
				if err != nil {
					return fmt.Errorf("authentication failed: %w", err)
				}
				defer resp.Body.Close()

				var result map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					return err
				}

				if resp.StatusCode == http.StatusOK {
					fmt.Println(green("\nAuthentication successful!"))
					fmt.Printf("  User: %s\n", result["name"])
					fmt.Printf("  User ID: %s\n", result["user_id"])

					// Save session with plaintext token
					if accessToken, ok := result["access_token"].(string); ok {
						session := &Session{
							UserID:      result["user_id"].(string),
							AccessToken: accessToken, // Save plaintext token
							ExpiresAt:   time.Now().Add(1 * time.Hour),
						}
						saveSession(session)
						currentSession = session
					}
				} else {
					fmt.Printf(red("Authentication failed: %s\n"), result["error"])
				}

				return nil
			},
		},
		{
			Name:  "status",
			Usage: "Check authentication status",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				session, err := loadSession()
				if err != nil {
					fmt.Println(red("Not authenticated. Please run 'auth' command first."))
					return nil
				}

				fmt.Println(green("Authenticated"))
				fmt.Printf(green("  User ID: %s\n"), session.UserID)
				fmt.Printf(green("  Token expires in: %s\n"), time.Until(session.ExpiresAt).Round(time.Second))

				return nil
			},
		},
		{
			Name:  "logout",
			Usage: "Logout and clear session",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				session, err := loadSession()
				if err != nil {
					fmt.Println("Not currently authenticated.")
					return nil
				}

				// Call logout endpoint
				url := fmt.Sprintf("http://localhost:8080/auth/logout?user_id=%s", session.UserID)
				http.Post(url, "application/json", nil)

				// Clear local session
				if err := clearSession(); err != nil {
					return err
				}

				fmt.Println(green("Logged out successfully"))
				currentSession = nil
				return nil
			},
		},
		{
			Name:  "list-users",
			Usage: "List available test users",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				fmt.Println("\nAvailable test users:")
				fmt.Println(strings.Repeat("-", 80))
				// Note: Initial plaintext tokens for testing
				initialTokens := map[string]string{
					"user_24680": "forbidden_monkey",
					"user_12345": "ultimate_giant",
					"user_11111": "mysterious_beast",
				}
				for _, user := range users {
					fmt.Printf("\nName:     %s\n", user.Name)
					fmt.Printf("User ID:  %s\n", user.UserID)
					fmt.Printf("Email:    %s\n", user.Email)
					fmt.Printf("Token:    %s (for initial login)\n", initialTokens[user.UserID])
					fmt.Printf("API Key:  %s\n", user.APIKey)
					fmt.Println(strings.Repeat("-", 80))
				}
				return nil
			},
		},
		{
			Name:  "whoami",
			Usage: "Display current authenticated user",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				if currentSession == nil {
					session, err := loadSession()
					if err != nil {
						fmt.Println("Not authenticated. Run 'app auth <method>' to login.")
						return nil
					}
					currentSession = session
				}

				fmt.Printf("Authenticated as: %s\n", currentSession.UserID)
				fmt.Printf("Session expires: %s\n", currentSession.ExpiresAt.Format(time.RFC3339))
				return nil
			},
		},
	}
}

func main() {
	// Try to load existing session
	session, _ := loadSession()
	currentSession = session

	cmd := &cli.Command{
		Name:  "app",
		Usage: "CLI application with authentication",
		Commands: []*cli.Command{
			{
				Name:     "auth",
				Usage:    "Authentication commands",
				Commands: authCommands(),
			},
			{
				Name:  "server",
				Usage: "Start HTTP authentication server",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "port",
						Aliases: []string{"p"},
						Usage:   "Port to start the server on",
						Value:   8080,
					},
				},
				Action: func(c context.Context, cmd *cli.Command) error {
					port := cmd.Int("port")
					server(port)
					return nil
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
