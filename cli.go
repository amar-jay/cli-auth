package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/AlecAivazis/survey/v2"
	"github.com/urfave/cli/v3"
)

type User struct {
	name                 string
	user_id              string
	last_generated_token string
	validationKey        string
}

var users = []User{
	{
		name:                 "amar-jay",
		user_id:              "user_24680",
		last_generated_token: "forbidden_monkey",
		validationKey:        "",
	},
	{
		name:                 "Alice",
		user_id:              "user_12345",
		last_generated_token: "ultimate_giant",
		validationKey:        "",
	},
}

// JSON response helper
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func validatingHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	verificationKey := r.URL.Query().Get("verification_key")

	if userID == "" || verificationKey == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing user_id or verification_key",
		})
		return
	}

	for i := range users {
		if users[i].user_id == userID {
			if users[i].validationKey == verificationKey {
				users[i].validationKey = "" // consume it
				respondJSON(w, http.StatusOK, map[string]string{
					"status":  "verified",
					"user_id": userID,
					"message": fmt.Sprintf("User %s verified successfully", users[i].name),
				})
				return
			}
			respondJSON(w, http.StatusUnauthorized, map[string]string{
				"status":  "failed",
				"user_id": userID,
				"error":   "Invalid verification key",
			})
			return
		}
	}

	respondJSON(w, http.StatusNotFound, map[string]string{
		"error": "User not found",
	})
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	if userID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing user_id",
		})
		return
	}

	for _, user := range users {
		if user.user_id == userID {
			if user.validationKey == "" {
				respondJSON(w, http.StatusOK, map[string]string{
					"user_id": userID,
					"status":  "not in verification state",
				})
			} else {
				verifyURL := "http://localhost:8080/verify-http-verification?user_id=" +
					userID + "&verification_key=" + user.validationKey
				respondJSON(w, http.StatusOK, map[string]string{
					"user_id":          userID,
					"status":           "pending verification",
					"verification_url": verifyURL,
				})
			}
			return
		}
	}

	respondJSON(w, http.StatusNotFound, map[string]string{
		"error": "User not found",
	})
}

func senderHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	if userID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Missing user_id",
		})
		return
	}

	for i := range users {
		if users[i].user_id == userID {
			// Hash validation key: sha256(name + user_id)
			raw := users[i].name + "_" + users[i].user_id
			hash := sha256.Sum256([]byte(raw))
			validationKey := hex.EncodeToString(hash[:])

			users[i].validationKey = validationKey

			fmt.Fprintf(w, "Logging in as (%s)\nClick to complete: http://localhost:8080/verify-http-verification?user_id=%s&verification_key=%s", users[i].name, userID, validationKey)
			return
		}
	}

	respondJSON(w, http.StatusNotFound, map[string]string{
		"error": "User not found",
	})
}

func server(port int) {

	// handle routes
	http.HandleFunc("/verify-http-verification", validatingHandler)
	http.HandleFunc("/status-http-verification", statusHandler)
	http.HandleFunc("/send-http-verification", senderHandler)

	fmt.Println("Starting server at port 8080...")
	err := http.ListenAndServe(":"+strconv.Itoa(port), nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}

func authCommands() []*cli.Command {

	return []*cli.Command{
		{
			Name:  "https",
			Usage: "cli auth https",
			Action: func(context.Context, *cli.Command) error {
				name := ""
				prompt := &survey.Input{
					Message: "Enter your user id: ",
				}
				survey.AskOne(prompt, &name)
				for _, user := range users {
					if user.user_id == name {
						resp, err := http.Get("http://localhost:8080/send-http-verification?user_id=" + name)
						if err != nil {
							panic(err)
						}
						defer resp.Body.Close()

						body, _ := io.ReadAll(resp.Body)
						fmt.Println(string(body))
					}
				}
				return nil
			},
		},
		{
			Name:  "token",
			Usage: "cli auth using token",
			Action: func(context.Context, *cli.Command) error {
				fmt.Println("boom! I say!")
				return nil
			},
		},
	}

}

func main() {
	cmd := &cli.Command{
		Name:  "app",
		Usage: "CLI appilcation",
		Commands: []*cli.Command{
			{
				Name:     "auth",
				Usage:    "cli auth https",
				Commands: authCommands(),
			},
			{
				Name:  "server",
				Usage: "start http server",
				Flags: []cli.Flag{
					&cli.Int16Flag{
						Name:    "port",
						Aliases: []string{"p"},
						Usage:   "port to start the server on",
						Value:   8080,
					},
				},
				Action: func(c context.Context, cl *cli.Command) error {
					port := int(cl.Flags[0].(*cli.Int16Flag).Value)
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
