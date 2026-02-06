package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/relays-api/internal/sdk/middleware"
	"github.com/nourabuild/relays-api/internal/sdk/models"
	"github.com/nourabuild/relays-api/internal/sdk/sqldb"
	"github.com/nourabuild/relays-api/internal/services/sentry"
)

func (a *App) HandleMe(c *gin.Context) {
	userID, err := middleware.GetClaims(c)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "unauthorized", nil)
		return
	}

	user, err := a.db.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		if !errors.Is(err, sqldb.ErrDBNotFound) {
			a.toSentry(c, "me", "db", sentry.LevelError, err)
			writeError(c, http.StatusInternalServerError, "internal_verify_user_error", nil)
			return
		}

		// User not found locally — fetch from auth service and create
		req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, "https://api.auth.noura.software/api/v1/user/me", nil)
		if err != nil {
			a.toSentry(c, "me", "http", sentry.LevelError, err)
			writeError(c, http.StatusInternalServerError, "internal_auth_request_error", nil)
			return
		}
		req.Header.Set("Authorization", c.GetHeader("Authorization"))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			a.toSentry(c, "me", "http", sentry.LevelError, err)
			writeError(c, http.StatusInternalServerError, "internal_auth_request_error", nil)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			writeError(c, http.StatusUnauthorized, "auth_service_error", nil)
			return
		}

		var authUser models.User
		if err := json.NewDecoder(resp.Body).Decode(&authUser); err != nil {
			a.toSentry(c, "me", "decode", sentry.LevelError, err)
			writeError(c, http.StatusInternalServerError, "internal_auth_decode_error", nil)
			return
		}

		fmt.Printf("Creating local user for auth service user: %+v\n", authUser)

		// Creating local user for auth service user:
		// // User {
		//   ID: 27
		//   Name: "John Doe"
		//   Account: "johndoe"
		//   Email: "john@example.com"
		//   Password: []
		//   Bio: ""
		//   DOB: ""
		//   City: ""
		//   Phone: ""
		//   AvatarPhotoID: ""
		//   IsAdmin: false
		//   CreatedAt: 2026-02-06 17:30:25.246413 UTC
		//   UpdatedAt: 2026-02-06 17:30:25.246413 UTC
		// }

		user, err = a.db.CreateUser(c.Request.Context(), models.NewUser{
			ID:      authUser.ID,
			Name:    authUser.Name,
			Account: authUser.Account,
			Email:   authUser.Email,
		})
		if err != nil {
			a.toSentry(c, "me", "db", sentry.LevelError, err)
			writeError(c, http.StatusInternalServerError, "internal_create_user_error", nil)
			return
		}
	}

	c.JSON(http.StatusOK, user)
}
