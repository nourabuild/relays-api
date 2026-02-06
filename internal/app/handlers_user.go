package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/relays-api/internal/sdk/middleware"
	"github.com/nourabuild/relays-api/internal/sdk/models"
	"github.com/nourabuild/relays-api/internal/sdk/sqldb"
	"github.com/nourabuild/relays-api/internal/services/sentry"
	"golang.org/x/crypto/bcrypt"
)

const (
	minPasswordLength = 8
	bcryptCost        = bcrypt.DefaultCost
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
		authHeader := c.GetHeader("Authorization")
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			writeError(c, http.StatusUnauthorized, "unauthorized", nil)
			return
		}

		req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, "https://api.auth.noura.software/api/v1/user/me", nil)
		if err != nil {
			a.toSentry(c, "me", "http", sentry.LevelError, err)
			writeError(c, http.StatusInternalServerError, "internal_auth_request_error", nil)
			return
		}
		req.Header.Set("Authorization", "Bearer "+parts[1])

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

// ChangePasswordRequest represents the request body for password change
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
	PasswordConfirm string `json:"password_confirm" binding:"required"`
}

// HandlePasswordChange handles password change for authenticated users
func (a *App) HandlePasswordChange(c *gin.Context) {
	// Get authenticated user ID
	userID, err := middleware.GetClaims(c)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "unauthorized", nil)
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	// Validate new passwords match
	if req.NewPassword != req.PasswordConfirm {
		writeError(c, http.StatusUnauthorized, "password_mismatch", map[string]string{
			"field": "password_confirm",
		})
		return
	}

	// Validate password complexity
	if err := validatePassword(req.NewPassword); err != nil {
		writeError(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Get user from database
	user, err := a.db.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		a.toSentry(c, "change_password", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "user_not_found", nil)
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_update_password_error", nil)
		return
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword(user.Password, []byte(req.CurrentPassword))
	if err != nil {
		writeError(c, http.StatusUnauthorized, "password_mismatch", map[string]string{
			"field": "current_password",
		})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		a.toSentry(c, "change_password", "bcrypt", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_hash_error", nil)
		return
	}

	// Update password
	err = a.db.UpdateUserPassword(c.Request.Context(), userID, hashedPassword)
	if err != nil {
		a.toSentry(c, "change_password", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_update_password_error", nil)
		return
	}

	// Optionally revoke all refresh tokens for security (force re-login on all devices)
	err = a.db.DeleteRefreshTokensByUserID(c.Request.Context(), userID)
	if err != nil {
		// Log error but don't fail the request
		a.toSentry(c, "change_password", "db", sentry.LevelWarning, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password has been changed successfully",
	})
}
